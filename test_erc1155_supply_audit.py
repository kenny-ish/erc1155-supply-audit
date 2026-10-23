import contextlib
import copy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import erc1155_supply_audit as m

FIXTURE = json.loads(Path(__file__).with_name('fixture.json').read_text())


def address_word(address):
    return bytes.fromhex('00' * 12 + address[2:])


def word(value):
    return int(value).to_bytes(32, 'big')


def make_log(spec, contract=FIXTURE['contract']):
    if spec['kind'] == 'single':
        data = word(spec['token_id']) + word(spec['value'])
        topic = m.TRANSFER_SINGLE_TOPIC
    else:
        ids, values = spec['ids'], spec['values']
        ids_offset = 64
        values_offset = ids_offset + 32 + 32 * len(ids)
        data = (word(ids_offset) + word(values_offset) + word(len(ids))
                + b''.join(word(value) for value in ids)
                + word(len(values)) + b''.join(word(value) for value in values))
        topic = m.TRANSFER_BATCH_TOPIC
    topics = [topic]
    for field in ('operator', 'from', 'to'):
        topics.append('0x' + address_word(spec[field]).hex())
    return {
        'address': contract,
        'blockHash': spec['block_hash'],
        'blockNumber': hex(spec['block']),
        'data': '0x' + data.hex(),
        'logIndex': hex(spec['log_index']),
        'removed': False,
        'topics': topics,
        'transactionHash': spec['transaction_hash'],
        'transactionIndex': hex(spec['transaction_index']),
    }


def batch_log():
    spec = FIXTURE['batch_example'].copy()
    spec['kind'] = 'batch'
    return make_log(spec)


class FakeRpc:
    def __init__(self, case_index=0):
        self.case = copy.deepcopy(FIXTURE['cases'][case_index])
        event = dict(self.case['event'])
        event['kind'] = 'single'
        self.logs = [make_log(event)]
        self.calls = []

    def request(self, method, params):
        self.calls.append((method, params))
        if method == 'eth_getLogs':
            lo = int(params[0]['fromBlock'], 16)
            hi = int(params[0]['toBlock'], 16)
            return [copy.deepcopy(log) for log in self.logs
                    if lo <= int(log['blockNumber'], 16) <= hi]
        if method == 'eth_call':
            call, tag = params
            if not call['data'].startswith(m.TOTAL_SUPPLY_SELECTOR):
                raise AssertionError(call)
            expected_id = int(call['data'][10:], 16)
            if expected_id != self.case['event']['token_id']:
                raise AssertionError(expected_id)
            value = self.case['before'] if int(tag, 16) < self.case['start'] else self.case['after']
            return '0x' + word(value).hex()
        raise AssertionError((method, params))


class SupplyAuditTests(unittest.TestCase):
    def setUp(self):
        self.rpc = FakeRpc(0)
        self.contract = FIXTURE['contract']
        self.token_id = self.rpc.case['event']['token_id']
        self.start, self.end = self.rpc.case['start'], self.rpc.case['end']
        self.guard = patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden'))
        self.guard.start()
        self.addCleanup(self.guard.stop)

    def run_audit(self, **kwargs):
        return m.audit(self.rpc, self.contract, self.token_id, self.start, self.end, **kwargs)

    def test_keccak_vectors_topics_and_table_sizes(self):
        self.assertEqual('0x' + m.keccak256(b'').hex(), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual('0x' + m.keccak256(b'\xc0').hex(), '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347')
        self.assertEqual(m.TRANSFER_SINGLE_TOPIC, FIXTURE['transfer_single_topic'])
        self.assertEqual(len(m.ROT), 5)
        self.assertEqual(sum(len(row) for row in m.ROT), 25)
        self.assertEqual(len(m.RC), 24)

    def test_both_live_case_outputs(self):
        for index, case in enumerate(FIXTURE['cases']):
            rpc = FakeRpc(index)
            report = m.audit(rpc, FIXTURE['contract'], case['event']['token_id'], case['start'], case['end'])
            with self.subTest(case=case['name']):
                if case['name'] == 'ordinary':
                    self.assertEqual(report['status'], 'ok')
                    self.assertEqual(report['event_delta'], 0)
                    self.assertEqual(report['supply_before'], 1)
                    self.assertEqual(report['onchain_supply_after'], 1)
                    self.assertEqual(report['entries'][0]['kind'], 'transfer')
                else:
                    self.assertEqual(report['status'], 'mismatch')
                    self.assertEqual(report['event_delta'], -1)
                    self.assertEqual(report['supply_before'], 0)
                    self.assertEqual(report['onchain_supply_after'], 1)
                    self.assertEqual(report['difference'], 2)
                    self.assertEqual(report['entries'][0]['kind'], 'burn')

    def test_single_and_batch_decode_from_live_fixed_data(self):
        single = m.parse_transfer_log(self.rpc.logs[0])
        batch = m.parse_transfer_log(batch_log())
        self.assertEqual(single['entries'], [(self.token_id, 1)])
        self.assertEqual(batch['entries'], list(zip(FIXTURE['batch_example']['ids'], FIXTURE['batch_example']['values'])))
        self.assertEqual(batch['from'], FIXTURE['batch_example']['from'])

    def test_missing_burn_log_is_a_mismatch(self):
        rpc = FakeRpc(1)
        rpc.logs = []
        case = rpc.case
        report = m.audit(rpc, self.contract, case['event']['token_id'], case['start'], case['end'])
        self.assertEqual(report['status'], 'mismatch')
        self.assertEqual(report['event_delta'], 0)
        self.assertEqual(report['difference'], 1)

    def test_non_event_supply_change_is_a_mismatch(self):
        self.rpc.case['after'] = 2
        report = self.run_audit()
        self.assertEqual(report['difference'], 1)
        self.assertEqual(report['status'], 'mismatch')

    def test_other_token_ids_are_not_counted(self):
        self.rpc.logs = []
        report = self.run_audit()
        self.assertEqual(report['entries_checked'], 0)
        self.assertEqual(report['event_delta'], 0)
        self.assertEqual(report['difference'], 0)

    def test_chunk_boundaries(self):
        report = self.run_audit(chunk=1)
        self.assertEqual(report['status'], 'ok')
        log_calls = [params[0] for method, params in self.rpc.calls if method == 'eth_getLogs']
        self.assertEqual(len(log_calls), 3)
        self.assertEqual([int(item['fromBlock'], 16) for item in log_calls], list(range(self.start, self.end + 1)))

    def test_removed_log_rejected(self):
        self.rpc.logs[0]['removed'] = True
        with self.assertRaisesRegex(ValueError, 'removed'):
            self.run_audit()

    def test_duplicate_log_rejected(self):
        self.rpc.logs.append(copy.deepcopy(self.rpc.logs[0]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.run_audit()

    def test_wrong_contract_rejected(self):
        self.rpc.logs[0]['address'] = '0x' + '00' * 20
        with self.assertRaisesRegex(ValueError, 'address'):
            self.run_audit()

    def test_malformed_single_and_batch_rejected(self):
        source = self.rpc.logs[0]
        with self.assertRaises(ValueError):
            m.parse_transfer_log(dict(source, data='0x00'))
        batch = batch_log()
        with self.assertRaises(ValueError):
            m.parse_transfer_log(dict(batch, data='0x' + bytes(64).hex()))
        with self.assertRaises(ValueError):
            m.parse_transfer_log(dict(batch, topics=batch['topics'][:3]))

    def test_noncanonical_address_topic_rejected(self):
        log = copy.deepcopy(self.rpc.logs[0])
        log['topics'][2] = '0x01' + '00' * 31
        with self.assertRaisesRegex(ValueError, 'canonical'):
            m.parse_transfer_log(log)

    def test_input_validation(self):
        with self.assertRaises(ValueError):
            m.audit(self.rpc, 'bad', self.token_id, self.start, self.end)
        for start, end, chunk in [(0, 1, 1), (2, 1, 1), (1, 2, 0)]:
            with self.assertRaises(ValueError):
                m.audit(self.rpc, self.contract, self.token_id, start, end, chunk)
        with self.assertRaises(ValueError):
            m.audit(self.rpc, self.contract, 1 << 256, self.start, self.end)

    def test_cli_exit_codes(self):
        args = ['--rpc-url', 'https://unused.invalid', '--contract', self.contract,
                '--token-id', str(self.token_id), '--from-block', str(self.start),
                '--to-block', str(self.end)]
        with patch.object(m, 'JsonRpc', return_value=self.rpc), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(args), 0)
            self.rpc.case['after'] = 2
            self.assertEqual(m.main(args), 1)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(m.main(args + ['--chunk', '0']), 2)

    def test_rpc_transport_errors_and_user_agent(self):
        for envelope, valid in [({'jsonrpc': '2.0', 'id': 1, 'result': '0xa'}, True),
                                ({'jsonrpc': '2.0', 'id': 2, 'result': '0xa'}, False),
                                ({'jsonrpc': '2.0', 'id': 1, 'error': {'code': -32000}}, False)]:
            with patch('urllib.request.urlopen') as open_url:
                open_url.return_value.__enter__.return_value = io.BytesIO(json.dumps(envelope).encode())
                rpc = m.JsonRpc('https://unused.invalid')
                if valid:
                    self.assertEqual(rpc.request('eth_call', []), '0xa')
                    self.assertEqual(dict(open_url.call_args.args[0].header_items())['User-agent'], 'erc1155-supply-audit/1.0')
                else:
                    with self.assertRaises(ValueError):
                        rpc.request('eth_call', [])


if __name__ == '__main__':
    unittest.main()
