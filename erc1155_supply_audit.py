#!/usr/bin/env python3
"""Reconcile ERC-1155 mint and burn logs with totalSupply(token_id)."""
import argparse
import json
import re
import sys
import urllib.request

MASK = (1 << 64) - 1
ROT = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2),
       (62, 6, 43, 15, 61), (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))
RC = (0x1, 0x8082, 0x800000000000808a, 0x8000000080008000,
      0x808b, 0x80000001, 0x8000000080008081, 0x8000000000008009,
      0x8a, 0x88, 0x80008009, 0x8000000a, 0x8000808b,
      0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x800a,
      0x800000008000000a, 0x8000000080008081, 0x8000000000008080,
      0x80000001, 0x8000000080008008)
ZERO_ADDRESS = '0x' + '00' * 20


def keccak256(data):
    """Ethereum Keccak-256 with the original 0x01 padding."""
    def rotate(value, shift):
        return ((value << shift) | (value >> ((64 - shift) % 64))) & MASK

    padded = bytearray(data)
    padded.extend(bytes(136 - len(data) % 136))
    padded[len(data)] = 1
    padded[-1] |= 128
    state = [0] * 25
    for offset in range(0, len(padded), 136):
        for i in range(17):
            state[i] ^= int.from_bytes(padded[offset + i * 8:offset + i * 8 + 8], 'little')
        for rc in RC:
            columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
                       for x in range(5)]
            deltas = [columns[(x - 1) % 5] ^ rotate(columns[(x + 1) % 5], 1)
                      for x in range(5)]
            rotated = [0] * 25
            for y in range(5):
                for x in range(5):
                    rotated[y + 5 * ((2 * x + 3 * y) % 5)] = rotate(
                        state[x + 5 * y] ^ deltas[x], ROT[x][y])
            for y in range(5):
                for x in range(5):
                    state[x + 5 * y] = rotated[x + 5 * y] ^ (
                        ~rotated[(x + 1) % 5 + 5 * y] & rotated[(x + 2) % 5 + 5 * y])
            state[0] ^= rc
    return b''.join(value.to_bytes(8, 'little') for value in state)[:32]


def signature(text):
    return '0x' + keccak256(text.encode('ascii')).hex()


TRANSFER_SINGLE_TOPIC = signature('TransferSingle(address,address,address,uint256,uint256)')
TRANSFER_BATCH_TOPIC = signature('TransferBatch(address,address,address,uint256[],uint256[])')
TOTAL_SUPPLY_SELECTOR = signature('totalSupply(uint256)')[:10]
TRANSFER_TOPICS = [TRANSFER_SINGLE_TOPIC, TRANSFER_BATCH_TOPIC]


def raw(value, size=None):
    if not isinstance(value, str) or re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', value) is None:
        raise ValueError('invalid hex data')
    result = bytes.fromhex(value[2:])
    if size is not None and len(result) != size:
        raise ValueError('unexpected hex data length')
    return result


def quantity(value):
    if not isinstance(value, str) or re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)', value) is None:
        raise ValueError('invalid RPC quantity')
    return int(value, 16)


def word(value):
    if value < 0 or value >= 1 << 256:
        raise ValueError('value does not fit in uint256')
    return value.to_bytes(32, 'big')


def normalize_address(value):
    if not isinstance(value, str) or re.fullmatch(r'0x[0-9a-fA-F]{40}', value) is None:
        raise ValueError('invalid address')
    return value.lower()


def address_word(value):
    return bytes.fromhex('00' * 12 + normalize_address(value)[2:])


def topic_address(value):
    result = raw(value, 32)
    if any(result[:12]):
        raise ValueError('indexed address is not canonical')
    return '0x' + result[12:].hex()


def data_word(data, offset):
    if offset < 0 or offset % 32 or offset + 32 > len(data):
        raise ValueError('ABI word is outside event data')
    return int.from_bytes(data[offset:offset + 32], 'big')


def uint_array(data, offset):
    length = data_word(data, offset)
    start = offset + 32
    end = start + 32 * length
    if end > len(data):
        raise ValueError('ABI array is truncated')
    return [data_word(data, start + i * 32) for i in range(length)], end


def parse_transfer_log(log):
    """Return a compact transfer record from one ERC-1155 event log."""
    if log.get('removed') is not False:
        raise ValueError('removed log cannot be audited')
    topics = log.get('topics')
    if not isinstance(topics, list) or len(topics) != 4:
        raise ValueError('ERC-1155 transfer must have four topics')
    topic = topics[0].lower()
    if topic not in TRANSFER_TOPICS:
        raise ValueError('unsupported event topic')
    operator = topic_address(topics[1])
    sender = topic_address(topics[2])
    recipient = topic_address(topics[3])
    data = raw(log.get('data', ''))
    entries = []
    if topic == TRANSFER_SINGLE_TOPIC:
        if len(data) != 64:
            raise ValueError('TransferSingle data must contain two words')
        entries.append((data_word(data, 0), data_word(data, 32)))
    else:
        if len(data) < 64:
            raise ValueError('TransferBatch data has no offsets')
        ids, ids_end = uint_array(data, data_word(data, 0))
        values, values_end = uint_array(data, data_word(data, 32))
        if len(ids) != len(values) or max(ids_end, values_end) != len(data):
            raise ValueError('TransferBatch arrays are inconsistent')
        entries.extend(zip(ids, values))
    return {
        'block': quantity(log['blockNumber']),
        'block_hash': log['blockHash'].lower(),
        'transaction_hash': log['transactionHash'].lower(),
        'transaction_index': quantity(log['transactionIndex']),
        'log_index': quantity(log['logIndex']),
        'operator': operator,
        'from': sender,
        'to': recipient,
        'entries': entries,
    }


class JsonRpc:
    def __init__(self, url, timeout=30):
        if not url.startswith(('http://', 'https://')) or timeout <= 0:
            raise ValueError('HTTP(S) RPC URL and positive timeout required')
        self.url, self.timeout, self.counter = url, timeout, 0

    def request(self, method, params):
        self.counter += 1
        request = urllib.request.Request(
            self.url,
            json.dumps({'jsonrpc': '2.0', 'id': self.counter,
                        'method': method, 'params': params}).encode(),
            {'Content-Type': 'application/json', 'User-Agent': 'erc1155-supply-audit/1.0'})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            result = json.load(response)
        if (not isinstance(result, dict) or result.get('jsonrpc') != '2.0'
                or result.get('id') != self.counter or 'error' in result
                or 'result' not in result):
            raise ValueError('invalid or failed RPC response for ' + method)
        return result['result']


def fetch_logs(rpc, contract, start, end, chunk):
    logs = []
    for first in range(start, end + 1, chunk):
        last = min(end, first + chunk - 1)
        result = rpc.request('eth_getLogs', [{
            'address': contract,
            'fromBlock': hex(first),
            'toBlock': hex(last),
            'topics': [TRANSFER_TOPICS],
        }])
        if not isinstance(result, list):
            raise ValueError('eth_getLogs must return a list')
        logs.extend(result)
    logs.sort(key=lambda item: (quantity(item['blockNumber']),
                                quantity(item['transactionIndex']), quantity(item['logIndex'])))
    return logs


def total_supply(rpc, contract, token_id, block):
    call_data = TOTAL_SUPPLY_SELECTOR + word(token_id).hex()
    result = raw(rpc.request('eth_call', [{'to': contract, 'data': call_data}, hex(block)]), 32)
    return int.from_bytes(result, 'big')


def audit(rpc, contract, token_id, start, end, chunk=2000):
    contract = normalize_address(contract)
    if token_id < 0 or token_id >= 1 << 256:
        raise ValueError('token ID does not fit in uint256')
    if start < 1 or end < start or chunk < 1:
        raise ValueError('require 1 <= start <= end and a positive chunk')
    before = total_supply(rpc, contract, token_id, start - 1)
    after = total_supply(rpc, contract, token_id, end)
    logs = fetch_logs(rpc, contract, start, end, chunk)
    selected_entries = 0
    event_delta = 0
    parsed = []
    seen = set()
    for log in logs:
        if log.get('address', '').lower() != contract:
            raise ValueError('log address does not match the requested contract')
        event = parse_transfer_log(log)
        identity = (event['block'], event['transaction_index'], event['log_index'])
        if identity in seen:
            raise ValueError('duplicate log identity')
        seen.add(identity)
        for item_id, amount in event['entries']:
            if item_id != token_id:
                continue
            selected_entries += 1
            if event['from'] == ZERO_ADDRESS and event['to'] != ZERO_ADDRESS:
                event_delta += amount
            elif event['to'] == ZERO_ADDRESS and event['from'] != ZERO_ADDRESS:
                event_delta -= amount
            parsed.append({
                'block': event['block'],
                'transaction_hash': event['transaction_hash'],
                'id': item_id,
                'amount': amount,
                'kind': ('mint' if event['from'] == ZERO_ADDRESS and event['to'] != ZERO_ADDRESS
                         else 'burn' if event['to'] == ZERO_ADDRESS and event['from'] != ZERO_ADDRESS
                         else 'transfer'),
            })
    expected = before + event_delta
    difference = after - expected
    return {
        'contract': contract,
        'token_id': token_id,
        'from_block': start,
        'to_block': end,
        'logs_seen': len(logs),
        'entries_checked': selected_entries,
        'supply_before': before,
        'event_delta': event_delta,
        'expected_supply_after': expected,
        'onchain_supply_after': after,
        'difference': difference,
        'status': 'ok' if difference == 0 else 'mismatch',
        'entries': parsed,
    }


def nonnegative(value):
    try:
        result = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('expected a decimal or hexadecimal integer') from exc
    if result < 0:
        raise argparse.ArgumentTypeError('must be non-negative')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpc-url', required=True)
    parser.add_argument('--contract', required=True)
    parser.add_argument('--token-id', required=True, type=nonnegative)
    parser.add_argument('--from-block', required=True, type=int)
    parser.add_argument('--to-block', required=True, type=int)
    parser.add_argument('--chunk', type=int, default=2000)
    parser.add_argument('--timeout', type=float, default=30)
    args = parser.parse_args(argv)
    try:
        report = audit(JsonRpc(args.rpc_url, args.timeout), args.contract, args.token_id,
                       args.from_block, args.to_block, args.chunk)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print('audit unavailable: ' + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'ok' else 1


if __name__ == '__main__':
    raise SystemExit(main())
