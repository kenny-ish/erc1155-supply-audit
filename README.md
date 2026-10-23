# erc1155-supply-audit

This small command-line auditor checks whether an ERC-1155 token ID's `TransferSingle` and `TransferBatch` mint and burn logs explain the change returned by `totalSupply(id)`. It uses only the caller-provided EVM JSON-RPC endpoint and Python 3.10 or newer standard library code.

## Example

Both examples below were run against the ERC-1155 contract at `0x495f947276749Ce646f68AC8c248420045cb7b5e` on Ethereum Mainnet through `https://eth.drpc.org` on 2026-10-10 UTC. The first is an ordinary transfer whose supply remains unchanged. The second is a burn event where the contract's `totalSupply(id)` result does not match the event delta, so exit code `1` is expected. The contract is not an exchange address.

    python erc1155_supply_audit.py --rpc-url https://eth.drpc.org --contract 0x495f947276749Ce646f68AC8c248420045cb7b5e --token-id 0xef8acc51b6411af79ffdad8182394f0d7792445b0000000000079e0000000001 --from-block 15000000 --to-block 15000002
    {
      "contract": "0x495f947276749ce646f68ac8c248420045cb7b5e",
      "difference": 0,
      "entries": [
        {
          "amount": 1,
          "block": 15000001,
          "id": 108348005865544129040411552508209223114542272553772717755275977563383596580865,
          "kind": "transfer",
          "transaction_hash": "0x4eb47ac1d75f7036a0a4fc93ba1fae367bea5aa00782257cf3027ca3474f2e88"
        }
      ],
      "entries_checked": 1,
      "event_delta": 0,
      "expected_supply_after": 1,
      "from_block": 15000000,
      "logs_seen": 1,
      "onchain_supply_after": 1,
      "status": "ok",
      "supply_before": 1,
      "to_block": 15000002,
      "token_id": 108348005865544129040411552508209223114542272553772717755275977563383596580865
    }

    python erc1155_supply_audit.py --rpc-url https://eth.drpc.org --contract 0x495f947276749Ce646f68AC8c248420045cb7b5e --token-id 0xb9e6629000415d49b6157f41b28bc653209f8c8a0000000000005000000003e8 --from-block 14200074 --to-block 14200076
    {
      "contract": "0x495f947276749ce646f68ac8c248420045cb7b5e",
      "difference": 2,
      "entries": [
        {
          "amount": 1,
          "block": 14200075,
          "id": 84084932066204505146800125493745518860054010484135415538560525275396371907560,
          "kind": "burn",
          "transaction_hash": "0xc8b17cd727f0d0d0cbee065fe055b3495820571c0409c5661a834a5f7da33309"
        }
      ],
      "entries_checked": 1,
      "event_delta": -1,
      "expected_supply_after": -1,
      "from_block": 14200074,
      "logs_seen": 6,
      "onchain_supply_after": 1,
      "status": "mismatch",
      "supply_before": 0,
      "to_block": 14200076,
      "token_id": 84084932066204505146800125493745518860054010484135415538560525275396371907560
    }

The offline tests use compact event fields from both live cases in `fixture.json`. A live `TransferBatch` event from the same contract is also included to exercise batch ABI decoding.

## Usage

- `--rpc-url`: required HTTP or HTTPS JSON-RPC URL. The caller chooses the provider.
- `--contract`: ERC-1155 contract address.
- `--token-id`: decimal or hexadecimal token ID.
- `--from-block`, `--to-block`: required inclusive decimal block numbers. The start must be at least 1.
- `--chunk`: block span per `eth_getLogs` request, default `2000`.
- `--timeout`: seconds per HTTP request, default `30`.

Exit code `0` means the event delta equals the `totalSupply` delta. Exit code `1` means they differ. Exit code `2` means the audit could not be completed. Historical `eth_call` access is required at block `from - 1` and at `to`. An event mismatch can indicate missing logs, a non-event supply change, or an incompatible contract implementation. It is not proof of a chain reorganization or lost funds.

## How it works

The tool reads `totalSupply(token_id)` at both boundary blocks, requests both ERC-1155 transfer event types in chunks, and decodes their ABI payloads locally. For the selected ID, a zero address as `from` counts as a mint, a zero address as `to` counts as a burn, and ordinary transfers contribute zero. The expected final supply is the starting supply plus the event delta.

The Keccak-256 implementation is included because Python's `hashlib.sha3_256` uses different padding. The program rejects malformed arrays, removed logs, duplicate log identities, noncanonical indexed addresses, and RPC errors. No ABI package, explorer, indexer, exchange API, or contract write is used.

## Tests

`python -m unittest -v`
