# BittensorMCP Signing SDK

Public signing helpers for [BittensorMCP](https://bittensormcp.com) self-custody write operations.

## Packages

| Package | Registry | Language |
|---------|----------|----------|
| [`@bittensormcp/sign`](packages/npm/) | npm | TypeScript / JavaScript |
| [`bittensormcp-sign`](packages/python/) | PyPI | Python |

## What is this?

BittensorMCP lets AI agents stake, unstake, and transfer TAO on your behalf — but in self-custody mode your **private key never touches the server**.

These packages implement the A2 two-step signing protocol:

1. The AI agent calls a write tool → server returns an `UNSIGNED_PAYLOAD` + `intent_id`
2. This SDK signs the payload locally with your sr25519 key
3. The signature is sent back → server submits the extrinsic to chain

Your private key is never passed to these packages either — you provide a `signer` callback that wraps your own keypair.

## Security

- Zero runtime dependencies (both packages)
- No postinstall scripts
- No code paths that receive a seed, mnemonic, or private key
- Published with provenance attestation (npm `--provenance`, PyPI Trusted Publisher)

## Publishing

```bash
# npm: tag as npm/v0.1.0 → workflow publishes @bittensormcp/sign@0.1.0
git tag npm/v0.1.0 && git push --tags

# PyPI: tag as py/v0.1.0 → workflow publishes bittensormcp-sign==0.1.0
git tag py/v0.1.0 && git push --tags
```

GitHub Actions workflows are in [.github/workflows/](.github/workflows/).
