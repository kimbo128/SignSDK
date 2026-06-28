# bittensormcp-sign

Self-custody signing helper for [BittensorMCP](https://bittensormcp.com).

Implements the A2 two-step protocol so your AI agent can stake, unstake, and transfer TAO **without your private key ever leaving your machine**.

## How it works

1. Agent calls a write tool (e.g. `bittensor_stake_add`) → server returns an `UNSIGNED_PAYLOAD`
2. This package signs the payload locally with your sr25519 keypair
3. The signature is sent to `bittensor_submit_signed` → server submits the extrinsic

**Your private key never leaves your process.** The signer receives payload bytes; your keypair stays with you.

## Installation

```bash
pip install bittensormcp-sign
```

Zero dependencies — uses only Python stdlib.

## Usage

```python
from bittensormcp_sign import sign_and_submit
from bittensor import Keypair

keypair = Keypair.create_from_mnemonic("your twelve word mnemonic ...")

result = sign_and_submit(
    endpoint="https://bittensormcp.com",
    token=wallet_jwt,           # from /api/auth/verify
    tool="bittensor_stake_add",
    args={
        "hotkey": "5G1YourHotkeyHere",
        "amount": 0.01,
        "netuid": 21,
    },
    signer=keypair,             # anything with .sign(bytes) -> bytes
)

print("txHash:", result["txHash"])
```

The `signer` can be:
- Any object with a `.sign(bytes) -> bytes` method (e.g. `bittensor.Keypair`, `substrateinterface.Keypair`)
- Any callable `(bytes) -> bytes`

### Supported tools

- `bittensor_stake_add`
- `bittensor_stake_remove`
- `bittensor_transfer`

## Getting a wallet JWT

```python
import hashlib, urllib.request, json

ss58 = keypair.ss58_address
domain = "bittensormcp.com"

# 1. Get nonce
resp = urllib.request.urlopen(urllib.request.Request(
    f"{endpoint}/api/auth/challenge",
    data=json.dumps({"ss58": ss58, "domain": domain}).encode(),
    headers={"Content-Type": "application/json"},
))
nonce = json.loads(resp.read())["nonce"]

# 2. Sign challenge
message = f"bittensormcp-auth:{nonce}:{domain}".encode()
signature = "0x" + keypair.sign(message).hex()

# 3. Exchange for JWT
resp = urllib.request.urlopen(urllib.request.Request(
    f"{endpoint}/api/auth/verify",
    data=json.dumps({"ss58": ss58, "nonce": nonce, "signature": signature}).encode(),
    headers={"Content-Type": "application/json"},
))
token = json.loads(resp.read())["token"]
```

## Security

- Zero runtime dependencies
- No postinstall scripts
- No network calls except to your configured `endpoint`
- Your private key is never passed to this package — only a signer callable
