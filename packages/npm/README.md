# @bittensormcp/sign

Self-custody signing helper for [BittensorMCP](https://bittensormcp.com).

Implements the A2 two-step protocol so your AI agent can stake, unstake, and transfer TAO **without your private key ever leaving your machine**.

## How it works

1. Agent calls a write tool (e.g. `bittensor_stake_add`) → server returns an `UNSIGNED_PAYLOAD`
2. This package signs the payload locally with your sr25519 keypair
3. The signature is sent to `bittensor_submit_signed` → server submits the extrinsic

**Your private key never leaves your process.** The signer callback receives payload bytes; your keypair stays with you.

## Installation

```bash
npm install @bittensormcp/sign
```

## Usage

```typescript
import { signAndSubmit } from '@bittensormcp/sign';
import { Keyring } from '@polkadot/keyring';

const keyring = new Keyring({ type: 'sr25519' });
const keypair = keyring.addFromMnemonic('your twelve word mnemonic ...');

const result = await signAndSubmit({
  endpoint: 'https://bittensormcp.com',
  token: walletJwt,           // from /api/auth/verify
  tool: 'bittensor_stake_add',
  args: {
    hotkey: '5G1YourHotkeyHere',
    amount: 0.01,
    netuid: 21,
  },
  signer: (payload) => keypair.sign(payload),
});

console.log('txHash:', result.txHash);
```

### Supported tools

- `bittensor_stake_add`
- `bittensor_stake_remove`
- `bittensor_transfer`

## Getting a wallet JWT

```typescript
// 1. Get a challenge nonce
const { nonce } = await fetch(`${endpoint}/api/auth/challenge`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ss58: keypair.address, domain: 'bittensormcp.com' }),
}).then(r => r.json());

// 2. Sign the challenge
const message = `bittensormcp-auth:${nonce}:bittensormcp.com`;
const signature = u8aToHex(keypair.sign(stringToU8a(message)));

// 3. Exchange for a JWT
const { token } = await fetch(`${endpoint}/api/auth/verify`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ss58: keypair.address, nonce, signature }),
}).then(r => r.json());
```

## Generating a wallet (no human-held keypair needed)

If your agent doesn't already have a coldkey, generate one locally — nothing leaves your process:

```typescript
import { generateWallet, authenticate, signAndSubmit } from '@bittensormcp/sign';

const wallet = await generateWallet();
console.log(`Fund this address before writes: ${wallet.ss58}`);
// wallet.mnemonic is yours to store — this package never persists or sends it

const { token } = await authenticate({
  endpoint: 'https://bittensormcp.com',
  ss58: wallet.ss58,
  signer: wallet.sign,
});

const result = await signAndSubmit({
  endpoint: 'https://bittensormcp.com',
  token,
  tool: 'bittensor_stake_add',
  args: { hotkey: '5G1...', amount: 0.01, netuid: 21 },
  signer: wallet.sign,
});
```

Wallet *generation* and *authentication* are fully agentic — no human needs to touch a
browser extension. *Funding* the address with TAO is the one step that always needs a
value source outside the system; that's not a limitation of this package, it's what
self-custody means.

## Security

- Zero postinstall scripts
- `@polkadot/util-crypto` is the only runtime dependency, used solely by `generateWallet()`
  (lazy-imported — `signAndSubmit`/`authenticate` alone don't pull it in)
- No network calls except to your configured `endpoint`
- Your private key is never passed to this package — only the `signer` callback, and
  `generateWallet()`'s keypair never leaves the closure it's generated in
