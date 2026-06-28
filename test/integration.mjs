/**
 * T747 — signAndSubmit round-trip integration test against production.
 *
 * Usage:
 *   node test/integration.mjs <mnemonic> <ss58>
 *
 * The test:
 *   1. Authenticates (challenge → sign → verify) to get a JWT
 *   2. Calls bittensor_premium_status to check tier/subscription
 *   3. If PREMIUM: runs stake_add 0.001 TAO on subnet 1 (smallest possible),
 *      then immediately stake_remove to return funds
 *   4. Verifies txHash looks like a real hash
 *
 * Prerequisites: the account must have an active premium subscription.
 */

import { signAndSubmit } from '../packages/npm/dist/index.mjs';
import { createRequire } from 'module';
import https from 'https';
import crypto from 'crypto';

const ENDPOINT = 'https://bittensormcp.com';

const [,, mnemonic, ss58Arg] = process.argv;
if (!mnemonic) {
  console.error('Usage: node test/integration.mjs "<mnemonic>" [ss58]');
  process.exit(1);
}

// --- helpers -----------------------------------------------------------------

function post(path, body, token) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const req = https.request({ hostname: 'bittensormcp.com', path, method: 'POST', headers }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(d) }); }
        catch { resolve({ status: res.statusCode, body: d }); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// --- step 1: derive ss58 + keypair from mnemonic ----------------------------
// We use @polkadot/keyring if available, otherwise prompt user to pass ss58 and sign manually.

let keypair;
let ss58;

try {
  const { Keyring } = await import('@polkadot/keyring');
  const { mnemonicToMiniSecret, sr25519Sign, sr25519PairFromSeed } = await import('@polkadot/util-crypto');
  const { u8aToHex } = await import('@polkadot/util');

  const seed = mnemonicToMiniSecret(mnemonic);
  const pair = sr25519PairFromSeed(seed);
  const kr = new Keyring({ type: 'sr25519', ss58Format: 42 });
  const kp = kr.addFromSeed(seed);
  ss58 = ss58Arg ?? kp.address;

  keypair = {
    sign: (msg) => {
      const sig = sr25519Sign(msg, { publicKey: pair.publicKey, secretKey: pair.secretKey });
      return sig;
    },
    address: ss58,
  };
  console.log(`[T747] Using @polkadot/keyring — ss58: ${ss58}`);
} catch {
  // Fallback: use substrateinterface via child_process (Python) if polkadot not available
  console.error('[T747] @polkadot/keyring not found. Install it or use the Python test runner.');
  process.exit(1);
}

// --- step 2: authenticate ----------------------------------------------------

console.log('\n[T747] Step 1: Request challenge...');
const domain = 'bittensormcp.com';
const chalRes = await post('/api/auth/challenge', { ss58, domain });
if (chalRes.status !== 200) { console.error('Challenge failed:', chalRes); process.exit(1); }
const { nonce } = chalRes.body;
console.log(`[T747] nonce: ${nonce}`);

const message = `bittensormcp-auth:${nonce}:${domain}`;
const msgBytes = new TextEncoder().encode(message);
const sigBytes = keypair.sign(msgBytes);
const signature = '0x' + Buffer.from(sigBytes).toString('hex');

console.log('[T747] Step 2: Verify signature...');
const verRes = await post('/api/auth/verify', { ss58, nonce, signature });
if (verRes.status !== 200) { console.error('Verify failed:', verRes); process.exit(1); }
const { token: jwt } = verRes.body;
console.log(`[T747] JWT: ${jwt.slice(0, 40)}...`);

// --- step 3: check premium status --------------------------------------------

console.log('\n[T747] Step 3: bittensor_premium_status...');

// Call via MCP protocol
const mcpCallRes = await post('/api/mcp', {
  jsonrpc: '2.0', id: 1, method: 'tools/call',
  params: { name: 'bittensor_premium_status', arguments: {} }
}, jwt);

if (mcpCallRes.status !== 200) { console.error('premium_status failed:', mcpCallRes); process.exit(1); }

const premiumContent = mcpCallRes.body?.result?.content?.[0]?.text;
console.log('[T747] premium_status:', premiumContent);

let premiumData;
try { premiumData = JSON.parse(premiumContent); } catch { premiumData = {}; }

if (premiumData.tier !== 'PREMIUM') {
  console.log(`[T747] Account is ${premiumData.tier} — skipping write test (need PREMIUM). Auth test PASSED.`);
  process.exit(0);
}

// --- step 4: signAndSubmit round-trip (stake_add then stake_remove) ----------

console.log('\n[T747] Step 4: stake_add 0.001 TAO subnet 1...');

// Signer callback using our keypair
const signer = (payload) => keypair.sign(payload);

const stakeResult = await signAndSubmit({
  endpoint: ENDPOINT,
  token: jwt,
  tool: 'bittensor_stake_add',
  args: { amount: 0.001, netuid: 1 },
  signer,
});

console.log('[T747] stake_add result:', stakeResult);
if (!stakeResult.txHash?.startsWith('0x')) {
  console.error('[T747] FAIL: txHash missing or malformed');
  process.exit(1);
}

console.log('\n[T747] Step 5: stake_remove to return funds...');
const unstakeResult = await signAndSubmit({
  endpoint: ENDPOINT,
  token: jwt,
  tool: 'bittensor_stake_remove',
  args: { amount: 0.001, netuid: 1 },
  signer,
});

console.log('[T747] stake_remove result:', unstakeResult);
if (!unstakeResult.txHash?.startsWith('0x')) {
  console.error('[T747] FAIL: stake_remove txHash missing');
  process.exit(1);
}

console.log('\n[T747] ALL TESTS PASSED');
console.log('  Auth:         OK');
console.log('  stake_add:   ', stakeResult.txHash);
console.log('  stake_remove:', unstakeResult.txHash);
