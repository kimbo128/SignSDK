/**
 * @bittensormcp/sign — self-custody signing helper for BittensorMCP.
 *
 * Implements the A2 two-step protocol:
 *   1. Call the write tool → receive UNSIGNED_PAYLOAD + intent_id
 *   2. Sign the payload locally → submit signature to bittensor_submit_signed
 *
 * SECURITY: This package never receives, stores, or transmits your private key
 * or mnemonic. You provide a signer function; the private key stays with you.
 */

export interface SignAndSubmitOptions {
  /** Base URL of the BittenSorMCP server, e.g. "https://bittensormcp.com" */
  endpoint: string;
  /** Wallet JWT from /api/auth/verify */
  token: string;
  /** MCP tool name, e.g. "bittensor_stake_add" */
  tool: string;
  /** Tool arguments */
  args: Record<string, unknown>;
  /**
   * sr25519 signer — receives raw payload bytes, returns 64-byte signature.
   * Example with @polkadot/keyring: (payload) => keypair.sign(payload)
   *
   * This function is called locally. Your private key never leaves your process.
   */
  signer: (payload: Uint8Array) => Uint8Array | Promise<Uint8Array>;
}

export interface SignAndSubmitResult {
  txHash: string;
  blockHash: string;
  block: number;
}

interface McpResponse {
  jsonrpc: '2.0';
  id: number;
  result?: {
    content?: Array<{ type: string; text?: string }>;
    structuredContent?: unknown;
  };
  error?: { code: number; message: string; data?: unknown };
}

interface UnsignedPayloadSignal {
  signal: 'UNSIGNED_PAYLOAD';
  intent_id: string;
  payload: string; // hex, no 0x prefix
  expires_at: string;
  hint: string;
}

async function mcpCall(
  endpoint: string,
  token: string,
  tool: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  const url = `${endpoint.replace(/\/$/, '')}/api/mcp`;
  const body = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: tool, arguments: args },
  });

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body,
  });

  const json: McpResponse = await res.json();

  if (json.error) {
    throw new Error(`MCP error [${json.error.code}]: ${json.error.message}`);
  }

  const result = json.result ?? {};

  // Prefer structuredContent (may be added by server in future)
  if (result.structuredContent != null) return result.structuredContent;

  // Fall back to parsing content[0].text as JSON
  const text = result.content?.[0]?.text;
  if (text) {
    try {
      return JSON.parse(text);
    } catch {
      return { text };
    }
  }

  return result;
}

export async function signAndSubmit(opts: SignAndSubmitOptions): Promise<SignAndSubmitResult> {
  const { endpoint, token, tool, args, signer } = opts;

  // Step 1: call the write tool — server returns UNSIGNED_PAYLOAD
  const step1 = (await mcpCall(endpoint, token, tool, args)) as Partial<UnsignedPayloadSignal>;

  if (step1?.signal !== 'UNSIGNED_PAYLOAD') {
    throw new Error(`Expected UNSIGNED_PAYLOAD signal, got: ${JSON.stringify(step1)}`);
  }

  const { intent_id, payload: payloadHex } = step1 as UnsignedPayloadSignal;

  // Step 2: sign locally — signer never called with your key, only with payload bytes
  const payloadBytes = hexToBytes(payloadHex);
  const sigBytes = await signer(payloadBytes);
  const signature = '0x' + bytesToHex(sigBytes);

  // Step 3: submit signature to server
  const step2 = (await mcpCall(endpoint, token, 'bittensor_submit_signed', {
    intent_id,
    signature,
  })) as Record<string, unknown>;

  if (!step2?.txHash) {
    throw new Error(`bittensor_submit_signed failed: ${JSON.stringify(step2)}`);
  }

  return {
    txHash: step2.txHash as string,
    blockHash: step2.blockHash as string,
    block: step2.block as number,
  };
}

function hexToBytes(hex: string): Uint8Array {
  const h = hex.replace(/^0x/, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ── Local wallet generation ──────────────────────────────────────────────
//
// Generates a fresh sr25519 keypair entirely in your process. The mnemonic
// is returned to you and never transmitted anywhere — this package makes
// zero network calls during generation. @polkadot/util-crypto is loaded
// lazily so signAndSubmit-only consumers (bring-your-own-keypair) don't pay
// for it.

export interface GeneratedWallet {
  /** 12-word mnemonic. Treat as a secret — store it yourself; nothing here persists it. */
  mnemonic: string;
  /** SS58-encoded address. Fund this before calling write tools or authenticate(). */
  ss58: string;
  /** sr25519 signer bound to this keypair. Pass directly as `signer` to signAndSubmit/authenticate. */
  sign: (payload: Uint8Array) => Uint8Array;
}

export async function generateWallet(ss58Format = 42): Promise<GeneratedWallet> {
  const { mnemonicGenerate, mnemonicToMiniSecret, sr25519PairFromSeed, sr25519Sign, encodeAddress, cryptoWaitReady } =
    await import('@polkadot/util-crypto');

  await cryptoWaitReady();

  const mnemonic = mnemonicGenerate();
  const seed = mnemonicToMiniSecret(mnemonic);
  const pair = sr25519PairFromSeed(seed);
  const ss58 = encodeAddress(pair.publicKey, ss58Format);

  return {
    mnemonic,
    ss58,
    sign: (payload: Uint8Array) => sr25519Sign(payload, pair),
  };
}

// ── Local authentication ─────────────────────────────────────────────────
//
// Runs the full challenge -> sign -> verify flow against the server, signing
// locally with the supplied signer. No private key material crosses this
// function; only the resulting signature does.

export interface AuthenticateOptions {
  /** Base URL of the BittensorMCP server, e.g. "https://bittensormcp.com" */
  endpoint: string;
  /** SS58 address to authenticate as */
  ss58: string;
  /** sr25519 signer for this ss58 — same shape as signAndSubmit's `signer` */
  signer: (payload: Uint8Array) => Uint8Array | Promise<Uint8Array>;
  /** Domain bound into the signed message. Defaults to the endpoint's host. */
  domain?: string;
}

export interface AuthenticateResult {
  token: string;
  subscriptionValidUntil: string | null;
}

// ── Premium activation ───────────────────────────────────────────────────
//
// Agent billing path (spec 010): activates or extends premium without a browser.
// Calls /api/billing/sign-transfer to get an unsigned Transfer extrinsic,
// signs locally, submits via /api/billing/submit-signed. No premium required
// to call these endpoints — this is the mechanism to GET premium.

export interface ActivatePremiumOptions {
  /** Base URL of the BittensorMCP server, e.g. "https://bittensormcp.com" */
  endpoint: string;
  /** Wallet JWT from authenticate() */
  token: string;
  /** sr25519 signer — same shape as signAndSubmit's signer */
  signer: (payload: Uint8Array) => Uint8Array | Promise<Uint8Array>;
  /** TAO amount to pay. Defaults to 0.1 (one month). Overpayment credited proportionally. */
  amountTao?: number;
}

export interface ActivatePremiumResult {
  subscriptionValidUntil: string;
  creditedDays: number;
  txHash: string;
}

export async function activatePremium(opts: ActivatePremiumOptions): Promise<ActivatePremiumResult> {
  const { endpoint, token, signer, amountTao = 0.1 } = opts;
  const base = endpoint.replace(/\/$/, '');

  const step1Res = await fetch(`${base}/api/billing/sign-transfer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ amountTao }),
  });
  if (!step1Res.ok) {
    throw new Error(`sign-transfer failed: HTTP ${step1Res.status} ${await step1Res.text()}`);
  }
  const { intent_id, payload: payloadHex } = (await step1Res.json()) as {
    signal: string; intent_id: string; payload: string; expires_at: string;
  };

  const payloadBytes = hexToBytes(payloadHex);
  const sigBytes = await signer(payloadBytes);
  const signature = '0x' + bytesToHex(sigBytes);

  const step2Res = await fetch(`${base}/api/billing/submit-signed`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ intent_id, signature }),
  });
  if (!step2Res.ok) {
    throw new Error(`submit-signed failed: HTTP ${step2Res.status} ${await step2Res.text()}`);
  }
  return (await step2Res.json()) as ActivatePremiumResult;
}

export async function authenticate(opts: AuthenticateOptions): Promise<AuthenticateResult> {
  const { endpoint, ss58, signer, domain } = opts;
  const base = endpoint.replace(/\/$/, '');
  const resolvedDomain = domain ?? new URL(base).host;

  const challengeRes = await fetch(`${base}/api/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ss58, domain: resolvedDomain }),
  });
  if (!challengeRes.ok) {
    throw new Error(`challenge failed: HTTP ${challengeRes.status} ${await challengeRes.text()}`);
  }
  const { nonce } = (await challengeRes.json()) as { nonce: string };

  const message = `bittensormcp-auth:${nonce}:${resolvedDomain}`;
  const messageBytes = new TextEncoder().encode(message);
  const sigBytes = await signer(messageBytes);
  const signature = '0x' + bytesToHex(sigBytes);

  const verifyRes = await fetch(`${base}/api/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ss58, nonce, signature }),
  });
  if (!verifyRes.ok) {
    throw new Error(`verify failed: HTTP ${verifyRes.status} ${await verifyRes.text()}`);
  }
  return (await verifyRes.json()) as AuthenticateResult;
}
