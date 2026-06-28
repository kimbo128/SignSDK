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
