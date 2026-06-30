"""
bittensormcp-sign — self-custody signing helper for BittensorMCP.

Implements the A2 two-step protocol so your AI agent can stake, unstake, and
transfer TAO without your private key ever leaving your machine.

SECURITY: This package never receives, stores, or transmits your private key
or mnemonic. You provide a signer callable; the key stays with you.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Union


class _SignerProtocol:
    """Duck-type check — anything with a .sign(bytes) -> bytes method works."""
    def sign(self, data: bytes) -> bytes: ...


Signer = Union[Callable[[bytes], bytes], _SignerProtocol]


def sign_and_submit(
    endpoint: str,
    token: str,
    tool: str,
    args: dict[str, Any],
    signer: Signer,
) -> dict[str, Any]:
    """
    Two-step self-custody signing for a BittenSorMCP write tool.

    Args:
        endpoint:  Base URL, e.g. "https://bittensormcp.com"
        token:     Wallet JWT from /api/auth/verify
        tool:      MCP tool name, e.g. "bittensor_stake_add"
        args:      Tool arguments dict
        signer:    Callable[bytes -> bytes] or object with .sign(bytes) -> bytes.
                   Receives raw payload bytes, must return a 64-byte sr25519 signature.
                   Your private key is never passed to this package.

    Returns:
        {"txHash": str, "blockHash": str, "block": int}

    Raises:
        ValueError:   Unexpected server response or missing txHash
        RuntimeError: MCP-level error or HTTP error
    """
    # Step 1: call the write tool — server returns UNSIGNED_PAYLOAD
    step1 = _mcp_call(endpoint, token, tool, args)

    if not isinstance(step1, dict) or step1.get("signal") != "UNSIGNED_PAYLOAD":
        raise ValueError(f"Expected UNSIGNED_PAYLOAD signal, got: {step1!r}")

    intent_id: str = step1["intent_id"]
    payload_hex: str = step1["payload"]

    # Step 2: sign locally — your private key never leaves your process
    payload_bytes = bytes.fromhex(payload_hex.removeprefix("0x"))
    sign_fn = getattr(signer, "sign", None)
    if callable(sign_fn):
        sig_bytes: bytes = sign_fn(payload_bytes)
    else:
        sig_bytes = signer(payload_bytes)  # type: ignore[arg-type]
    signature = "0x" + sig_bytes.hex()

    # Step 3: submit signature
    step2 = _mcp_call(endpoint, token, "bittensor_submit_signed", {
        "intent_id": intent_id,
        "signature": signature,
    })

    if not isinstance(step2, dict) or "txHash" not in step2:
        raise ValueError(f"bittensor_submit_signed failed: {step2!r}")

    return {
        "txHash": step2["txHash"],
        "blockHash": step2.get("blockHash", ""),
        "block": step2.get("block", 0),
    }


def _mcp_call(endpoint: str, token: str, tool: str, args: dict[str, Any]) -> Any:
    url = endpoint.rstrip("/") + "/api/mcp"
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }).encode()

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data: dict = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} from {url}: {exc.read().decode(errors='replace')}") from exc

    if "error" in data:
        err = data["error"]
        raise RuntimeError(f"MCP error [{err.get('code')}]: {err.get('message')}")

    result = data.get("result") or {}

    # Prefer structuredContent
    if result.get("structuredContent") is not None:
        return result["structuredContent"]

    # Fall back to content[0].text parsed as JSON
    content = result.get("content") or []
    if content and content[0].get("type") == "text":
        text = content[0].get("text", "")
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return {"text": text}

    return result


# ── Local wallet generation ──────────────────────────────────────────────
#
# Generates a fresh sr25519 keypair entirely in your process. The mnemonic
# is returned to you and never transmitted anywhere. Requires the optional
# 'substrateinterface' dependency (pip install bittensormcp-sign[wallet]) so
# the base package stays dependency-free for bring-your-own-keypair users.

def generate_wallet() -> dict[str, Any]:
    """
    Generate a fresh sr25519 keypair locally. Nothing is sent over the network.

    Requires: pip install bittensormcp-sign[wallet]

    Returns:
        {"mnemonic": str, "ss58": str, "sign": Callable[[bytes], bytes]}

    The mnemonic is returned to you and never persisted or transmitted by
    this package. Store it yourself if you need the wallet to survive
    process restarts.
    """
    try:
        from substrateinterface import Keypair
    except ImportError as exc:
        raise ImportError(
            "generate_wallet() requires substrateinterface. "
            "Install with: pip install bittensormcp-sign[wallet]"
        ) from exc

    mnemonic = Keypair.generate_mnemonic()
    kp = Keypair.create_from_mnemonic(mnemonic, crypto_type=1)  # 1 = sr25519

    return {
        "mnemonic": mnemonic,
        "ss58": kp.ss58_address,
        "sign": lambda payload: kp.sign(payload),
    }


# ── Local authentication ─────────────────────────────────────────────────
#
# Runs the full challenge -> sign -> verify flow locally, signing with the
# supplied signer. No private key material crosses this function.

def authenticate(
    endpoint: str,
    ss58: str,
    signer: Signer,
    domain: str | None = None,
) -> dict[str, Any]:
    """
    Complete the wallet-JWT auth flow: request a nonce, sign it locally, verify.

    Args:
        endpoint: Base URL, e.g. "https://bittensormcp.com"
        ss58:     SS58 address to authenticate as
        signer:   Callable[bytes -> bytes] or object with .sign(bytes) -> bytes
        domain:   Optional; defaults to the endpoint's host

    Returns:
        {"token": str, "subscriptionValidUntil": str | None}
    """
    from urllib.parse import urlparse

    base = endpoint.rstrip("/")
    resolved_domain = domain or urlparse(base).netloc

    challenge = _http_post_json(f"{base}/api/auth/challenge", {"ss58": ss58, "domain": resolved_domain})
    nonce = challenge["nonce"]

    message = f"bittensormcp-auth:{nonce}:{resolved_domain}".encode()
    sign_fn = getattr(signer, "sign", None)
    sig_bytes: bytes = sign_fn(message) if callable(sign_fn) else signer(message)  # type: ignore[arg-type]
    signature = "0x" + sig_bytes.hex()

    return _http_post_json(f"{base}/api/auth/verify", {"ss58": ss58, "nonce": nonce, "signature": signature})


# ── Premium activation ───────────────────────────────────────────────────
#
# Agent billing path (spec 010): activates or extends premium without a browser.
# No premium required — this is the mechanism to GET premium.

def activate_premium(
    endpoint: str,
    token: str,
    signer: Signer,
    amount_tao: float | None = None,
) -> dict[str, Any]:
    """
    Activate or extend premium subscription programmatically (agent billing path).

    Args:
        endpoint:   Base URL, e.g. "https://bittensormcp.com"
        token:      Wallet JWT from authenticate()
        signer:     Callable[bytes -> bytes] or object with .sign(bytes) -> bytes
        amount_tao: TAO to pay. Defaults to 0.1 (one month). Overpayment credited proportionally.

    Returns:
        {"subscriptionValidUntil": str, "creditedDays": int, "txHash": str}
    """
    base = endpoint.rstrip("/")
    tao = amount_tao if amount_tao is not None else 0.1

    step1 = _http_post_json_auth(f"{base}/api/billing/sign-transfer", token, {"amountTao": tao})

    payload_hex: str = step1["payload"]
    intent_id: str = step1["intent_id"]

    payload_bytes = bytes.fromhex(payload_hex.removeprefix("0x"))
    sign_fn = getattr(signer, "sign", None)
    sig_bytes: bytes = sign_fn(payload_bytes) if callable(sign_fn) else signer(payload_bytes)  # type: ignore[arg-type]
    signature = "0x" + sig_bytes.hex()

    return _http_post_json_auth(f"{base}/api/billing/submit-signed", token, {
        "intent_id": intent_id,
        "signature": signature,
    })


def _http_post_json_auth(url: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} from {url}: {exc.read().decode(errors='replace')}") from exc


def _http_post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} from {url}: {exc.read().decode(errors='replace')}") from exc


__all__ = ["sign_and_submit", "generate_wallet", "authenticate", "activate_premium"]
__version__ = "0.3.0"
