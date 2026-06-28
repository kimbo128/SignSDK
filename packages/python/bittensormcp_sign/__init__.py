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


__all__ = ["sign_and_submit"]
__version__ = "0.1.0"
