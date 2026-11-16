"""Offline-only PS-AI-V1-02 ASK-only wire/preview contract prototype.

NOT imported by Gateway runtime; it does not authenticate, evaluate PowerShell,
authorize execution, sign proofs, send requests, or alter receipts.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid


class MachineShellContractError(ValueError):
    """No untrusted input or command bytes in errors."""


_TARGET = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROFILE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
MAX_COMMAND_BYTES = 8192


def canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (ValueError, UnicodeError, TypeError, OverflowError, RecursionError):
        raise MachineShellContractError("MACHINE_SHELL_JSON_INVALID") from None


def validate_submit(body: object, *, registered_targets: frozenset[str]) -> dict:
    """Exact machine-facing shape. Syntax success NEVER authorizes a command."""
    if type(body) is not dict or set(body) != {"requestId", "target", "command"}:
        raise MachineShellContractError("MACHINE_SHELL_SUBMIT_SCHEMA_DENIED")
    request_id, target, command = body["requestId"], body["target"], body["command"]
    if type(request_id) is not str:
        raise MachineShellContractError("MACHINE_SHELL_UUID_DENIED")
    try:
        parsed = uuid.UUID(request_id)
    except (ValueError, AttributeError):
        raise MachineShellContractError("MACHINE_SHELL_UUID_DENIED") from None
    if str(parsed) != request_id or parsed.version not in (4, 7):
        raise MachineShellContractError("MACHINE_SHELL_UUID_DENIED")
    if (type(target) is not str or _TARGET.fullmatch(target) is None or
            type(registered_targets) is not frozenset or target not in registered_targets):
        raise MachineShellContractError("MACHINE_SHELL_TARGET_DENIED")
    if type(command) is not str or not command.strip() or "\x00" in command:
        raise MachineShellContractError("MACHINE_SHELL_COMMAND_DENIED")
    # JSON escaping is unrelated to the Windows interpreter byte ceiling.
    try:
        raw = command.encode("utf-8", errors="strict")
    except UnicodeError:
        raise MachineShellContractError("MACHINE_SHELL_COMMAND_DENIED") from None
    if not 0 < len(raw) <= MAX_COMMAND_BYTES:
        raise MachineShellContractError("MACHINE_SHELL_COMMAND_DENIED")
    return {"requestId": request_id, "target": target, "command": command}


def frozen_preview(
    submitted: object,
    *,
    registered_targets: frozenset[str],
    trusted_context: dict,
) -> dict:
    """Build ASK-only review data; digest is NOT approval, signature or proof.

    Trusted context must be assembled on Gateway from authenticated actor,
    registered Windows target and fixed versioned ASK-only V1 contract.
    No editable command policy or AST filtering in V1. Context is not AI input.
    """
    body = validate_submit(submitted, registered_targets=registered_targets)
    keys = {"actor", "contractVersion", "contractDigest", "profile",
            "executorIdentity", "workingDirectory", "sourceSha256",
            "timeoutSeconds", "outputLimitBytes"}
    if type(trusted_context) is not dict or set(trusted_context) != keys:
        raise MachineShellContractError("MACHINE_SHELL_TRUSTED_CONTEXT_DENIED")
    c = trusted_context
    if (type(c["actor"]) is not str or not c["actor"] or len(c["actor"]) > 128 or
        type(c["contractVersion"]) is not int or c["contractVersion"] < 1 or
        type(c["contractDigest"]) is not str or not _HEX_SHA256.fullmatch(c["contractDigest"]) or
        type(c["profile"]) is not str or not _PROFILE.fullmatch(c["profile"]) or
        type(c["executorIdentity"]) is not str or not c["executorIdentity"] or
        type(c["workingDirectory"]) is not str or not c["workingDirectory"] or
        type(c["sourceSha256"]) is not str or not _HEX_SHA256.fullmatch(c["sourceSha256"]) or
        type(c["timeoutSeconds"]) is not int or not 1 <= c["timeoutSeconds"] <= 60 or
        type(c["outputLimitBytes"]) is not int or not 1 <= c["outputLimitBytes"] <= 65536):
        raise MachineShellContractError("MACHINE_SHELL_TRUSTED_CONTEXT_DENIED")
    snapshot = {
        "schemaVersion": 1, "disposition": "ASK_ONLY", "actor": c["actor"],
        "requestId": body["requestId"], "target": body["target"],
        "command": body["command"],
        "commandSha256": hashlib.sha256(body["command"].encode("utf-8")).hexdigest(),
        "contractVersion": c["contractVersion"], "contractDigest": c["contractDigest"],
        "profile": c["profile"], "executorIdentity": c["executorIdentity"],
        "workingDirectory": c["workingDirectory"], "sourceSha256": c["sourceSha256"],
        "timeoutSeconds": c["timeoutSeconds"], "outputLimitBytes": c["outputLimitBytes"],
    }
    digest = hashlib.sha256(canonical(snapshot)).hexdigest()
    return {"preview": snapshot, "previewSha256": digest}
