"""Source-only ASK-gated Windows machine PowerShell adapter.

Disabled unless trusted Gateway runtime explicitly installs it. This module
does NOT grant the actor credentials or make a direct owner-only shell proxy.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import time
from urllib import error, request

from .core import Denied, Stale

AUDIENCE = "fortis-powershell-executor:machine-dispatch:v1"
DOMAIN = b"fortis:machine-powershell:v1\n"
_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_PROFILE = "windows-powershell-5.1-nonadmin-one-shot-v1"
_CONTRACT_DIGEST = hashlib.sha256(b"fortis-repo-machine-powershell:ASK_ONLY:v1").hexdigest()


def _canonical(obj):
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Denied("MACHINE_POWERSHELL_JSON_DENIED") from None


def _command(value):
    if type(value) is not str or not value.strip() or "\x00" in value:
        raise Denied("MACHINE_POWERSHELL_COMMAND_DENIED")
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError:
        raise Denied("MACHINE_POWERSHELL_COMMAND_DENIED") from None
    if len(raw) > 8192:
        raise Denied("MACHINE_POWERSHELL_COMMAND_DENIED")
    return hashlib.sha256(raw).hexdigest()


def issue_proof(key, *, actor, target, request_id, fingerprint, command_sha256,
                now=None, nonce=None):
    """Trusted Gateway ONLY. Caller-supplied approved flags are never accepted."""
    if (type(key) is not bytes or not 32 <= len(key) <= 4096 or
            type(actor) is not str or not _ID.fullmatch(actor) or
            type(target) is not str or not _ID.fullmatch(target) or
            type(request_id) is not str or not _UUID.fullmatch(request_id) or
            type(fingerprint) is not str or not _HEX.fullmatch(fingerprint) or
            type(command_sha256) is not str or not _HEX.fullmatch(command_sha256)):
        raise Denied("MACHINE_POWERSHELL_PROOF_ISSUER_DENIED")
    timestamp = int(time.time()) if now is None else now
    token_nonce = secrets.token_urlsafe(24) if nonce is None else nonce
    if (type(timestamp) is not int or type(token_nonce) is not str or
            not re.fullmatch(r"[a-zA-Z0-9_-]{22,128}", token_nonce)):
        raise Denied("MACHINE_POWERSHELL_PROOF_ISSUER_DENIED")
    claims = {
        "version": 1, "audience": AUDIENCE, "actor": actor, "target": target,
        "requestId": request_id, "coreFingerprint": fingerprint,
        "commandSha256": command_sha256, "issuedAt": timestamp,
        "expiresAt": timestamp + 60, "nonce": token_nonce,
    }
    mac = hmac.new(key, DOMAIN + _canonical(claims), hashlib.sha256).hexdigest()
    return {"claims": claims, "mac": mac}


def _private_file(path):
    if type(path) is not str or not Path(path).is_absolute():
        raise Denied("MACHINE_POWERSHELL_PRIVATE_CONFIG_REQUIRED")
    item = Path(path)
    if item.is_symlink() or not item.is_file():
        raise Denied("MACHINE_POWERSHELL_PRIVATE_CONFIG_REQUIRED")
    info = item.stat()
    if (info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) & 0o077):
        raise Denied("MACHINE_POWERSHELL_PRIVATE_CONFIG_REQUIRED")
    return item


class MachineShellTransport:
    """Fixed mTLS host, fixed machine API; no proxies or redirect following."""

    origin = "https://host.docker.internal:10443"

    def __init__(self, *, ca, client_cert, client_key, bearer_file, proof_file):
        ca_path = _private_file(ca)
        cert_path = _private_file(client_cert)
        key_path = _private_file(client_key)
        bearer_path = _private_file(bearer_file)
        proof_path = _private_file(proof_file)
        if len({str(x.resolve()) for x in (ca_path, cert_path, key_path,
                                           bearer_path, proof_path)}) != 5:
            raise Denied("MACHINE_POWERSHELL_CREDENTIAL_REUSE_DENIED")
        self.key = proof_path.read_bytes()
        self.bearer = bearer_path.read_text(encoding="ascii").strip()
        if (not 32 <= len(self.key) <= 4096 or
                not 32 <= len(self.bearer) <= 256 or
                any(not 33 <= ord(c) <= 126 for c in self.bearer)):
            raise Denied("MACHINE_POWERSHELL_CREDENTIAL_INVALID")
        context = ssl.create_default_context(cafile=str(ca_path))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self.opener = request.build_opener(
            request.ProxyHandler({}), request.HTTPSHandler(context=context),
            _NoRedirect())

    def _send(self, method, path, *, payload=None, request_id=None):
        if (method == "POST" and path != "/machine-shell/v1/execute") or (
                method == "GET" and (
                    not re.fullmatch(r"/machine-shell/v1/results/[0-9a-f-]{36}", path)
                    or payload is not None)) or method not in ("GET", "POST"):
            raise Denied("MACHINE_POWERSHELL_ROUTE_DENIED")
        body = None if payload is None else _canonical(payload)
        if body is not None and len(body) > 16000:
            raise Denied("MACHINE_POWERSHELL_REQUEST_LIMIT")
        headers = {"Authorization": "Bearer " + self.bearer, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Idempotency-Key"] = request_id
        req = request.Request(self.origin + path, data=body, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=90) as response:
                if response.status != 200:
                    raise RuntimeError("MACHINE_POWERSHELL_REMOTE_UNCONFIRMED")
                raw = response.read(2 * 65536 + 8192 + 1)
        except (OSError, error.HTTPError, error.URLError, TimeoutError):
            raise RuntimeError("MACHINE_POWERSHELL_REMOTE_UNCONFIRMED") from None
        if len(raw) > 2 * 65536 + 8192:
            raise RuntimeError("MACHINE_POWERSHELL_RESPONSE_LIMIT")
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError):
            raise RuntimeError("MACHINE_POWERSHELL_RESPONSE_INVALID") from None
        if type(result) is not dict:
            raise RuntimeError("MACHINE_POWERSHELL_RESPONSE_INVALID")
        return result

    def execute(self, request_id, command, proof):
        return self._send("POST", "/machine-shell/v1/execute", request_id=request_id,
                          payload={"requestId": request_id, "command": command,
                                   "proof": proof})

    def status(self, request_id):
        return self._send("GET", "/machine-shell/v1/results/" + request_id)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("MACHINE_POWERSHELL_REDIRECT_DENIED")


class MachinePowerShellAdapter:
    """Existing Core adapter: PENDING/ASK, only trusted approved Core dispatch."""

    def __init__(self, *, transport, target, actor, source_sha256, executor_identity):
        if (not hasattr(transport, "execute") or not hasattr(transport, "status") or
                type(transport.key) is not bytes or len(transport.key) < 32 or
                type(target) is not str or not _ID.fullmatch(target) or
                type(actor) is not str or not _ID.fullmatch(actor) or
                type(source_sha256) is not str or not _HEX.fullmatch(source_sha256) or
                type(executor_identity) is not str or not executor_identity):
            raise ValueError("MACHINE_POWERSHELL_ADAPTER_CONFIG_INVALID")
        self.transport = transport
        self.target, self.actor = target, actor
        self.source_sha256 = source_sha256
        self.executor_identity = executor_identity
        self.core = None

    def bind_core(self, core):
        if self.core is not None or core.adapters.get("powershell") is not None:
            raise ValueError("MACHINE_POWERSHELL_ALREADY_BOUND")
        self.core = core
        core.adapters["powershell"] = self
        # Exact trusted actor+target; unknown target, other actor => DENY.
        core.policies[(self.actor, "powershell", "execute", self.target)] = "ASK"

    def prepare(self, payload):
        if (type(payload) is not dict or
                payload.get("service") != "powershell" or
                payload.get("operation") != "execute" or
                payload.get("target") != self.target or
                type(payload.get("expectedVersion")) is not int or
                payload["expectedVersion"] != 0 or
                type(payload.get("params")) is not dict or
                set(payload["params"]) != {"command"}):
            raise Denied("MACHINE_POWERSHELL_SCOPE_DENIED")
        if (self.core is None or
                self.core._policy(self.actor, payload) != "ASK"):
            raise Denied("MACHINE_POWERSHELL_ASK_REQUIRED")
        command = payload["params"]["command"]
        digest = _command(command)
        return {
            "schemaVersion": 1, "disposition": "ASK_ONLY",
            "actor": self.actor, "target": self.target,
            "command": command, "commandSha256": digest,
            "contractVersion": 1, "contractDigest": _CONTRACT_DIGEST,
            "profile": _PROFILE, "sourceSha256": self.source_sha256,
            "executorIdentity": self.executor_identity,
            "workingDirectory": "Windows current user's home",
            "timeoutSeconds": 60, "outputLimitBytes": 65536,
            "warning": "Arbitrary PowerShell under Windows user identity; no sandbox or automatic risk verdict.",
        }

    def _approved_row(self, payload):
        if self.core is None:
            raise Denied("MACHINE_POWERSHELL_DISABLED")
        row = self.core._read(payload["requestId"])
        if (row["state"] != "DISPATCHED" or row["decision"] != "approve" or
                type(row["owner"]) is not str or not row["owner"] or
                row["actor"] != self.actor or row["request"] != payload or
                row["preview"] != self.prepare(payload) or
                self.core._policy(self.actor, payload) != "ASK"):
            raise Stale("MACHINE_POWERSHELL_OWNER_APPROVAL_REQUIRED")
        return row

    def apply(self, payload):
        row = self._approved_row(payload)
        proof = issue_proof(
            self.transport.key, actor=row["actor"], target=self.target,
            request_id=row["requestId"], fingerprint=row["fingerprint"],
            command_sha256=row["preview"]["commandSha256"])
        return self.transport.execute(row["requestId"],
                                      payload["params"]["command"], proof)

    def _check_receipt(self, request_id, result):
        if (type(result) is not dict or result.get("requestId") != request_id or
                result.get("state") not in ("EXECUTED", "FAILED") or
                type(result.get("commandSha256")) is not str):
            return False
        if self.core is None:
            return False
        row = self.core._read(request_id)
        if row["actor"] != self.actor or row["request"]["service"] != "powershell":
            return False
        if row["preview"]["commandSha256"] != result["commandSha256"]:
            return False
        if (type(result.get("exitCode")) is not int or
                type(result.get("stdout")) is not str or
                type(result.get("stderr")) is not str or
                len(result["stdout"].encode("utf-8")) > 65536 or
                len(result["stderr"].encode("utf-8")) > 65536):
            return False
        return True

    def receipt(self, request_id):
        row = self.core._read(request_id)
        if row["actor"] != self.actor or row["request"]["service"] != "powershell":
            raise Denied("MACHINE_POWERSHELL_RECEIPT_SCOPE_DENIED")
        response = self.transport.status(request_id)
        return None if response.get("state") == "NOT_FOUND" else response

    def confirm(self, request_id, result):
        if not self._check_receipt(request_id, result):
            return False
        remote = self.receipt(request_id)
        return self._check_receipt(request_id, remote) and remote == result
