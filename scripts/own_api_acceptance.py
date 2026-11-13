#!/usr/bin/env python3
"""Explicit one-shot typed ALLOW READ acceptance; never repeats a submitted UUID.

The durable local intent is written BEFORE a request. On rerun, query result
with reconcile=False; never resubmit or auto-close UNKNOWN. No raw data output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
import sys

# The script is invoked directly from the canonical Repo checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import own_api_doctor as doctor

SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class AcceptanceStop(ValueError):
    pass


def check(ok, code):
    if not ok:
        raise AcceptanceStop(code)


def intent_path(path):
    check(path.is_absolute() and path.suffix == ".json",
          "JOURNAL_ABSOLUTE_JSON_REQUIRED")
    # A local Fortis workspace receipt, not protected Gateway state or Git.
    root = Path("/workspace/repo/Workfiles")
    # Reject path traversal and symlinks anywhere in the ancestor chain.
    check(path == path.resolve(strict=False) and
          path.parent.is_dir() and
          (path.parent == root or root in path.parent.parents) and
          path.parent.resolve() == path.parent and
          not path.is_symlink(), "JOURNAL_OWNER_WORKFILES_REQUIRED")
    return path


def persist_once(path, value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    check(len(data) <= 2048, "JOURNAL_LIMIT")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def read_intent(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        check(stat.S_ISREG(info.st_mode) and
              info.st_size <= 2048 and info.st_size > 0 and
              not (info.st_mode & 0o077), "JOURNAL_UNSAFE")
        data = os.read(fd, 2049)
    finally:
        os.close(fd)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise AcceptanceStop("JOURNAL_INVALID") from None


def validate_data(manifest, operation, target, data, catalog_version):
    """Use the trusted local packaged provider validator; do not invent schema."""
    from fortis_approvals.extensions.model import discover, bounded
    selected = discover((manifest["serviceId"],))
    check(len(selected) == 1, "PROVIDER_SOURCE_UNAVAILABLE")
    ops = [r for r in selected[0].operations if r.name == operation]
    check(len(ops) == 1 and ops[0].kind == "read" and ops[0].ready is True and
          ops[0].version == catalog_version, "PROVIDER_SOURCE_VERSION_CHANGED")
    op = ops[0]
    check(op.params is not None, "PROVIDER_PARAMS_SCHEMA_UNAVAILABLE")
    try:
        op.params({})
        bounded(data, 65536)
        op.result(data)
    except Exception:
        raise AcceptanceStop("PROVIDER_RESULT_SCHEMA_INVALID") from None
    if manifest["serviceId"] == "mirror" and operation == "get_repository":
        check(data["repository"]["repoId"] == target, "MIRROR_TARGET_RESULT_CHANGED")
    return len(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())


def acceptance(manifest, *, operation, target, request_id, expected_digest,
               journal, submit_read, client):
    valid = doctor.manifest_checker.validate(manifest)
    check(valid["sourcePinned"], "UPSTREAM_SOURCE_NOT_PINNED")
    check(type(expected_digest) is str and SHA256.fullmatch(expected_digest),
          "EXPECTED_DIGEST_INVALID")
    try:
        check(str(uuid.UUID(request_id)) == request_id, "UUID_INVALID")
    except (ValueError, TypeError, AttributeError):
        raise AcceptanceStop("UUID_INVALID") from None
    choices = [row for row in manifest["operations"] if row["name"] == operation and
               target in row["targets"]]
    check(len(choices) == 1 and choices[0]["effect"] == "READ" and
          choices[0]["policy"] == "ALLOW", "OPERATION_NOT_ALLOWLISTED")
    catalog = client.catalog()
    check(catalog.get("configurationDigest") == expected_digest,
          "LIVE_CONFIGURATION_DIGEST_MISMATCH")
    match = doctor.catalog_rows(catalog, manifest)
    check(match["status"] == "PASS", "LIVE_CATALOG_NOT_READY")
    rows = [r for r in catalog["operations"]
            if r["service"] == manifest["serviceId"] and
               r["operation"] == operation and r["target"] == target]
    check(len(rows) == 1 and type(rows[0].get("version")) is str,
          "LIVE_OPERATION_NOT_FOUND")

    manifest_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True,
                             separators=(",", ":")).encode()).hexdigest()
    intent = {"schemaVersion": 1, "requestId": request_id,
              "service": manifest["serviceId"], "operation": operation,
              "target": target, "configurationDigest": expected_digest,
              "manifestDigest": manifest_hash}
    path = intent_path(journal)
    existed = path.exists() or path.is_symlink()
    if existed:
        check(read_intent(path) == intent, "JOURNAL_BINDING_CHANGED")
    elif not submit_read:
        return {"status": "READY_FOR_ONE_SHOT_READ", "requestId": request_id,
                "submitted": False, "liveVerified": False}
    else:
        # Journal is intentionally created before any network effect.
        persist_once(path, intent)

    if existed:
        reply = client.result(request_id, reconcile=False)
    else:
        reply = client.call(manifest["serviceId"], operation, target, {},
                            reason="Owner-planned own-API scoped live READ acceptance",
                            request_id=request_id)
    check(type(reply) is dict and reply.get("requestId") == request_id,
          "RESPONSE_REQUEST_ID_MISMATCH")
    state = reply.get("state")
    if state != "EXECUTED":
        return {"status": "UNKNOWN_STOP_NO_REPLAY", "requestId": request_id,
                "state": state if state in ("PENDING", "UNCERTAIN", "NOT_FOUND",
                                           "REJECTED", "EXPIRED", "STALE") else "UNKNOWN",
                "liveVerified": False}
    if type(reply.get("data")) is not dict:
        reply = client.result(request_id, reconcile=False)
    check(type(reply) is dict and reply.get("requestId") == request_id and
          reply.get("state") == "EXECUTED" and type(reply.get("data")) is dict,
          "EXECUTED_RESULT_NOT_READABLE")
    size = validate_data(manifest, operation, target, reply["data"], rows[0]["version"])
    check(size <= choices[0]["maxResponseBytes"], "RESULT_EXCEEDS_MANIFEST_LIMIT")
    return {"status": "LIVE_TYPED_READ_VERIFIED", "requestId": request_id,
            "service": manifest["serviceId"], "operation": operation,
            "target": target, "configurationDigest": expected_digest,
            "schemaValidated": True, "resultBytes": size,
            "liveVerified": True, "submitted": True}


def main(argv=None, *, client=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--submit-read", action="store_true",
                        help="Explicit one-shot ALLOW/read; without it only validate/lookup")
    args = parser.parse_args(argv)
    try:
        manifest = doctor.manifest_checker.load(args.manifest)
        if client is None:
            from fortis_approvals.extensions.client import default_client
            client = default_client()
        result = acceptance(manifest, operation=args.operation, target=args.target,
            request_id=args.request_id, expected_digest=args.expected_digest,
            journal=args.journal, submit_read=args.submit_read, client=client)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] != "UNKNOWN_STOP_NO_REPLAY" else 3
    except (AcceptanceStop, doctor.manifest_checker.ManifestStop) as exc:
        # Codes are local constants, never print secret-bearing exception text.
        print(json.dumps({"status": "STOP", "code": str(exc)}, sort_keys=True))
        return 2
    except Exception:
        print('{"status":"UNKNOWN","code":"ACCEPTANCE_UNCONFIRMED_NO_REPLAY"}')
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
