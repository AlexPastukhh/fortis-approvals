#!/usr/bin/env python3
"""Source-only manifest lint for first-party HTTPS READ onboarding.

This deliberately does not connect to an upstream, read the Gateway vault,
grant permissions, or attest an owner release. It is NOT an installer.
"""
import argparse
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

MAX_INPUT = 32768
ID = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
DNS_LABEL = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
ALIAS = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
ROUTE_SEGMENT = re.compile(r"(?:[A-Za-z0-9._~-]+|\{[a-z][a-z0-9_]*\})\Z")
PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")


class ManifestStop(ValueError):
    """Fail closed with no secret values, paths, or raw input in the diagnostic."""


def check(ok, code):
    if not ok:
        raise ManifestStop(code)


def fields(value, exact, code):
    check(type(value) is dict and set(value) == set(exact), code)


def duplicates(pairs):
    value = {}
    for key, item in pairs:
        check(key not in value, "DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def load(path):
    # Source-only local artifact: bound file read, never follow a final symlink.
    check(path.is_absolute(), "MANIFEST_ABSOLUTE_PATH_REQUIRED")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            import stat
            check(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_INPUT,
                  "MANIFEST_FILE_INVALID")
            raw = os.read(fd, MAX_INPUT + 1)
            check(len(raw) == info.st_size, "MANIFEST_INPUT_LIMIT")
        finally:
            os.close(fd)
        return json.loads(raw.decode("utf-8"), object_pairs_hook=duplicates)
    except ManifestStop:
        raise
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        raise ManifestStop("MANIFEST_INPUT_INVALID") from None


def check_route(value, binding, path_parameters=None):
    """An additional typed receipt UUID is metadata, never a caller route."""
    check(type(value) is str and 1 <= len(value) <= 200 and
          value.startswith("/") and value != "/" and
          all(ROUTE_SEGMENT.fullmatch(part) and part not in (".", "..")
              for part in value[1:].split("/")), "ROUTE_NOT_CLOSED")
    check(path_parameters is None or
          type(path_parameters) is dict and path_parameters == {"request_id": "uuid4"},
          "ROUTE_PATH_PARAMETERS_INVALID")
    extra = [] if path_parameters is None else ["request_id"]
    found = PLACEHOLDER.findall(value)
    check((binding is None and not found and not extra) or
          (type(binding) is str and ID.fullmatch(binding) and
           binding not in extra and found == [binding] + extra),
          "ROUTE_TARGET_BINDING_INVALID")


def validate(value):
    fields(value, ("schemaVersion", "serviceId", "ownerRepository",
                   "sourceSha", "transport", "credential", "operations"),
           "MANIFEST_FIELDS_INVALID")
    check(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1,
          "MANIFEST_SCHEMA_UNSUPPORTED")
    service = value["serviceId"]
    check(type(service) is str and ID.fullmatch(service) and
          service not in ("github", "sonarcloud", "workspace", "synthetic"),
          "MANIFEST_SERVICE_INVALID")
    check(type(value["ownerRepository"]) is str and
          REPO.fullmatch(value["ownerRepository"]),
          "MANIFEST_OWNER_REPO_INVALID")
    sha = value["sourceSha"]
    check(sha is None or type(sha) is str and SHA.fullmatch(sha),
          "MANIFEST_SOURCE_SHA_INVALID")

    network = value["transport"]
    fields(network, ("profile", "origin", "tlsServerName", "pinnedCaPath",
                     "gatewayDockerNetwork"), "MANIFEST_TRANSPORT_INVALID")
    profile = network["profile"]
    check(profile in ("WIN-HTTPS", "DOCKER-HTTPS"), "MANIFEST_PROFILE_INVALID")
    check(type(network["origin"]) is str and len(network["origin"]) <= 200,
          "MANIFEST_ORIGIN_INVALID")
    try:
        url = urlsplit(network["origin"])
        hostname = url.hostname
        port = url.port
    except ValueError:
        raise ManifestStop("MANIFEST_ORIGIN_INVALID") from None
    check(url.scheme == "https" and url.username is None and url.password is None and
          url.path == "" and not url.query and not url.fragment and
          url.netloc and port in (None, 443) and
          type(hostname) is str and hostname == network["tlsServerName"] and
          network["origin"] in ("https://" + hostname, "https://" + hostname + ":443"),
          "MANIFEST_TLS_ORIGIN_INVALID")
    if profile == "WIN-HTTPS":
        check(hostname == "host.docker.internal" and
              network["gatewayDockerNetwork"] is None,
              "MANIFEST_WINDOWS_TRANSPORT_INVALID")
    else:
        check(type(hostname) is str and DNS_LABEL.fullmatch(hostname) and
              hostname not in ("localhost", "host", "gateway") and
              type(network["gatewayDockerNetwork"]) is str and
              ALIAS.fullmatch(network["gatewayDockerNetwork"]),
              "MANIFEST_DOCKER_TRANSPORT_INVALID")
    ca = network["pinnedCaPath"]
    check(type(ca) is str and len(ca) <= 180 and
          re.fullmatch(r"/run/fortis-secrets/[a-z][a-z0-9-]{0,63}/ca\.pem", ca),
          "MANIFEST_PINNED_CA_PATH_INVALID")

    credential = value["credential"]
    fields(credential, ("vaultAlias", "upstreamPrincipal", "vaultOwner"),
           "MANIFEST_CREDENTIAL_INVALID")
    check(type(credential["vaultAlias"]) is str and
          ALIAS.fullmatch(credential["vaultAlias"]) and
          type(credential["upstreamPrincipal"]) is str and
          1 <= len(credential["upstreamPrincipal"]) <= 80 and
          ALIAS.fullmatch(credential["upstreamPrincipal"]) and
          credential["vaultOwner"] == "OWNER_ONLY",
          "MANIFEST_CREDENTIAL_INVALID")
    ops = value["operations"]
    check(type(ops) is list and 1 <= len(ops) <= 20,
          "MANIFEST_OPERATIONS_INVALID")
    names = set()
    for op in ops:
        required = ("name", "method", "path", "targetBinding",
                    "targets", "effect", "policy", "maxResponseBytes")
        optional = ("pathParameters",) if "pathParameters" in op else ()
        fields(op, required + optional, "MANIFEST_OPERATION_FIELDS_INVALID")
        name = op["name"]
        check(type(name) is str and ID.fullmatch(name) and name not in names,
              "MANIFEST_OPERATION_ID_INVALID")
        names.add(name)
        # V1 lint purposefully supports READ only. ASK/WRITE requires a
        # separately reviewed effect/preview/receipt-specific contract.
        check(op["method"] == "GET" and op["effect"] == "READ" and
              op["policy"] == "ALLOW", "MANIFEST_READ_ONLY_REQUIRED")
        if "pathParameters" in op:
            check(type(op["pathParameters"]) is dict and
                  op["pathParameters"] == {"request_id": "uuid4"},
                  "ROUTE_PATH_PARAMETERS_INVALID")
        check_route(op["path"], op["targetBinding"], op.get("pathParameters"))
        targets = op["targets"]
        check(type(targets) is list and 1 <= len(targets) <= 30 and
              len(set(str(x) for x in targets)) == len(targets) and
              all(type(x) is str and NAME.fullmatch(x) and x not in (".", "..")
                  for x in targets), "MANIFEST_TARGET_SCOPE_INVALID")
        check(type(op["maxResponseBytes"]) is int and
              1 <= op["maxResponseBytes"] <= 262144,
              "MANIFEST_RESPONSE_LIMIT_INVALID")

    return {"status": "SOURCE_MANIFEST_VALID",
            "liveVerified": False, "readyToDeploy": False,
            "serviceId": service, "transportProfile": profile,
            "sourcePinned": sha is not None,
            "operationCount": len(ops)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = validate(load(args.manifest))
    except ManifestStop as exc:
        print(json.dumps({"status": "STOP", "reason": str(exc)},
                         sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
