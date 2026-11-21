"""Typed Fortis Repo-side SonarCloud client.

This module never receives or reads a SonarCloud token. It sends only closed
Sonar operation envelopes through the shared machine-authenticated transport.
"""
import argparse
import json
import re
import ssl
import sys
import uuid

from ....core import Denied
from ....clients.gateway_transport import (
    DEFAULT_CERTIFICATE, DEFAULT_ENDPOINT, DEFAULT_GRANT,
    MAX_RESPONSE_BYTES, GatewayTransport, read_machine_grant,
)
from ....repo_action_contract import validate_intent, validate_read_query

ENDPOINT = DEFAULT_ENDPOINT
PUBLIC_SERVER_CERT = DEFAULT_CERTIFICATE
CLIENT_GRANT_FILE = DEFAULT_GRANT
ALLOW_TEST_ENDPOINTS = False  # patched only by isolated TLS tests
_STATES = frozenset(("PENDING", "APPROVED", "DISPATCHED", "EXECUTED",
                     "REJECTED", "DENIED", "EXPIRED", "STALE", "UNCERTAIN",
                     "CANCELLED_BEFORE_DISPATCH"))
_OPERATIONS = {
    "sonar.list_projects": ("list_projects", "/v1/reads"),
    "sonar.list_issues": ("list_issues", "/v1/reads"),
    "sonar.get_issue": ("get_issue", "/v1/reads"),
    "sonar.get_quality_gate": ("get_quality_gate", "/v1/reads"),
    "sonar.propose_accept_issue": ("accept_issue", "/v1/actions"),
    "approvals.request_status": (None, "/v1/requests/"),
}
def payload(tool, *, target=None, project_key=None, page=1, page_size=20,
            reason=None, request_id=None):
    """Build one strict request. Proposal IDs must be stable and explicit."""
    if tool not in _OPERATIONS:
        raise Denied("FORTIS_TOOL_NOT_SUPPORTED")
    if tool == "approvals.request_status":
        if (type(request_id) is not str or
                not re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    request_id) or str(uuid.UUID(request_id)) != request_id):
            raise Denied("FORTIS_STATUS_REQUEST_ID_REQUIRED")
        return "/v1/requests/" + request_id, None
    operation, path = _OPERATIONS[tool]
    if operation == "accept_issue" and request_id is None:
        raise Denied("FORTIS_PROPOSAL_STABLE_REQUEST_ID_REQUIRED")
    ident = request_id or str(uuid.uuid4())
    if type(ident) is not str:
        raise Denied("FORTIS_REQUEST_ID_INVALID")
    params = {}
    if operation in ("list_projects", "list_issues"):
        params = {"page": page, "pageSize": page_size}
    elif operation in ("get_issue", "accept_issue"):
        params = {"projectKey": project_key}
    body = {"requestId": ident, "service": "sonarcloud",
            "operation": operation, "target": target, "params": params,
            "reason": reason or "Read Sonar quality or propose owner action"}
    if operation == "accept_issue":
        validate_intent(body)
    else:
        validate_read_query(body)
    return path, body


def call(tool, *, target=None, project_key=None, page=1, page_size=20,
         reason=None, request_id=None, transport=None, grant_path=None,
         certificate_path=None):
    """Invoke a typed Gateway operation; injected transport is test-only."""
    path, body = payload(tool, target=target, project_key=project_key,
                         page=page, page_size=page_size, reason=reason,
                         request_id=request_id)
    gateway = GatewayTransport(
        endpoint=ENDPOINT, grant_path=grant_path or CLIENT_GRANT_FILE,
        certificate_path=certificate_path or PUBLIC_SERVER_CERT,
        opener=transport, max_response_bytes=MAX_RESPONSE_BYTES,
        allow_test_endpoint=ALLOW_TEST_ENDPOINTS,
    )
    result = (gateway.get_status(request_id) if body is None else
              gateway.post(path, body, accept_202=(body["operation"] == "accept_issue" or
                                                  path == "/v1/reads")))
    if body is None or body["operation"] == "accept_issue":
        expected_id = request_id if body is None else body["requestId"]
        if (set(result) != {"requestId", "state"} or
                result["requestId"] != expected_id or
                type(result["state"]) is not str or result["state"] not in _STATES):
            raise Denied("FORTIS_STATUS_RESPONSE_INVALID")
    else:
        pending=(type(result) is dict and
                 set(result)=={"requestId","service","operation","state"} and
                 result["requestId"]==body["requestId"] and
                 result["operation"]==body["operation"] and
                 result["service"]=="sonarcloud" and
                 result["state"] in ("PENDING","REJECTED","EXPIRED","STALE"))
        if not pending and (type(result) is not dict or
                set(result) != {"requestId", "service", "operation", "data"} or
                result["requestId"] != body["requestId"] or
                result["operation"] != body["operation"] or
                result["service"] != "sonarcloud" or type(result["data"]) is not dict):
            raise Denied("FORTIS_READ_RESPONSE_INVALID")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Restricted Fortis Sonar client; no upstream Sonar credential")
    parser.add_argument("tool", choices=sorted(_OPERATIONS))
    parser.add_argument("--target")
    parser.add_argument("--project-key")
    parser.add_argument("--page", type=int, default=1)
    parser.add_argument("--page-size", type=int, default=20)
    parser.add_argument("--reason")
    parser.add_argument("--request-id")
    args = parser.parse_args(argv)
    try:
        result = call(args.tool, target=args.target,
                      project_key=args.project_key, page=args.page,
                      page_size=args.page_size, reason=args.reason,
                      request_id=args.request_id)
    except (Denied, ValueError) as exc:
        print("FORTIS_REPO_TOOL_DENIED=" + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


# Backward-compatible private helper for existing source-only tests/tools.
_grant_from_file = read_machine_grant


if __name__ == "__main__":
    raise SystemExit(main())
