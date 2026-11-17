"""Typed Repo-side machine PowerShell facade. No owner credential or retry loop."""
import re

from ..core import Denied


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_TARGET = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class PowerShellMachineClient:
    """One ASK per fresh requestId. Never creates retries after uncertain ACKs."""

    def __init__(self, gateway):
        self.gateway = gateway

    def capabilities(self):
        response = self.gateway.post("/v1/powershell/capabilities", {})
        if type(response) is not dict or set(response) != {
                "configured", "policy", "machineExecutionAutoApprove", "version"}:
            raise Denied("MACHINE_POWERSHELL_CAPABILITIES_INVALID")
        if (response["configured"] is True and
                (response["policy"] != "ASK" or
                 response["machineExecutionAutoApprove"] is not False or
                 response["version"] != 1)):
            raise Denied("MACHINE_POWERSHELL_CAPABILITIES_INSECURE")
        return response

    def submit(self, command, *, request_id, target="windows-owner"):
        if (type(request_id) is not str or not _UUID.fullmatch(request_id) or
                type(target) is not str or not _TARGET.fullmatch(target) or
                type(command) is not str or not command.strip() or "\x00" in command):
            raise Denied("MACHINE_POWERSHELL_REQUEST_INVALID")
        try:
            size = len(command.encode("utf-8", "strict"))
        except UnicodeError:
            raise Denied("MACHINE_POWERSHELL_REQUEST_INVALID") from None
        if size > 8192:
            raise Denied("MACHINE_POWERSHELL_REQUEST_INVALID")
        # No call to intentions / generic Git retry. On a transport error the
        # original UUID must be read, not resubmitted with a new UUID.
        result = self.gateway.post("/v1/powershell/submit", {
            "requestId": request_id, "target": target, "command": command},
            accept_202=True)
        if (type(result) is not dict or result.get("requestId") != request_id or
                result.get("state") not in (
                    "PENDING", "REJECTED", "EXPIRED", "STALE", "REVOKED",
                    "APPROVED", "DISPATCHED", "EXECUTED", "UNCERTAIN")):
            raise Denied("MACHINE_POWERSHELL_RESPONSE_INVALID")
        return result

    def result(self, request_id):
        if type(request_id) is not str or not _UUID.fullmatch(request_id):
            raise Denied("MACHINE_POWERSHELL_REQUEST_INVALID")
        result = self.gateway.post("/v1/powershell/result", {"requestId": request_id},
                                   accept_202=True)
        if (type(result) is not dict or result.get("requestId") != request_id or
                type(result.get("state")) is not str):
            raise Denied("MACHINE_POWERSHELL_RESULT_INVALID")
        return result
