"""Trusted GitHub adapter construction and opt-in Gateway registration.

Registration intentionally does NOT add actor grants or policy entries.
Core defaults every GitHub operation to DENY until a separate owner-reviewed
policy configuration is supplied.
"""
from ...core import Denied
from .contract import GITHUB_ACTION_OPERATIONS, GITHUB_READ_OPERATIONS
from .gateway.adapter import GitHubAdapter
from .gateway.transport import GitHubHTTPTransport, TOKEN_FILE


def build_github_adapter(*, owner, repositories, receipt_store,
                         token_path=TOKEN_FILE, transport=None):
    """Build Gateway-only adapter; token is read only when this is called."""
    upstream = transport or GitHubHTTPTransport.from_file(token_path)
    return GitHubAdapter(
        upstream, owner=owner, repositories=repositories,
        receipt_store=receipt_store,
    )


def register_github_integration(*, core, broker, adapter):
    """Register adapter plumbing only; never grant an actor or choose policy."""
    if not isinstance(adapter, GitHubAdapter):
        raise ValueError("GITHUB_ADAPTER_REQUIRED")
    if "github" in core.adapters or "github" in broker.read_adapters:
        raise Denied("GITHUB_INTEGRATION_ALREADY_REGISTERED")
    core.adapters["github"] = adapter
    broker.read_adapters["github"] = adapter
    # No mutation of core.policies, broker.actor_operations or
    # broker.actor_read_operations. All operations remain DENY by default.
    return {
        "service": "github",
        "read_operations": GITHUB_READ_OPERATIONS,
        "action_operations": GITHUB_ACTION_OPERATIONS,
        "policy_configured": False,
        "actor_grants_configured": False,
    }
