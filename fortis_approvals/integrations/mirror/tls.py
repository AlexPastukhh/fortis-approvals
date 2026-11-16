"""Mirror-only private-CA TLS trust, without changes to global HTTPS clients.

CA_PATH is a fixed trusted-source path in the already existing Gateway
read-only secrets mount. The CA PEM is public; its provenance is owner-reviewed.
Missing, invalid or inaccessible CA MUST NOT fall back to system trust or HTTP.
"""
import os
from pathlib import Path
import ssl
import stat
from urllib import request

from fortis_approvals.core import Denied
from fortis_approvals.extensions.http import JSONAPI, NoRedirect, Route

CA_PATH = Path("/run/fortis-secrets/mirror-read/ca.pem")
ORIGIN = "https://host.docker.internal"
PAGE_QUERY = ('offset', 'limit', 'revision')
INVENTORY_QUERY = ('inventory', 'scope_digest')
ROUTES = (
    Route("get_repo", "GET", "/gateway/v1/repositories/{repo_id}", readonly=True),
    Route("list_repositories_v2", "GET", "/gateway/v2/repositories", readonly=True,
          query_keys=PAGE_QUERY + INVENTORY_QUERY),
    Route("get_repository_v2", "GET", "/gateway/v2/repositories/{repo_id}", readonly=True),
    Route("list_worktrees_v2", "GET", "/gateway/v2/repositories/{repo_id}/worktrees",
          readonly=True, query_keys=PAGE_QUERY),
    Route("get_github_status_v2", "GET", "/gateway/v2/repositories/{repo_id}/github",
          readonly=True, query_keys=PAGE_QUERY),
    Route("get_available_actions_v2", "GET", "/gateway/v2/repositories/{repo_id}/actions", readonly=True),
    Route("get_capabilities_v2", "GET", "/gateway/v2/capabilities", readonly=True,
          query_keys=INVENTORY_QUERY),
)


def mirror_context():
    """Load exactly one CA from an owner-provisioned regular PEM; never print it."""
    try:
        # No symlink at the leaf or service-specific parent directory.
        if CA_PATH.parent.is_symlink():
            raise ValueError("parent link")
        fd = os.open(CA_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or not 0 < meta.st_size <= 16384:
                raise ValueError("CA size or file type")
            with os.fdopen(fd, "rb", closefd=False) as source:
                pem = source.read(16385)
            if (not 0 < len(pem) <= 16384 or
                    pem.count(b"-----BEGIN CERTIFICATE-----") != 1 or
                    pem.count(b"-----END CERTIFICATE-----") != 1):
                raise ValueError("CA PEM")
            # Supplying cadata means ONLY this CA is trusted: not global CAs.
            context = ssl.create_default_context(cadata=pem.decode("ascii"))
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError("TLS verification")
            return context
        finally:
            os.close(fd)
    except (OSError, UnicodeError, ValueError, ssl.SSLError):
        raise Denied("MIRROR_CA_UNAVAILABLE") from None


class MirrorPinnedAPI:
    """Only fixed HTTPS/443 GET, with owner-reviewable service-specific CA."""

    origin = ORIGIN

    def __init__(self):
        self.routes = {route.name: route for route in ROUTES}

    def call(self, route_name, *, credential=None, path=None, query=None,
             body=None, request_id=None):
        if route_name not in self.routes:
            raise Denied("INTEGRATION_ROUTE_DENIED")
        context = mirror_context()
        opener = request.build_opener(
            request.ProxyHandler({}), NoRedirect(),
            request.HTTPSHandler(context=context))
        # Preserve JSONAPI's strict path, query, credential, status, size, and
        # no-redirect contract. Never mutate a shared opener between calls.
        transport = JSONAPI(self.origin, ROUTES, opener=opener)
        return transport.call(route_name, credential=credential, path=path,
                              query=query, body=body, request_id=request_id)
