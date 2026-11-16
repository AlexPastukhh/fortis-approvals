"""Action Core DOCKER-HTTPS transport with its owner-provisioned CA certificate."""
import os
import re
import ssl
import stat
from pathlib import Path
from urllib import request

from fortis_approvals.core import Denied
from fortis_approvals.extensions.http import JSONAPI, NoRedirect, Route
from fortis_approvals.extensions.vault import Secret

CA_PATH = Path("/run/fortis-secrets/action-core-read/ca.pem")
ORIGIN = "https://action-core-gw"
ROUTES = (
    Route(
        "read_action",
        "GET",
        "/gateway/v1/actions/{action_id}",
        readonly=True,
    ),
)


def action_core_context():
    """Trust only the owner-provisioned public CA; never fall back to system trust."""
    try:
        if CA_PATH.parent.is_symlink() or CA_PATH.parent.parent.is_symlink():
            raise ValueError("CA path contains a symlink")
        fd = os.open(CA_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or not 0 < metadata.st_size <= 16384
            ):
                raise ValueError("CA file type, permissions or size")
            with os.fdopen(fd, "rb", closefd=False) as source:
                pem = source.read(16385)
            if (
                not 0 < len(pem) <= 16384
                or re.fullmatch(
                    rb"\s*-----BEGIN CERTIFICATE-----\s*"
                    rb"[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*",
                    pem,
                ) is None
            ):
                raise ValueError("CA PEM")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=pem.decode("ascii"))
            if (
                not context.check_hostname
                or context.verify_mode != ssl.CERT_REQUIRED
            ):
                raise ValueError("TLS verification")
            return context
        finally:
            os.close(fd)
    except (OSError, UnicodeError, ValueError, ssl.SSLError):
        raise Denied("ACTION_CORE_CA_UNAVAILABLE") from None


class ActionCorePinnedAPI:
    """Fixed HTTPS/443 GET transport; no proxy, redirects or caller URL."""

    origin = ORIGIN

    def __init__(self):
        self.routes = {route.name: route for route in ROUTES}

    def call(
        self,
        route_name,
        *,
        credential=None,
        path=None,
        query=None,
        body=None,
        request_id=None,
    ):
        if route_name not in self.routes:
            raise Denied("ACTION_CORE_ROUTE_DENIED")
        if not isinstance(credential, Secret):
            raise Denied("ACTION_CORE_CREDENTIAL_REQUIRED")
        if (
            type(path) is not dict
            or set(path) != {"action_id"}
            or path["action_id"] not in {"3", "4"}
        ):
            raise Denied("ACTION_CORE_TARGET_DENIED")
        if query not in (None, {}) or body is not None:
            raise Denied("ACTION_CORE_READ_ONLY_ROUTE")
        context = action_core_context()
        opener = request.build_opener(
            request.ProxyHandler({}),
            NoRedirect(),
            request.HTTPSHandler(context=context),
        )
        transport = JSONAPI(
            self.origin,
            ROUTES,
            timeout=5,
            max_response_bytes=65_536,
            opener=opener,
        )
        return transport.call(
            route_name,
            credential=credential,
            path=path,
            query=query,
            body=body,
            request_id=request_id,
        )
