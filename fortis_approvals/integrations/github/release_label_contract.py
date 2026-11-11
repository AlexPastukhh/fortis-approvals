"""Closed *transport authorization* types for Fortis-managed Release Labels.

The public fortis-release-impact-action owns semantic label PROJECTION. This
module defines only the minimal managed namespace and bounds for mutation.
It must never infer release impact or authorize deployment.
"""
import hashlib
import re
from ...core import Denied, canonical

RELEASE = frozenset({
    "release:no-deployment", "release:image-rebuild", "release:config-deploy",
    "release:windows-update", "release:package-build",
    "release:migration-required", "release:review-required",
})
BUILD = re.compile(r"build:[a-z][a-z0-9-]{0,43}\Z")
LABEL_NAME = re.compile(r"[^\x00-\x1f\x7f]{1,50}\Z")
MAX_LABELS = 250
STICKY = "release:review-required"


def managed(value, *, removable=False):
    if type(value) is not str or len(value) > 50 or not (
        value in RELEASE or BUILD.fullmatch(value)):
        raise Denied("GITHUB_RELEASE_LABEL_INVALID")
    if removable and value == STICKY:
        raise Denied("GITHUB_RELEASE_REVIEW_FLAG_OWNER_ONLY")
    return value


def checked_names(names, *, managed_only=False, nonempty=False, limit=MAX_LABELS):
    if type(names) is not list or len(names)>limit or (nonempty and not names):
        raise Denied("GITHUB_LABEL_LIST_INVALID")
    result=set()
    for value in names:
        if type(value) is not str or len(value)>50 or LABEL_NAME.fullmatch(value) is None:
            raise Denied("GITHUB_LABEL_NAME_INVALID")
        if managed_only:managed(value)
        if value in result:
            raise Denied("GITHUB_LABEL_DUPLICATE")
        result.add(value)
    return sorted(result)


def names_hash(names):
    return hashlib.sha256(canonical(checked_names(names)).encode()).hexdigest()


def label_definition(name):
    managed(name)
    if name.startswith("build:"):
        return {"name":name,"color":"1d76db",
                "description":"Fortis: release planning target, not deployment proof"}
    if name==STICKY:
        return {"name":name,"color":"b60205",
                "description":"Fortis: owner review required; never auto-clear"}
    if name=="release:no-deployment":
        return {"name":name,"color":"0e8a16",
                "description":"Fortis: validated PR requires no runtime deployment"}
    return {"name":name,"color":"fbca04",
            "description":"Fortis: planned release action, not installed state"}
