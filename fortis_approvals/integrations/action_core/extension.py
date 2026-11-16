"""Typed, read-only Action Core provider; all transport is Gateway-owned."""
import re

from fortis_approvals.extensions.model import Operation, Provider, bounded, check
from fortis_approvals.integrations.action_core.tls import ActionCorePinnedAPI
from fortis_approvals.integrations.review_schema import object_schema

_CATEGORY = re.compile(r"[a-z][a-z0-9_-]{0,79}\Z")
_ALLOWED_TARGETS = frozenset({"3", "4"})
_RESULT_FIELDS = {
    "action_id",
    "name",
    "category",
    "current_version_number",
    "definition_yaml",
    "schedule_active",
}


def _no_params(value):
    object_schema({})(value)


def validate_result(value):
    """Reject unknown fields, loose Python types and oversized upstream data."""
    check(
        type(value) is dict and set(value) == _RESULT_FIELDS,
        "ACTION_CORE_RESULT_INVALID",
    )
    check(
        type(value["action_id"]) is int and value["action_id"] in (3, 4),
        "ACTION_CORE_RESULT_INVALID",
    )
    check(
        type(value["name"]) is str and 1 <= len(value["name"]) <= 200
        and all(ord(character) >= 32 for character in value["name"]),
        "ACTION_CORE_RESULT_INVALID",
    )
    check(
        type(value["category"]) is str
        and _CATEGORY.fullmatch(value["category"]) is not None,
        "ACTION_CORE_RESULT_INVALID",
    )
    check(
        type(value["current_version_number"]) is int
        and value["current_version_number"] >= 1,
        "ACTION_CORE_RESULT_INVALID",
    )
    check(
        type(value["definition_yaml"]) is str
        and 1 <= len(value["definition_yaml"]) <= 65_536,
        "ACTION_CORE_RESULT_INVALID",
    )
    check(
        type(value["schedule_active"]) is bool,
        "ACTION_CORE_RESULT_INVALID",
    )
    bounded(value, 65_536)


def read_action(ctx):
    """Read the current version of exactly one configured Action."""
    check(
        type(ctx.target) is str and ctx.target in _ALLOWED_TARGETS,
        "ACTION_CORE_TARGET_DENIED",
    )
    value = ctx.call("read_action", path={"action_id": ctx.target})
    validate_result(value)
    check(
        value["action_id"] == int(ctx.target),
        "ACTION_CORE_TARGET_RESULT_MISMATCH",
    )
    return value


PROVIDER = Provider(
    "action_core",
    (
        Operation(
            "read_action",
            "Read the current Action definition for an explicitly allowed Action ID",
            "read",
            _no_params,
            validate_result,
            read_action,
            credential="read",
            routes=("read_action",),
        ),
    ),
    api=ActionCorePinnedAPI(),
)
