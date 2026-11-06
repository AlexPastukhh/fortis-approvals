"""SonarCloud-specific typed operations and request validation.

The shared Repo envelope/broker owns authentication and transport; this module
owns only Sonar operation names and parameter shapes.
"""
import re

from ...core import Denied

from .analysis_contract import READS, ACTIONS, READ_NAMES, ACTION_NAMES, validate_read, validate_action

SONAR_ACTION_OPERATIONS = frozenset({("sonarcloud", "accept_issue")})
SONAR_READ_OPERATIONS = frozenset({
    ("sonarcloud", "list_projects"),
    ("sonarcloud", "list_issues"),
    ("sonarcloud", "get_issue"),
    ("sonarcloud", "get_quality_gate"),
})
LEGACY_READ_OPERATIONS = SONAR_READ_OPERATIONS
SONAR_READ_OPERATIONS = SONAR_READ_OPERATIONS | READS
SONAR_ACTION_OPERATIONS = SONAR_ACTION_OPERATIONS | ACTIONS
SONAR_PROJECT_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


def validate_sonar_action(operation, target, params):
    if operation in ACTION_NAMES or operation == "accept_issue" and "comment" in params:
        return validate_action(operation, target, params)
    if operation != "accept_issue":
        raise Denied("REPO_OPERATION_NOT_SUPPORTED")
    if (set(params) != {"projectKey"} or
            type(params["projectKey"]) is not str or
            not SONAR_PROJECT_KEY.fullmatch(params["projectKey"])):
        raise Denied("REPO_SONAR_PARAMS_DENIED")
    if not SONAR_PROJECT_KEY.fullmatch(target):
        raise Denied("REPO_TARGET_DENIED")
    return params


def validate_sonar_read(operation, target, params):
    if operation in READ_NAMES:
        return validate_read(operation, target, params)
    if operation not in {name for service, name in SONAR_READ_OPERATIONS}:
        raise Denied("REPO_OPERATION_NOT_SUPPORTED")
    if not SONAR_PROJECT_KEY.fullmatch(target):
        raise Denied("REPO_TARGET_DENIED")
    if operation in ("list_projects", "list_issues"):
        if (set(params) != {"page", "pageSize"} or
                type(params["page"]) is not int or
                not 1 <= params["page"] <= 10000 or
                type(params["pageSize"]) is not int or
                not 1 <= params["pageSize"] <= 100):
            raise Denied("REPO_SONAR_READ_PARAMS_DENIED")
    elif operation == "get_issue":
        if (set(params) != {"projectKey"} or
                type(params["projectKey"]) is not str or
                not SONAR_PROJECT_KEY.fullmatch(params["projectKey"])):
            raise Denied("REPO_SONAR_READ_PARAMS_DENIED")
    elif params:
        raise Denied("REPO_SONAR_READ_PARAMS_DENIED")
    return params
