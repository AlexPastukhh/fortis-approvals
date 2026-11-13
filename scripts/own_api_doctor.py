#!/usr/bin/env python3
"""Read-only first-party API diagnosis. Never deploys, provisions or submits calls.

Static checks are reusable from check-own-api-manifest.py. Optional authenticated
catalog/Core inventory reads do not prove upstream TLS, host state or quiescence.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

# Running by file path puts scripts/ (not its parent) on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

CHECKER = Path(__file__).with_name("check-own-api-manifest.py")
spec = importlib.util.spec_from_file_location("own_api_manifest_checker", CHECKER)
manifest_checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest_checker)


def catalog_rows(value, manifest):
    """Check the *exact* trusted target/policy; never infer permissions from GET."""
    if type(value) is not dict or type(value.get("operations")) is not list:
        raise ValueError("CATALOG_SCHEMA_INVALID")
    expected = {(manifest["serviceId"], row["name"], target)
                for row in manifest["operations"] for target in row["targets"]}
    rows = [r for r in value["operations"] if type(r) is dict and
            r.get("service") == manifest["serviceId"]]
    actual = {(r.get("service"), r.get("operation"), r.get("target")) for r in rows}
    ready = (actual == expected and len(rows) == len(expected) and
             all(r.get("kind") == "read" and r.get("policy") == "ALLOW" and
                 r.get("ready") is True and
                 type(r.get("credential")) is dict and
                 r["credential"].get("ready") is True
                 for r in rows))
    return {"status": "PASS" if ready else "STOP",
            "configuredOperationTargets": len(rows),
            "expectedOperationTargets": len(expected)}


def core_summary(requests, activity):
    if (type(requests) is not dict or type(requests.get("items")) is not list or
        type(activity) is not dict):
        raise ValueError("CORE_INVENTORY_SCHEMA_INVALID")
    rows = requests["items"]
    states = {}
    for item in rows:
        if type(item) is not dict or type(item.get("state")) is not str:
            raise ValueError("CORE_INVENTORY_SCHEMA_INVALID")
        state = item["state"]
        states[state] = states.get(state, 0) + 1
    if type(activity.get("claimed")) is not int or type(activity.get("queued")) is not int:
        raise ValueError("CORE_ACTIVITY_SCHEMA_INVALID")
    # The authenticated inventory is paged. Never equate a single page with
    # the global unresolved set or treat heartbeat as a quiescence proof.
    partial = requests.get("truncated") is True or activity.get("truncated") is True
    return {
        "unresolvedStatesOnPage": states,
        "requestInventoryCoverage": "PARTIAL" if partial else "COMPLETE_SNAPSHOT",
        "claimed": activity["claimed"],
        "queued": activity["queued"],
        "workerQuiescence": "OWNER_CONFIRMATION_REQUIRED",
    }


def diagnose(manifest, *, catalog=None, requests=None, activity=None):
    validated = manifest_checker.validate(manifest)
    result = {
        "status": "SOURCE_MANIFEST_VALID",
        "serviceId": validated["serviceId"],
        "transportProfile": validated["transportProfile"],
        "sourcePinned": validated["sourcePinned"],
        "manifest": "PASS",
        "catalog": {"status": "UNKNOWN"},
        "coreInventory": {"status": "NOT_CHECKED"},
        "upstreamTls": "NOT_CHECKED",
        "hostListener": "NOT_CHECKED",
        "protectedRelease": "NOT_CHECKED",
        "isolatedRestore": "NOT_CHECKED",
        "liveRead": "NOT_EXECUTED",
        "workerQuiescence": "NOT_PROVEN",
    }
    if catalog is not None:
        result["catalog"] = catalog_rows(catalog, manifest)
        result["status"] = ("CATALOG_READY_READ_NOT_TESTED"
                            if result["catalog"]["status"] == "PASS"
                            else "STOP_CATALOG_MISMATCH")
    if requests is not None or activity is not None:
        if requests is None or activity is None:
            raise ValueError("CORE_INVENTORY_INCOMPLETE")
        result["coreInventory"] = core_summary(requests, activity)
    return result


def main(argv=None, *, catalog_client=None, workflow_client=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--live-catalog", action="store_true",
                        help="Authenticated catalog READ; does NOT invoke an upstream API")
    parser.add_argument("--core-inventory", action="store_true",
                        help="Authenticated global request/activity READ; never proves quiescence")
    args = parser.parse_args(argv)
    try:
        manifest = manifest_checker.load(args.manifest)
        catalog = requests = activity = None
        if args.live_catalog:
            if catalog_client is None:
                from fortis_approvals.extensions.client import default_client
                catalog_client = default_client()
            catalog = catalog_client.catalog()
        if args.core_inventory:
            if workflow_client is None:
                from fortis_approvals.workflow.client import default_client
                workflow_client = default_client()
            requests = workflow_client.list_requests(offset=0, limit=100,
                                                       unresolved_only=True)
            activity = workflow_client.activity(offset=0, limit=100)
        report = diagnose(manifest, catalog=catalog, requests=requests, activity=activity)
        print(json.dumps(report, sort_keys=True))
        return 2 if report["status"].startswith("STOP") else 0
    except manifest_checker.ManifestStop as exc:
        print(json.dumps({"status": "STOP", "code": str(exc)}, sort_keys=True))
        return 2
    except (ValueError, TypeError):
        print('{"status":"STOP","code":"INVALID_READBACK"}')
        return 2
    except Exception:
        # Never print upstream exception, response, token, paths or private Core rows.
        print('{"status":"UNKNOWN","code":"READBACK_UNAVAILABLE"}')
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
