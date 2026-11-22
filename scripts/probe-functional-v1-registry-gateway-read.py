#!/usr/bin/env python3
"""Owner-run E1 readback via the *existing authenticated* typed Gateway.

Read only. No DB, filesystem host probing, token output, grants or WRITE.
SUCCESS is a SOURCE_ONLY observation, NOT actual cross-UID host acceptance.
The original operation UUID + selected source SHA must be independently pinned.
The separate host cross-UID access probe is still mandatory.
"""
import argparse
import json

from fortis_approvals.core import Denied, Stale
from fortis_approvals.integrations.registry.repo_client import RegistryCandidateClient
from fortis_approvals.workflow.client import default_client


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selected-main-sha', required=True)
    parser.add_argument('--original-operation-id', required=True)
    parser.add_argument('--page-limit', type=int, default=20)
    args = parser.parse_args(argv)
    try:
        # Existing Repo grant/TLS endpoint; no caller-selected URL/credential.
        observed = RegistryCandidateClient(default_client().gateway).observe_e1_candidate(
            expected_source_sha=args.selected_main_sha,
            original_operation_id=args.original_operation_id,
            page_limit=args.page_limit)
    except (Denied, Stale) as exc:
        # Only closed error code; no raw response, auth header or token.
        print('REGISTRY_E1_GATEWAY_READ_STOP ' + str(exc))
        return 2
    except Exception:
        print('REGISTRY_E1_GATEWAY_READ_UNAVAILABLE')
        return 2
    print(json.dumps(observed, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
