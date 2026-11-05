# Contributing

## Development setup

Use Python 3.11 and install the pinned runtime/test dependencies:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r fortis_approvals/requirements-owner.txt
```

## Tests

Run the supported offline security and provider regression suite:

```sh
bash scripts/test-source.sh
python -B -m compileall -q fortis_approvals
python scripts/update-source-manifests.py
python scripts/update-source-manifests.py --check
```

The GitHub Actions workflow runs the offline suite and checks that the source
manifests are current. Historical image
build/audit artifacts are preserved for provenance; they are not deployment
instructions and may depend on owner-held files outside this repository.

## Change boundaries

- Keep provider-specific schemas, transports, adapters, and Repo clients in
  their provider integration package.
- Keep machine authentication, Core policy, owner approval, and ingress in
  shared Gateway code.
- Default new operations to DENY. Never grant an actor or select ALLOW/ASK
  policy as a side effect of registering an adapter.
- Do not add arbitrary HTTP proxying, caller-selected URLs, or generic Git
  mutation endpoints.
- Never add tokens, private keys, machine grants, state files, or production
  database contents to Git.
- Do not alter live volumes, compose projects, images, or running containers
  from a source change. Deployment requires a separate owner-reviewed release.
- Add offline tests for validation, denial paths, response projections,
  idempotency, stale preconditions, and secret redaction.
