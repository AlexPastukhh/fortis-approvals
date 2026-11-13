# Own API diagnosis & typed READ acceptance — source candidate

Canonical policy: UC-GW-012; source manifest rules stay in
\`scripts/check-own-api-manifest.py\`. These tools are diagnostic/acceptance
clients, not new Gateway endpoints, credential providers, deployers, or host
installers. They do not replace owner-controlled Check/Apply/Backup/Promote.

## Doctor (default: offline, no network)

From the canonical Fortis Repo environment:

    python3 -B scripts/own_api_doctor.py --manifest "$PWD/docs/templates/own-api/mirror-read.example.json"

Opt-in authenticated reads (no upstream call, no Gateway state changes):

    python3 -B scripts/own_api_doctor.py --manifest "$PWD/docs/templates/own-api/mirror-read.example.json" --live-catalog --core-inventory

\`CATALOG_READY_READ_NOT_TESTED\` is NOT live upstream acceptance.
The Doctor cannot prove Windows listener, TLS, isolated restore, exact
production container image or worker quiescence from the Repo machine alone.
An incomplete Core inventory must be labelled incomplete, never interpreted as
no unresolved requests. Avoid printing catalog raw responses or secrets.

## One-shot Acceptance

Get a new UUID and exact **configurationDigest from the protected owner
release record**, not a hard-coded old Check. Use an **absolute** intent path
inside an already existing private Workfiles directory; preserve the file
for audit and do not reuse a journal for another request.

Default without \`--submit-read\`: checks manifest, exact ALLOW/read catalog
target and digest; prints READY_FOR_ONE_SHOT_READ without submitting:

    python3 -B scripts/own_api_acceptance.py --manifest "$PWD/docs/templates/own-api/mirror-read.example.json" --operation get_repository --target fortis-approvals --request-id <new-uuid> --expected-digest <protected-digest> --journal /workspace/repo/Workfiles/<owner-folder>/mirror-read-<uuid>.json

A **separate, explicit** \`--submit-read\` performs one typed READ and
validates the returned data against trusted installed source provider schema.
The request intent is fsynced **before** calling Gateway. A second invocation
with the same journal only calls \`result(uuid,reconcile=False)\`, never
\`call()\` again, even after a network timeout or UNKNOWN.

Output contains request ID, validated operation/target/digest and bounded
result size but not response body, credentials, token or secret paths.
Request-ID journal is local Workfiles evidence, **not** the authoritative
Core receipt or protected Gateway release record.

Never claim true upstream negative tests, Windows TLS/ACL acceptance, isolated
restore or machine quiescence from these CLIs. For WRITE/ASK use a separately
reviewed contract; this implementation rejects it. As with Mirror, a
new upstream API needs a compatible packaged typed provider and its own
schema/source review before it can achieve LIVE_TYPED_READ_VERIFIED.
