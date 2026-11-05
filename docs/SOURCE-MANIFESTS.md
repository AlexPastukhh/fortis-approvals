# Source manifest policy

Three manifests have separate purposes:

- `SOURCE-MANIFEST.sha256` is the immutable baseline from the initial 196-file extraction. Do not rewrite it.
- `CURRENT-SOURCE-MANIFEST.sha256` records the current bytes for exactly those original baseline paths. It changes when a baseline file is edited or replaced by a compatibility shim.
- `MODULARIZED-SOURCE-MANIFEST.sha256` records the current standalone repository tree, including provider packages, GitHub scaffolding, tests and docs. It excludes itself, Git metadata, generated caches, local state and credential-like files.

After a source change, regenerate and verify the current manifests:

```sh
python scripts/update-source-manifests.py
python scripts/update-source-manifests.py --check
```

CI runs the check-only command. A stale manifest fails the workflow. Never include `.env` files, credentials, tokens, private keys, machine grants, runtime databases or generated state in a manifest.
