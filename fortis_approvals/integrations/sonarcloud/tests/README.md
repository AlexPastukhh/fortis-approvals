# SonarCloud integration tests

The detailed regression suite remains in `fortis_approvals/tests/` because it
covers shared Core, Repo ingress and the historical compatibility import paths.

Run the provider-specific suites from the repository root:

```sh
python3 -B -m unittest discover -s fortis_approvals/tests -p 'test_sonar*.py' -v
python3 -B -m unittest discover -s fortis_approvals/tests -p 'test_repo_sonar*.py' -v
python3 -B -m unittest discover -s fortis_approvals/integrations/sonarcloud/tests -p 'test_*.py' -v
```

Do not remove the root compatibility wrappers until all external callers and
the next Gateway image manifest have been migrated.
