# PowerShell Executor extraction — source evidence, 2026-11-17

Status: **SOURCE CANDIDATE / BOOTSTRAP AND PUBLICATION BLOCKED**.
No standalone GitHub repository, Windows clone, process cutover or machine
PowerShell permission is established by this record.

## Reproducible source

- Source repository: AlexPastukhh/docke-windows-mirror.
- Source commit: `b25bf88d330ff8b8921469f5bf0bedbc353a7861`.
- Recipe: `scripts/extract-powershell-executor.py` in this task.
- Recipe SHA256: `10406fbb4fd1e0adc5b6749ec481ca15ef36d56fb6263ae65862903072d6534a`.
- The runner Git blob is copied byte-for-byte to
  `fortis_powershell_executor/owner_shell.py`.
- Launcher module and test imports/mock target are relocated.
- Packaging includes the baseline API/migration documentation, Linux/Windows
  source CI, the inherited pinned Release Impact workflow, release target
  catalog, source provenance and legacy receipt compatibility tests.
- No license was added: the original source has no root license file.
  Visibility/licensing remain owner choices during repository bootstrap.
- No .git, credentials or real receipt data are in the generated candidate.
  The recipe only reads approved tracked files and refuses dirty/wrong
  source, wrong SHA/origin, symlink inputs and an existing destination.

## Candidate archive

- Files: 15.
- Bytes: 16437.
- SHA256: `c1de976bd229d5b1c65d1d50e705c0f26769da34a2c2b2eda8b63b09ab1af1b1`.
- Directory in Fortis Repo:
  `/workspace/repo/Workfiles/_fortis_windows_transfer_tmp/powershell-executor-extraction-20261117/source-candidate`.
- Archive:
  `/workspace/repo/Workfiles/_fortis_windows_transfer_tmp/powershell-executor-extraction-20261117/powershell-executor-source-candidate.zip`.
- This is a source review/future Docker task import package, **not a Windows
  installation channel**. Production source still follows owner GitHub merge
  and Windows clone update; the archive is not permission to run a worker.
- These are reproducible temporary copies. The recipe, tests and provenance
  source are preserved in Git; this directory is not their only copy.

## Source verification

| Check | Result / limit |
| --- | --- |
| Extraction recipe tests | 11 PASS; identity, clean main, no overwrite, no unrelated private files, symlink rejection and reproducibility |
| Gateway targeted regression | 25 PASS, including the 11 extraction tests, existing owner Portal, release-source and source-manifest checks |
| Candidate worker/receipt tests | 9 PASS; HTTP/worker fixtures, existing legacy receipt reads, exact UUID conflict and retained unresolved blocking |
| Script Center suite | 94 tests, PASS with 1 pre-existing platform skip |
| Real source resolver with disposable Git clones | 8 PASS, included above: accepted standalone clone; wrong Mirror path/origin, dirty/off-main/stale/missing-upstream and .git-file rejection |
| PowerShell syntax | 3 scripts parsed with PowerShell 7.6.9 in Linux; invariant globalization required by this test runtime |
| Release target catalog | PASS through the shared validator on a disposable offline Git fixture; 1 target, 0 build units |
| Archive | Exact file inventory, SHA256 and ZipFile.testzip verified |

Linux PowerShell 7 results are **not Windows PowerShell 5.1, NTFS ACL,
installed process, mTLS handshake or owner Portal live acceptance**.
Tests use synthetic receipts and fake runners, never installed owner data
or a real PowerShell command on Windows.

## Script Center source

Task: `task/powershell-executor-extraction-20261117`,
based on `1737e4b14ecbab9726a228d71f64e1c0caf3bd08`.

The adapter now selects `%USERPROFILE%\Repos\fortis-powershell-executor`
through `Get-FortisPowerShellExecutorWindowsMain.ps1`. It preserves the
registration entry, non-admin/ACL/source-change/port checks, protected config
path and all five existing TLS/receipt fields. There is no Mirror fallback
and no Git fetch/update, process stop, credential creation or new DB setup.
This is uninstalled source; the current Windows launcher/process is untouched.

## Source delivery state

- Approvals implementation commit: `793ab4f6d994867afde7f42cc63bd928c9b2b992`.
- Script Center implementation/CI commit: `e56d95aaf6504ecb8653ded640ce8e1c95c65c15`.
- Script Center now also contains a Linux/Windows source CI candidate at
  `.github/workflows/powershell-executor-source-ci.yml`; no GitHub run is
  claimed before publication. Its Windows job qualifies the resolver and
  parses the changed PowerShell files without launching Executor.
- The external tool approval review rejected draft publication to
  `AlexPastukhh/fortis-approvals` because explicit consent for this source
  payload and external destination was missing. No draft PR or remote task
  branch was created; no alternate publication route was attempted.
- Publishing the recipe/plan/tests and the Script Center launcher/resolver/CI
  requires explicit owner permission for those two GitHub destinations.
  Windows activation is a separate later step and is not part of the draft.

## External prerequisites and runtime boundary

Fresh Gateway capabilities do not expose create_repository. The attempted
typed repository READ returned `FORTIS_HTTP_403`; this does not prove whether
the repo is absent or outside the current token scope. No alternate GitHub
client or direct network Git was used.

UC-CONT-027 needs an owner-provided HTTPS repository URL and initial main;
owner chooses visibility/license. If the repo already exists, establish its
Gateway access instead of creating a duplicate. No canonical Docker anchor,
task or Windows clone for the new repo was created without this prerequisite.

MOVE-01 host metadata, actual old process/children/quiescence, installed
TLS/config/DB preservation, source release and MOVE-07/08 Windows cutover/
rollback remain pending. Machine ASK and configurable command restrictions
are subsequent unimplemented stages. See the single backlog for status.
