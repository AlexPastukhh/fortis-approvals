# Primary Fortis Gateway — operator procedure

**Operational entrypoint:** for a repeatable Gateway release use
[UC-GW-005](use-cases/releases.md#uc-gw-005) and
[Lightweight owner release path](#lightweight-owner-release-path-pr4b);
for recovery use [UC-GW-006](use-cases/recovery.md#uc-gw-006).
The dated incidents and old host IDs below are **historical evidence**, not
current deployment state or command templates. Obtain current image, record,
workers, capabilities and credentials from live owner/Repo readback before any
action. Owner-only PowerShell 5.1 Check/Apply/Backup/Promote and separate
quiescence attestations remain mandatory. This runbook does not activate or
prove any source candidate. A merged controller fix is source-only and is
not Windows/Production installation; it needs separate owner-controlled
Windows synchronization, parse/SelfTest and guarded acceptance.

## Action Core READ / Docker network migration — separate opt-in gate

The opt-in Action Core HTTPS/443 release introduces an additional **owner-only**
network admission gate. The existing Manage-Integrations.ps1 supports
-EnableActionCoreNetwork for checked Check/Apply only: it pins exact Docker
network identities, requires a verified Docker backend outbound TCP/8000 block,
and checks both legacy HTTP bypasses from the staged Gateway before activation.
The original bridge source and protected Return remain supported. Neither
this text nor a source merge changes Windows Firewall, Docker networks,
Gateway runtime or PostgreSQL. Follow
[ACTION-CORE-NETWORK-ISOLATION.md](ACTION-CORE-NETWORK-ISOLATION.md)
and UC-GW-009/012; production activation remains STOP until owner-run
preflight, source CI, isolated restore and negative/positive live probes.


## Исторический actor-scoped incident read и owner closure (релиз 2026-11-09)

In that **historical 2026-11-09 release**, owner-reported
`FORTIS_PRIMARY_PROMOTED` and `FORTIS_PRIMARY_VERIFIED` confirmed
source `a200137775eb6c6b8dcec81f31206b0d481d9003` as Primary **then**;
Repo machine `details()` for all six historical UUIDs was
verified over the live authenticated endpoint. The single-click owner
closure has source/TLS/WebAuthn tests, but this dated readback is not a
separate owner-browser click acceptance.

After release the authenticated Repo machine TLS client can call:

```python
from fortis_approvals.workflow.client import default_client
client=default_client()
full=client.details('2df32a24-efb1-4dac-97f6-3b66147d8944')
# full['request'], full['events'], full['worker'], full['receipt']
# For paginated events: client.details(uuid, event_offset=100, event_limit=100)
```

This is `POST /v1/workspace/details` with a UUID and event pagination.
**At the 2026-11-09 release it was actor-scoped; this statement is historical.**
After the 2026-11-10 PR #62 release, the same authenticated machine API
reads requests of **any actor**. It returns the complete Core owner-equivalent
request including payload, preview, fingerprint, decision, owner, timestamps,
result and failure; plus audit events, worker state/result/error and durable
receipts if present. A worker claim token and owner session are never included.
This is **read only**: it never submits, replays, finishes or reconciles.

AI investigation must separately compare upstream GitHub branches/SHA,
local Git worktrees and the Repo worker journal. Absence of a receipt
does not prove absence of a remote effect.

In the Owner Portal incident tab, `Закрыть заявку` now directly records
`UNCERTAIN -> CLOSED_UNCONFIRMED` after the normal owner WebAuthn login
and CSRF check. There is no second WebAuthn ceremony, backup name,
explanation or terminal-FAILED worker prerequisite. It is an
administrative dismissal: it **does not assert EXECUTED or NOT_EXECUTED**,
does not retry, and preserves original request, result, failure, worker
job and immutable audit. The owner and closure mode are recorded.

If a `CLAIMED` worker job survives administrative closure, subsequent
backup and release still preserve it by the explicitly approved UUID
and a verified closure audit; no silent state change. Existing operator
quiescence attestation for claim carryover remains necessary.


## Защищённый перенос нескольких APPROVED — установлен 2026-11-10

**Цель:** обновлять Gateway, сохраняя явно рассмотренные владельцем
`APPROVED` без удаления/исполнения; затем отменять их через Owner Portal.

**Live acceptance PR #62:** merged `main`
`8403c63297f78e38294899c6bd094cc9f9eac66f`, owner
`Check READY → FORTIS_INTEGRATIONS_ACTIVATED → FORTIS_PRIMARY_BACKUP_PASS
→ FORTIS_PRIMARY_PROMOTED`, owner `docker inspect` healthy/`unless-stopped`
на `127.0.0.1:19203/19204`. Image
`sha256:cdd7c22308d9e5820545f9ead2f71c3543c29b6f4ee7886d3b1b6cbc8f24d66c`;
record `31bdca259de84757a2a0f164a9e494bd/record.json`,
backup `fortis-gateway-backup-b7d972135c774928bbedd19975072df7`
(полные host пути — в [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)).
Repo live `globalRequestInventory.crossActorDetails=true`,
две `APPROVED` прочитаны с полным audit; никакой отмены не произошло.
Следующие releases не должны повторять эту одноразовую процедуру
по старым SHA/record без нового review.

Точно названный владельцем список `APPROVED` передаётся в существующий
параметр `-PreserveApprovedRequest` как **строка из UUID через запятую**
(старый одиночный UUID остаётся допустим). Для ручного исключения **не копировать исторические UUID** в новый релиз:
владелец должен заново получить полный актуальный список защищённых
`APPROVED/CLAIMED/UNCERTAIN` и применить точные параметры по
[UC-GW-005](use-cases/releases.md#uc-gw-005). Приведённые выше UUID и
receipt 2026-11-10 сохраняются только как датированное свидетельство.

**Безопасность и стоп-условия:** это не список на исполнение или авто-ASK.
`Check/Apply` требует точный `main` SHA, owner review и независимое
подтверждение отсутствия активного старого worker. Каждый текущий APPROVED
обязательно входит в список (максимум 20; никаких подстановок или
дубликатов), список должен в точности совпасть. Для каждого проверяется
Core result/failure=null, audit без DISPATCHED, отсутствие нативного job,
GitHub/Sonar receipt и корректная связка request. Любой PENDING/DISPATCHED,
неизвестный UUID, race, отсутствующая проверка, активное исполнение
или изменение набора во время preflight — STOP.

`Check` печатает `SOURCE_STATE_PREFLIGHT_READ_ONLY` и
`FORTIS_APPROVED_SCOPE_FORWARD_VERIFIED`. Дальше `Apply` делает
строгий приём источника, побайтовый clone, повторную сверку источника,
release smoke, стадию/активацию; существующие SQLite и audit не
переписываются. `Backup/Promote` наследуют точную изначальную область,
допускают уменьшение APPROVED после отмены владельцем и сохраняют
неопределённые CLAIMED, но требуют новой quiescence attestation.

**После owner release:** владелец через Owner Portal может выполнить
`APPROVED → CANCELLED_BEFORE_DISPATCH`, каждый раз с fingerprint,
Core writer-lock и проверками отсутствия dispatch/job/receipt. Это
отмена, а не физическое удаление записи и не повтор старого UUID.
При подтверждённой live capability глобальная инвентаризация доступна:
AI с действующей machine TLS/grant-аутентификацией видит список по всем
инициаторам через `WorkflowClient.list_requests()` и полную
read-only карточку любого UUID через `WorkflowClient.details(uuid)`.
`unresolved_only=True` возвращает также `PENDING`: это **не**
«Требуют разбора». Точный состав Owner Portal:
`APPROVED/DISPATCHED/UNCERTAIN`, см. [UC-GW-009](use-cases/incidents.md#uc-gw-009).
Ответ `details` включает request/preview/audit/worker/receipt,
но исключает machine credential, owner session/WebAuthn и worker claim
token. Чужие `status/result/reconcile/claim/finish` не расширены.
Глобальный live readback подтверждён для двух `APPROVED`; отдельный
live сценарий под второй machine identity ещё не проведён.

**Историческая граница принятия:** исходный PR и Windows image 2026-11-10 приняты
владельцем как описано выше; это **не** доказательство живого owner
browser click «Отменить до выполнения»/«Автопроверка результата»,
cross-actor live теста под вторым grant или autostart после reboot.
Для каждого будущего source SHA снова нужны owner admission,
`Check → Apply → Backup → Promote` и readback; не копировать прежние
release аргументы без актуального списка pending/approved/claimed.

## Исторические UNCERTAIN / CLAIMED — защищённый перенос (действующий механизм)

Совместимый установленный контроллер умеет переносить точный владелец-подтверждённый
список `UNCERTAIN` через `-PreserveUncertainRequests`. Единственная
сохранённая историческая `CLAIMED`-операция
`2df32a24-efb1-4dac-97f6-3b66147d8944` относится к
`workspace.create_task feed_and_search_and_bank_and_brain`. Её worker
record остаётся `CLAIMED`, а отсутствие Repo receipt не означает доказанного
отсутствия эффекта. Не закрывать её автоматически и не переписывать SQLite.

**Для новых штатных релизов — упрощённый `Check -Auto → Apply -Auto`**
с отдельными owner GO, Backup, Promote и независимой quiescence-проверкой
по [действующему runbook](#lightweight-owner-release-path-pr4b).
Приведённый здесь ручной `Check -Build` с точными
`-PreserveUncertainRequests` / `-PreserveClaimedJobs` остаётся
**исключением**, когда `-Auto` недопустим. Появление новых
`UNCERTAIN` в совместимой установленной версии допускается только через
[проверяемый механизм](UNCERTAIN-GROWTH-RELEASE-2026-11-17.md),
не через отключение целостности состояния.
Независимое доказательство отсутствия активной работы обязательно:
`-ConfirmWorkerQuiescent` само по себе не является доказательством.
`Backup` и `Promote` наследуют protected scope и требуют новой аттестации
`-ConfirmWorkerQuiescent`. Не запускать повторный `Apply` или чистку worker
после неоднозначного результата.

После административного `UNCERTAIN → CLOSED_UNCONFIRMED` активный список
`UNCERTAIN` для нового релиза может уменьшиться; сохранённый `CLAIMED`
разрешается переносить **только с прежним точным UUID и проверенным
аудитом закрытия**. Это не исполнение и не terminalization worker job.
`Закрыть заявку` не требует ни backup-имени, ни повторного WebAuthn,
ни terminal `FAILED`; по-прежнему запрещено имитировать receipt.
Для обычного расследования, чтения и действий владельца выбирать
[UC-GW-009](use-cases/incidents.md#uc-gw-009), а не повторять
исторический release.


The initial Backup/Promote, Docker Desktop restart and Legacy retirement were
owner-confirmed on 2026-11-07 in
[dated cutover evidence](../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md).
Later image releases replaced that initial Primary; its container/image IDs are
not today's deployment pins. [Current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
owns the latest confirmed runtime/source record. Before any operation, resolve
exact IDs, configuration and state through protected controller records and
live readback. Keep provider credentials, owner state and referenced rollback
artifacts. Normal ports remain 19203/19204; retained Legacy is not a fallback.

## Architecture and roles

- ONE Primary Gateway process handles authenticated Approvals, SonarCloud,
  GitHub/native worktree and installed extension operations. Not a generic proxy:
  only installed typed operations/grants/policies are available.
- `fortis-repo-test` remains a separate authorized machine client / local
  native-worktree worker. GitHub Actions run on GitHub, not in another Gateway.
- Only Primary receives normal Repo work. Legacy may stay stopped without losing
  the retained rollback state; it is not a replacement for GitHub/native recovery.
- Primary defaults to machine port `19204`, owner portal `19203`. No automatic
  fallback to legacy `19104` and no bypass through provider tokens/helpers.

## One-time operator adoption (Windows PowerShell 5.1)

**Historical completed adoption.** The sequence below explains the original
promotion and its contract; do not rerun it merely to update documentation or
copy its old runtime pins. Normal image releases use the next section.

1. Accept source changes through Gateway PR/CI/owner-approved merge and get the
   approved merged `main` into the clean Windows clone by the Mirror procedure.
   Check file hashes, exact source SHA and PowerShell parse before executing.
2. Ensure the *existing* accepted Gateway is healthy, protected `current.json`
   points to a Complete release, no undecided active request, no conflicting
   writer, and `fortis-gateway` is not already owned by an unrelated container.
3. In the accepted Windows clone, run:

   ```powershell
   $dir = Join-Path $HOME 'Repos\fortis-approvals\fortis_approvals\deploy'
   $manager = Join-Path $dir 'Manage-Integrations.ps1'
   $errors = $null; $tokens = $null
   foreach ($script in @($manager,(Join-Path $dir 'Primary-Gateway.ps1'),
                         (Join-Path $dir 'Provider-Credentials.ps1'))) {
       [void][Management.Automation.Language.Parser]::ParseFile($script,[ref]$tokens,[ref]$errors)
       if ($errors.Count) { throw "POWERSHELL_PARSE_FAILED: $script" }
   }
   & $manager -Action SelfTest
   & $manager -Action Backup
   & $manager -Action Promote
   ```

   `Backup` stops only the pinned candidate briefly, creates a new named-volume
   copy and compares complete native/GitHub/Sonar/Owner state receipts, stores a
   protected receipt under `%LOCALAPPDATA%\Fortis\GatewayReleases`, then starts
   the same container and checks health. It never copies credentials into Repo.
   The backup is a local Docker recovery copy, not an off-machine disaster backup.
   `Promote` requires that protected verified backup; changes only container
   name to `fortis-gateway` and restart to `unless-stopped`, then writes
   **separate** `primary.json` without altering the old release record.
4. Check Docker identity, image, read-only secret mounts and policy:

   ```powershell
   docker inspect fortis-gateway --format '{{.Id}} | {{.Name}} | {{.State.Health.Status}} | {{.HostConfig.RestartPolicy.Name}}'
   docker ps --filter 'name=^/fortis-gateway$' --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
   ```

   Expected same pinned ID/image/state/ports, `healthy`, `unless-stopped`.
   **STOP** for any discrepancy; no manual editing protected records.

## Audited UNCERTAIN growth — shared controller contract

[One technical contract](UNCERTAIN-GROWTH-RELEASE-2026-11-17.md)
defines the shared helper for standard Auto and manual checked releases.
Installed behavior is admitted by the exact Windows controller source,
SelfTest and protected records; source merge or CI alone is not installation.

## P3.4 — source-only owner publisher volume mount (not activated)

The [separate protected opt-in design](P3-4-PUBLISHER-GATEWAY-MOUNT-RELEASE.md)
introduces only a FIXED named Docker volume, readonly mounted at
/run/r7-publisher-activation. It requires an owner-provisioned two-file
identity with UID 10001 and modes 0700/0600 and a byte-bound offline
fingerprint stored only in protected release records. The first activation
must use manual SHA-pinned Check -Build and bound Apply with
-EnablePublisherMount and independently attested quiescence. -Auto must
fail closed on first opt-in. An already installed identity may be preserved
by later -Auto releases only with its original volume and material digest.
A source merge does not provision the volume, run Docker or enable Publisher.
Maintain UC-GW-005 protected UNCERTAIN/CLAIMED scope and host readback.

## Release Labels image/runtime boundary

The [Release Labels contract](use-cases/integrations.md#uc-gw-011)
owns closed operation names, policy, and per-operation live acceptance.
Server-side changes require the regular exact image-baked Gateway release
under [UC-GW-005](use-cases/releases.md#uc-gw-005), not just a Docker source
fast-forward. Check current capabilities and effective policy; an earlier
successful pilot does not authorize new operations, automatic publisher
startup, GitHub Projects, or an unreviewed release. Do not copy a dated
Release Labels rollout as a second deployment procedure.

## Exact visual-media receipt SHA256 keys in bounded release records

`github_pilot_helpers.inspect_state` returns `sha256` keyed by relative file
paths. The canonical visual media file is named
`native-git/visual-media/<UUID>-<index>-<64-hex-sha>.png`, **131 characters**.
The original Windows bounded serializer allowed at most 128 characters for
*every* PSCustomObject property, causing `RELEASE_RECORD_JSON_INVALID_PROPERTY`
when a release `sourceReceipt.sha256` contained such a file. This explains the
observed after-stop Save failure if that visual file was present; independently
confirm the incident's actual long-key inventory before treating the match as
forensic proof.

The hardened serializer now allows exactly the canonical 131-character PNG
file hash key in **only** `root.sourceReceipt.sha256`. All other dictionary and
PSCustomObject fields keep the <=128 character key constraint. The release
record still forbids arbitrary PSCustomObject members (`NoteProperty` only),
excessive objects, unexpected value types, depth, size, and work budgets.
Windows PowerShell 5.1 SelfTest requires positive roundtrip and protected-
temporary-file persistence of the long key, and negative rejection in the
wrong field or with a forged extension. This complements the fail-closed
pre-stop proof added in PR #83; neither authorizes Apply or manually modifies
the protected old `Returned` attempt. Owner must check the exact merged source,
independent Windows tests, fresh Check/image, and separate GO before deployment.

## Source receipt serializability gate before Docker stop (source-only safety repair)

A 2026-11-13 pinned owner Apply with image and Check record verified
successfully reached `ATTEMPT_POINTER_SAVED` and stopped the old source, but
the FIRST bounded record serialization containing the actual `sourceReceipt`
failed with `RELEASE_RECORD_JSON_INVALID_PROPERTY`. Its error-record Save and
Return's record Save then failed. The owner independently verified the original
Gateway physically `running/healthy`, old `current.phase=Complete`, and
`attempt.phase=Prepared` (`42873eb790a04861a1b9b977bb9dbab8`, no on-disk
receipt, not activated). That is incomplete durable recovery, NOT a new release
and NOT an accepted `Returned` record. Do not retry Apply/Return or manually
edit protected records/pointers/volumes; keep the old healthy Gateway alive.

The safe source guard now captures the **actual** pre-stop state-helper receipt
and executes the same bounded release-record serializer against the fully
prepared release DTO, *before* even saving Prepared or writing `attempt.json`.
The original in-memory `sourceReceipt` is restored in `finally`, including
when an unsupported member fails closed. Windows PowerShell 5.1 SelfTest also
checks realistic nested JSON-decoded receipt shape and negative ScriptProperty
injection: it must reject arbitrary adapted members without evaluating them.
This prevents this class of post-stop serialization failure from first being
discovered after source stop. It does **not** establish the exact offending
property of the owner incident, guarantee no post-stop race, or authorize
another release. That earlier `Prepared` attempt is historical: the owner preflight on
2026-11-14 read the prior attempt as `Complete`. Do not retry or reuse its
record as authorization; every new release still needs a fresh Check binding
and separate explicit Apply GO.

## 2026-11-14: oversized per-file source receipt hash map

The owner Apply for PR4b reached `SOURCE_RECEIPT_SERIALIZATION_PREFLIGHT` and
failed with `RELEASE_RECORD_JSON_OBJECT_TOO_LARGE`. It failed before
`PREPARED_RECORD_SAVED`, publication of `attempt.json`, and `STOP_SOURCE`;
this attempt did not stop the previous Gateway. The failed output did not
include the offending object's count or scope, so the exact count is not
claimed here.

Code inspection identifies `root.sourceReceipt.sha256` as the legitimate
variable-sized object: State-Helper returns one path-to-SHA256 entry per
retained state file, including native artifact bundles and optional
visual-media. The generic 256-property cap was also applied to this map.
The controller source repair raises the limit to 8,192 **only** at this exact
scope; all other objects remain capped at 256. It reports the hash-map
count and, on a cap failure, only scope, count and limit. Existing depth,
node, character, string and 1 MiB serialized-output budgets remain unchanged.
Windows PowerShell 5.1 SelfTest round-trips and atomically persists a
300-entry hash map, while still rejecting an unrelated 257-property
summary. This source repair does not authorize deployment: accept the source,
verify exact Windows SHA and SelfTest, run a fresh Check, then require a
separate owner Apply GO.

## Checked-image attempt pointer ordering (controller source repair)

The protected Check binding includes the SHA256 of the **previous**
`attempt.json` pointer, along with current/primary/backup hashes, source
identity, public config/probes, scope and immutable checked image. A new
Apply must validate that complete binding **before** writing its own
`attempt.json`, or it would invalidate the binding itself. The controller
must persist the new attempt pointer after the final pre-stop Check binding
verification and **before** the first `docker stop` effect. After the stop,
compare the frozen source state receipt separately before cloning.

An older Apply that prints `RELEASE_CHECKED_IMAGE_BINDING_CHANGED` after
`ATTEMPT_POINTER_SAVED` must **not** be retried, and neither protected
record nor pointer may be edited to bypass the check. Inspect the original
attempt record, `current.json`, `attempt.json` and healthy original Gateway
read-only. Source fix requires reviewed PR, Windows Mirror Pull, Windows
PowerShell 5.1 SelfTest and a **new** source-SHA-bound Check artifact before
a separately authorized owner-controlled Apply. An untested restore remains
an explicitly accepted risk, never proof that restoration is available.

## Checked image: one build, exact image reuse (manual pinned path)

The controller supports an owner-protected Check artifact to avoid
building the same mutable source tag twice. This manual path is separate
from normal `-Auto`; always verify current Windows source and host evidence,
not an earlier release's image or record.

After owner approval of a coordinated window and recovery readiness, the owner
runs SelfTest, then one Check -Build -SourceSha <merged-sha> with -Config,
-Probes and the exact reviewed preservation/owner-quiescence scopes.
The READY report contains checkedImageId (full sha256 image ID) and
checkedImageRecord (an owner-protected record path). Record those values in
owner-local evidence, not the private record payload.

Run Apply -Image <checkedImageId> -CheckedImageRecord <checkedImageRecord>
-SourceSha <merged-sha> with the SAME config, probes, scopes, owner quiescence,
vault and opt-in flags. DO NOT use -Build on this Apply.
The controller checks the immutable image ID and revision label, Windows clean
main SHA, source/current/primary protected records, configuration and probe
hashes, configuration digest, full source-state SHA256 receipt, exact scope and
quiescence flags, and owner shell/dynamic/CI opt-ins, including again immediately
before STOP_SOURCE and once more on the frozen source receipt after the previous
writer stops but before CLONE_STATE. A late mismatch enters guarded return.
Missing credentials or any source drift is STOP, not a
prompt to silently replace an unrecognized credential or re-run the build.

The previous live runtime image itself MUST still be inspectable by exact ID
before STOP_SOURCE. A retained running container is not sufficient. A present
image is a necessary precondition, NOT proof of isolated restore or DR. If the
old image is missing: RELEASE_PREVIOUS_IMAGE_MISSING and STOP. Do not stop the
Gateway, fabricate a matching image/tag/record or auto-export a live container.
The corrected controller enforces this on ordinary Check -Build too, before
issuing READY. A READY from the older controller does NOT make an image-missing
Apply safe. For an explicitly owner-accepted emergency see
[UC-GW-013](use-cases/recovery.md#uc-gw-013): a verified rescue image may
run only the two offline source mount-digest preflights; the original
container/image/protected record identity remains mandatory.
The controller source change requires owner PowerShell 5.1 SelfTest and a
NEW exact-source Check/Apply binding; do not reuse the pre-fix P4 image-check
record. This does not restore the lost image or prove rollback. Do not perform
ordinary Backup, Promote, prune or restart while investigating.

The original Check -Build followed by Apply -Build remains a compatibility
path that builds twice, and is NOT immutable. The pinned artifact cannot
authorize an unsafe release, a new set of UNKNOWN UUIDs, or missing rollback.
After successful Apply, owner live readback, Backup and Promote remain separate
mandatory operations. For UC-GW-013 only, a missing historical image may also
block the OLD-container admission during Promote even after the NEW Gateway
has passed Backup. The narrowly guarded emergency Promote continuation in
[UC-GW-013](use-cases/recovery.md#uc-gw-013) rechecks the historical backup
record (the current `primary-backup.json` now targets the NEW candidate),
immutable previous-primary/source identity and sealed rescue image/TAR,
before rename or restart-policy mutation. It never substitutes the rescue
for the original image identity and never proves rollback. Owner Windows
5.1 SelfTest and an exact reviewed controller update are mandatory.
An uncertain attempt requires the original record and
UC-GW-006, never blind retry.

## P4 GitHub Deployments READ — first-activation reference (already live)

**Current-state note (2026-11-20; not a new release instruction):** the owner
reported that the P4 `Check/Apply/Backup/Promote` cycle was completed. An
independent authenticated Repo → Gateway capability readback confirms
`githubDeploymentReads.enabled=true`, `repositories=["fortis-approvals"]`,
exactly four typed GET operations and `writeEnabled=false`;
`installedStateProof=false` means this API is **not** technical evidence of a
deployed source/image. The current Windows host, image identity, controller
records and recovery path were not independently inspected for this docs edit.
P4 READ is **not** awaiting first activation and must **not** be released again
because of the historical checklist below. Future scope/image changes require
fresh protected owner admission and the ordinary UC-GW-005/006 gates.

The following first-activation procedure and safeguards are retained as
historical operational reference, not as outstanding tasks for P4.

The accepted P4 source exposes only four typed GitHub Deployments GET operations
and the per-repository githubDeploymentReads capability. Owner activation is a
**separate, manually checked Windows release**, not a GitHub PR merge, token
rotation, unattended CD, ordinary -Auto release, or reuse of the P3.4
Publisher pilot.

The protected owner controller accepts -CdReadRepositories as a strict,
comma-separated **exact repository list**, maximum ten, with no duplicate,
case-insensitive aliases or path syntax. Its default is empty. A *new* nonempty
scope is allowed **only** in explicit -Action Check -Build -SourceSha (exact SHA)
and corresponding -Action Apply -CheckedImageRecord (protected original check)
-Image (exact checked image) -SourceSha (same exact SHA), with
-ConfirmWorkerQuiescent and the identical -CdReadRepositories at both phases.
Use the controller's existing full manual owner release contract to supply
all other required current protected inputs, and take the owner GO decisions
separately. These phrases are constraints, not a ready-to-execute command
template; never copy an earlier image ID, state receipt or UUID. -Auto
**rejects** this new input; Backup/Promote reject it too.

The checked-image record includes the exact requested list. The resulting
protected release record must contain runtime.cdReadRepositories and the
controller must regenerate FORTIS_GITHUB_CD_READ_REPOSITORIES from that
protected value, discarding unreviewed inherited env. The offline state
helper requires exact Docker environment equality; a missing, extra, duplicate
or reordered list is STOP. Legacy records without the field are admitted as
empty, not as newly granted access. Later ordinary -Auto releases may only
carry an *already reviewed* scope from a protected Complete source record.

**Historical first-activation acceptance checklist:** before the completed
P4 release, the required gates were source PR/CI, owner Windows 5.1 SelfTest,
protected exact-SHA Check/Apply, unchanged historical UNCERTAIN/CLAIMED
receipts, separate independent worker quiescence, Gateway capability readback
and both positive/negative typed REST GET evidence. These are not new pending
P4 steps; the owner's completion report and the confirmed live READ capability
are not substitutes for independently reopening historical protected receipts.
The owner must independently verify GitHub Deployments READ token permission
without adding WRITE. Test disallowed repository, other machine actor and
absent Deployments POST. GitHub statuses are projection evidence only and
**never** prove installed state. After accepted readback, the normal fresh
owner approvals for Backup / Promote apply; on uncertainty, use original
attempt/UC-GW-006 rather than retrying effects. No step here authorizes P5-P8.

<a id="lightweight-owner-release-path-pr4b"></a>

## Lightweight owner release path (installed owner -Auto workflow)

**For each future owner release, after PR merge and Windows `main` verified at the
exact GitHub SHA**, use the protected `Manage-Integrations.ps1` controller,
not a second coordinator or new trust boundary. Run in **interactive owner
Windows PowerShell 5.1**, never by an AI through a remote shell:

```powershell
$manager = Join-Path $HOME 'Repos\fortis-approvals\fortis_approvals\deploy\Manage-Integrations.ps1'
& $manager -Action SelfTest
# Require FORTIS_RELEASE_BOUNDED_JSON_SELFTEST_PASS and FORTIS_INTEGRATIONS_SELFTEST_PASS.
& $manager -Action Check -Auto
# Review exact source SHA, read-only scope count, READY and checked-image ID.
# Only after owner approves this exact release window:
& $manager -Action Apply -Auto
# After activation and accepted owner/machine readback:
& $manager -Action Backup -Auto
& $manager -Action Promote -Auto
```

Do not proceed to Check unless SelfTest finishes successfully. The
`FORTIS_RELEASE_JSON_OBJECT_LIMIT scope= count=257 limit=256` line is an
intentional negative serializer fixture, not a failure by itself. An actual
`VariableIsUndefined` error on `RecordPath`/`R`, or any incomplete SelfTest,
is a hard STOP: update the Windows controller from reviewed accepted source;
never patch local protected scripts in place or disable StrictMode.

For older Primary records, `gatewayNetworks` and the optional
`providers.action_core` may be absent. The current owner SelfTest validates
those absent fields under PowerShell 5.1 StrictMode; require
`FORTIS_ACTION_CORE_OPTIONAL_FIELDS_SELFTEST_PASS` before `Check -Auto`.
It must never invent network identities or activate the separate
`-EnableActionCoreNetwork` opt-in. If the field is present but malformed,
the controller must STOP. If Check fails after `BUILD_IMAGE` with a
`PropertyNotFoundStrict` message, do not run Apply or blindly retry Check:
review the controller version and protected release evidence first.

This mode **does not deploy automatically**. Check builds once and writes the
same protected, immutable checked-image binding used by manual Check. Auto
Apply selects only its protected `auto-check.json` pointer, revalidates exact
clean Windows main vs typed GitHub `main`, source SHA, config/probe hashes,
owner records, current state receipt, and previous image retention. No
second Docker build, remote script download, PAT, ad hoc config file or manual
UUID string is required. The public config and probes are recovered only
from the protected **current** Complete release record. Missing or invalid
prior values are `STOP`, never replaced with a guessed template.

**Before STOP_SOURCE:** verify that mandatory external upstreams for
staged release probes are available in the intended network/identity scope.
The owner-local [Mirror Gateway READ HTTPS listener](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/GATEWAY-READ-ONLY.md)
is a separate foreground Windows process from Browser Mirror: a healthy
Browser UI does not prove HTTPS/443 is running.
`Check READY` does **not** prove external upstream reachability or bearer
authorization. Mandatory staged probes run **after the source Gateway is stopped**.
Prefer passive listener/TLS checks that do not submit a new Core request
after the sealed Check; absent mandatory upstream readiness is STOP.
Never bypass probes or blindly retry failed Apply:
[UC-GW-006](use-cases/recovery.md#uc-gw-006) owns the original attempt.

The Repo machine grant performs **read-only** global request/worker activity
inventory. `PENDING`, `DISPATCHED` or any live `APPROVED` demand STOP/owner
review; full and bounded pagination is mandatory. The compatible installed
controller's Auto Check seals the original `UNCERTAIN/CLAIMED` scope and an
offline SQL/audit witness. Auto Apply uses
the **original sealed scope**, not the latest Repo READ list, and the same
read-only verifier admits only [bounded new UNCERTAIN entries](UNCERTAIN-GROWTH-RELEASE-2026-11-17.md).
The final ID list is frozen after stopping the original Gateway. Older
Check records without a witness require a fresh Check. Existing
`CLAIMED` worker is never resumed/closed. The owner must **independently**
verify quiescence and type `QUIESCENT` again at each phase. Applying requires
separate explicit `APPLY`, Backup and Promote their own confirmation. Failed
or ambiguous Apply is handled via protected attempt record and Return/UC-GW-006,
not retry of `Apply -Auto`.

**Important:** record source SHA, `checkedImageId` and `checkedImageRecord`
in owner-local evidence; do not paste private records or tokens.
Strictly audited additions to `UNCERTAIN` may pass only with a valid witness.
Any other source-state drift, incomplete evidence or missing witness
still causes STOP; never bypass the checked-image binding.
Do not use `-Auto` against an older Windows source revision: owner Merge/Pull
and PowerShell SelfTest must precede this workflow. The explicit manual
controller path remains available for incident handling and exact reviewed
`APPROVED` carryovers.

## Normal releases after adoption

`Manage-Integrations.ps1 -Action Apply` retains the exact source, stages a
new image in a run-specific container (`restart=no`), performs readbacks and
writes a new protected Complete record. Following successful activation and
owner evidence, run `-Action Backup` and `-Action Promote` again. The former
Primary (now stopped) gets its historical name and `restart=no`. Do not try to
start two Gateways on the same published ports or RW state volume. Resume/Return
must continue using the original attempt record, not fabricated identifiers.

## Acceptance and retirement

1. From actual Fortis Repo client: verify Sonar Quality Gate/Issues, GitHub
   repository/branches/open PRs/Actions, live capabilities and TLS machine grant.
2. Verify Owner Portal/WebAuthn on 19203; preserve ALLOW/ASK/DENY restrictions.
3. Confirm no normal client uses Legacy 19104. Set only its restart policy to
   `no`, stop only its exact ID; do not delete image, state or credential volumes.
   Updating Legacy's old Compose service can reconfigure it: don't `compose up`
   that project during normal operation.
4. During an agreed maintenance window restart Docker Desktop and confirm
   `fortis-gateway` becomes healthy and Repo readbacks pass without manual start.
   Docker Desktop must itself start with the user session; engine-level service
   before Windows logon is a different deployment goal.
5. Record verified host output, final release pointer, retained recovery volume
   and limits for the new release. Do not overwrite the initial cutover evidence
   or present an old acceptance result as a fresh check.
   The reported owner host output and Repo readback confirm deployment; a fresh
   full ALLOW/ASK/DENY policy acceptance cycle is still outstanding.

## STOP and rollback boundaries

Mismatched source image/record, unexpected writer, insecure mount/ACL, missing
backup, owner credential mismatch, pending or uncertain effect, unhealthy
Gateway, parse failure or any Docker rename ambiguity means STOP. The controller
attempts bounded name/policy rollback only on exact IDs and reports
`PRIMARY_PROMOTION_RECOVERY_REQUIRED` if reconciliation is necessary.
Rolling back an installed image never undoes already published GitHub changes;
compare receipts and GitHub head before any state restore. Do not repoint
clients to Legacy as an automatic fallback.
