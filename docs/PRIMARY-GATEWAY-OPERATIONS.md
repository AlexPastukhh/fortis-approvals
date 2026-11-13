# Primary Fortis Gateway — operator procedure

## Исторический actor-scoped incident read и owner closure (релиз 2026-11-09)

Owner-reported `FORTIS_PRIMARY_PROMOTED` and `FORTIS_PRIMARY_VERIFIED`
confirm source `a200137775eb6c6b8dcec81f31206b0d481d9003` as the
current Primary; Repo machine `details()` for all six historical UUIDs was
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
(старый одиночный UUID остаётся допустим). Для текущего блокера:

```powershell
$approved = 'ba299f4f-f49c-4ef7-80cf-e1f31a232024,49bcd340-8d21-4a7c-906a-ea5ea56ba748'
$claimed  = '2df32a24-efb1-4dac-97f6-3b66147d8944'
# Вручную, только с owner-подтверждением quiescence и SHA нового merged main:
# & $manager -Action Check -Build -SourceSha $sha -Config $configFile `
#     -PreserveApprovedRequest $approved -PreserveClaimedJobs $claimed -ConfirmWorkerQuiescent
```

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
Глобальная инвентаризация **уже установлена**: любой AI с
действующей machine TLS/grant-аутентификацией видит список по всем
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

**Граница принятия:** исходный PR и Windows image 2026-11-10 приняты
владельцем как описано выше; это **не** доказательство живого owner
browser click «Отменить до выполнения»/«Автопроверка результата»,
cross-actor live теста под вторым grant или autostart после reboot.
Для каждого будущего source SHA снова нужны owner admission,
`Check → Apply → Backup → Promote` и readback; не копировать прежние
release аргументы без актуального списка pending/approved/claimed.

## Исторические UNCERTAIN / CLAIMED — защищённый перенос (действующий механизм)

Установленный контроллер умеет переносить точный владелец-подтверждённый
список `UNCERTAIN` через `-PreserveUncertainRequests`. Единственная
сохранённая историческая `CLAIMED`-операция
`2df32a24-efb1-4dac-97f6-3b66147d8944` относится к
`workspace.create_task feed_and_search_and_bank_and_brain`. Её worker
record остаётся `CLAIMED`, а отсутствие Repo receipt не означает доказанного
отсутствия эффекта. Не закрывать её автоматически и не переписывать SQLite.

Для **нового image release**, при его явной необходимости, использовать
штатный `Manage-Integrations.ps1`: Windows SelfTest, `Check -Build` с принятым
source SHA и полным точным списком текущих `UNCERTAIN`, `Apply` после owner GO,
затем отдельные `Backup` и `Promote`. Для наследуемого `CLAIMED` указывать
`-PreserveClaimedJobs <exact-UUID> -ConfirmWorkerQuiescent` на
`Check`/`Apply`. Заявление об отсутствии активных внешних Repo worker
процессов необходимо подтвердить независимо: сам switch это **не проверяет**.
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

## Pending Release Labels typed API release — not yet installed

The source candidate for PR label READ/ASK methods is defined in
[UC-GW-011](use-cases/integrations.md#uc-gw-011). It changes server-side
`fortis_approvals/integrations/github/*` and native policy/ingress code,
so **it requires an image-baked Primary release**, not merely a Docker
source fast-forward. Follow the existing owner-managed release procedure
below and [UC-GW-005](use-cases/releases.md#uc-gw-005), preserving active
APPROVED/CLAIMED/UNCERTAIN work and retained rollback.

Before Apply/Build, check exact owner-merged PR HEAD, source manifest,
tests, no unresolved effects, policy/read grants and token permissions
(Issues or Pull requests write); **do not print token contents**. The
label APIs must remain ASK, not blanket ALLOW. After Backup/Promote,
read `/v1/workspace/capabilities` for the exact three read and three
write method names; exercise read-only repository/PR context, wrong
actor/repo/branch rejection and owner-approved label changes on an
isolated test PR. Verify GitHub labels, Core receipts and unchanged
human labels; only then mark `LIVE_API_VERIFIED`. A denied/absent
permission or unknown effect is STOP, not retry or credential bypass.
No Projects mutations or unattended publisher are activated by
this release. Technical method schemas belong in UC-GW-011; this
runbook deliberately does not duplicate them.

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
another release. A separate reviewed incident-recovery procedure is required
for the outstanding protected `Prepared` attempt. A new owner-approved source
Check and separate explicit Apply GO are required after that recovery.


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

## Checked image: one build, exact image reuse (source pending merge/release)

The source-side controller now supports an owner-protected Check artifact to avoid
building the same mutable source tag twice. It is NOT installed until this task
PR is accepted/merged and the Windows clone is verified at that source SHA.

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

The original Check -Build followed by Apply -Build remains a compatibility
path that builds twice, and is NOT immutable. The pinned artifact cannot
authorize an unsafe release, a new set of UNKNOWN UUIDs, or missing rollback.
After successful Apply, owner live readback, Backup and Promote remain separate
mandatory operations; an uncertain attempt requires the original record and
UC-GW-006, never blind retry.

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
