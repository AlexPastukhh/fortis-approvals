# Primary Fortis Gateway — operator procedure

## Исторический CLAIMED — owner-reviewed карантин (SOURCE CANDIDATE 2026-11-09)

После PR #37 Windows Check показал шесть `UNCERTAIN` и один
не-терминальный worker job `CLAIMED` с UUID
`2df32a24-efb1-4dac-97f6-3b66147d8944`
(`workspace.create_task feed_and_search_and_bank_and_brain`).
В Repo worker journal для данного UUID нет записи; это НЕ
доказательство отсутствия Git-эффекта. `ee9c5e73-5d5a-4ea1-8133-d79d59511f32`
(`workspace.commit`) имеет worker journal `FAILED/UNCERTAIN`.
Живые данные Primary не изменены.

Новый параметр `-PreserveClaimedJobs` с `-ConfirmWorkerQuiescent`
допускает перенос **только конкретного UUID** в сочетании с
`-PreserveUncertainRequests`, `-Build` и `-SourceSha`.
Помимо статуса Core `UNCERTAIN` helper требует совпадения actor,
payload и `workspace.create_task`; любая `QUEUED`, другие
CLAIMED, несовпадение UUID или активная Core-заявка запрещены.
Базы (включая worker job) сохраняются побайтово: статус
`CLAIMED` НЕ меняется на `FAILED` либо `EXECUTED`.

**ВНИМАНИЕ:** `-ConfirmWorkerQuiescent` — *аттестация владельца*,
не автоматическое доказательство, что внешний Fortis Repo worker
остановил исполнение. До Check/Apply/Backup/Promote нужно
независимо убедиться в отсутствии активного executor, исследовать
точный task name и git worktree/journal и исключить новые операции
на период cold cutover. Не использовать флаг формально.

Только после отдельного owner-merged PR, зелёного Source CI,
нового SHA и Windows PowerShell 5.1 SelfTest:

```powershell
$claimedId = '2df32a24-efb1-4dac-97f6-3b66147d8944'
$incidentIds = @(
 '18af495b-f84c-4fd3-b613-ebd5fdfa0165'
 '35ac68df-8be5-4dae-bf20-11f75555eecc'
 '31e8f60b-f396-4e5f-8a46-7772faf95fa4'
 '7b2ea090-4408-4d9c-b1b6-be5a97eb7b36'
 '2df32a24-efb1-4dac-97f6-3b66147d8944'
 'ee9c5e73-5d5a-4ea1-8133-d79d59511f32'
) -join ','
# existing $manager, $config and $approvedSha; worker idle verified by owner
& $manager -Action Check -Build -SourceSha $approvedSha -Config $config `
  -PreserveUncertainRequests $incidentIds -PreserveClaimedJobs $claimedId `
  -ConfirmWorkerQuiescent
# Apply только после READY и отдельного owner GO:
& $manager -Action Apply -Build -SourceSha $approvedSha -Config $config `
  -PreserveUncertainRequests $incidentIds -PreserveClaimedJobs $claimedId `
  -ConfirmWorkerQuiescent
```

После успешного Apply команда `Backup`/`Promote` наследует scope из
защищённого record, но для каждой операции заново требует
`-ConfirmWorkerQuiescent`. Не передавайте `-PreserveClaimedJobs`
при Backup/Promote. Исходный `CLAIMED` останется в новой базе.
В текущем Owner Portal закрытие `UNCERTAIN` с worker job != `FAILED`
по-прежнему отвергается; требуется отдельный защищённый workflow
расследования и terminalization. Не редактируйте рабочую SQLite.

## Сохранение исторических UNCERTAIN при следующем image release (SOURCE CANDIDATE 2026-11-09)

Эта процедура существует **только в новой source-ветке**, не в установленном
Primary. Incident lifecycle подключается версионным модулем
`fortis_approvals/incidents.py`, а исходные хеши Core/WebAuthn/Owner Portal
сохраняются неизменными. Сначала необходимы owner-merged PR, зелёный CI на точном HEAD,
Windows guarded pull, `SelfTest` и корректная публичная конфигурация.
Нельзя использовать прежний `main` SHA
`d343ac00a30bfbc3de33b5184fcca9b5b4254c27`: он не содержит нового
владельческого параметра.

Из ранее показанного владельцем read-only inventory известно четыре UUID.
Перед релизом нужно повторно подтвердить их состояние и отсутствие
других новых инцидентов:

```powershell
$incidentIds = @(
    '18af495b-f84c-4fd3-b613-ebd5fdfa0165'
    '35ac68df-8be5-4dae-bf20-11f75555eecc'
    '31e8f60b-f396-4e5f-8a46-7772faf95fa4'
    '7b2ea090-4408-4d9c-b1b6-be5a97eb7b36'
) -join ','
# $approvedSha = exact owner-merged and CI-green NEW source HEAD SHA
# $config = existing public extensions configuration path
& $manager -Action Check -Build -SourceSha $approvedSha -Config $config `
    -PreserveUncertainRequests $incidentIds
# Только после READY и отдельного owner GO:
& $manager -Action Apply -Build -SourceSha $approvedSha -Config $config `
    -PreserveUncertainRequests $incidentIds
```

`Check` с новым параметром выполняет read-only inspection старого state;
`Apply` после owner approval выполняет штатный staged release.
Проверки списка требуют точного совпадения всех `UNCERTAIN`, запрещают
`PENDING/APPROVED/DISPATCHED`, проверяют отсутствие активных worker jobs.
Контроллер записывает scope в protected release record; состояние
переносится байт-в-байт, без подмены исходов. При будущих релизах/Backup/
Promote будет допустимо лишь *подмножество* исходных UUID (если случаи
закрыты), но не новые неизвестные запросы **без нового явного решения
владельца**. При новом UNCERTAIN нужен owner-reviewed список всех текущих
UUID и повторный `Check -Build -SourceSha` с новым source SHA.

После Apply зайти в Owner Portal → `Требуют разбора`. Для каждого запроса
сначала выполнить `Проверить подтверждение (receipt)`. Если receipt не
найден и расследование действительно закончено, выполнить штатную
`-Action Backup` и подтвердить `FORTIS_PRIMARY_BACKUP_PASS` плюс
protected backup record/volume identity, проверить фактический GitHub/Git
effect и только затем закрывать в UI через WebAuthn с объяснением
`CLOSED_UNCONFIRMED`. В UI имя backup является **owner attestation**,
а не независимой проверкой Docker volume; backup нужно отдельно
верифицировать оператору. Закрытие расследования не утверждает успех
операции и не разрешает повторное выполнение исходного UUID.

При несовпадении UUID/состояния, неправильном source/image SHA,
непроверенном backup, несовпадении protected record/volume либо
ошибке на любом preflight — STOP. Не отключать guard, не править SQLite
и не делать повторный `Apply` до выяснения точного состояния.


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
