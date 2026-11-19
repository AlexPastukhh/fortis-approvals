# Fortis Approvals Gateway — текущее состояние

**Последний зафиксированный owner-reported выпуск, 2026-11-18:**
после merge PR #131 опубликованный source `main` —
`7d7221f9b61fb3660aa2561d3445638436686da4`.
Owner выполнил `Check -Auto READY` для image
`sha256:a596585d72b58c51147acb83a09024ae06a6b87bfd63e62e18eb07ad4c580575`
с configuration digest
`972ed32d2b7242a1c8487811bc448902a11869dbaf2fe0a08c9880a1f120f6cd`.
Затем `Apply -Auto` вернул `FORTIS_INTEGRATIONS_ACTIVATED`,
`active=true`, `previousRetained=true`, `productionUnchanged=true`;
protected record у владельца:
`%LOCALAPPDATA%\Fortis\GatewayReleases\6c375631b872463c90378f1a5a08179c\record.json`.
Owner выполнил `Backup -Auto`:
`FORTIS_PRIMARY_BACKUP_PASS fortis-gateway-backup-bf0218ec39ac46c2a016bbee4debf179`,
затем `Promote -Auto`: `FORTIS_PRIMARY_PROMOTED`.
Независимый Repo TLS/machine API и integration catalog READ после Promote
успешны; Mirror operation `get_repository` объявлена `ALLOW/ready=true`.
Выпуск не является доказательством отдельного host restart/autostart,
WebAuthn browser acceptance или GitHub provider WRITE acceptance.

**Исторический релиз 2026-11-14, PR #94:** source
`c473edb88737f773d2f9ec0a9943235ebb18aa3a`, image
`sha256:900456ddba50c164de202645f2e3b6859599b5a64383f13d3628665c640a509a`;
record `%LOCALAPPDATA%\Fortis\GatewayReleases\e2e0610bd2f54c268cd06dbba1d57a6c\record.json`;
backup `fortis-gateway-backup-2cb0d07e64a149728d0aefd5830302f0`.
Эта дата — предыдущее evidence, не текущие deployment pins.

**Граница проверки 2026-11-18:** post-Promote machine readback подтверждает
доступность Gateway API и integration catalog, но **не заменяет** независимый
host `docker inspect` с точными image/ports/restart и проверку Docker Desktop
restart. Не выдавать owner outputs за независимую проверку Windows runtime.
Provider mutation acceptance в Apply: `PENDING_OR_NOT_APPLICABLE`.
Точные runtime IDs всегда брать из protected records и свежего host readback.

**Исторический срез 2026-11-10, PR #62:** ранее owner подтвердил
`Check → Apply → Backup → Promote` для
`8403c63297f78e38294899c6bd094cc9f9eac66f`; тот
`docker inspect` показывал running/healthy/unless-stopped.
Ниже — датированное evidence этого **предыдущего**, а не текущего выпуска.
[Agent guide](../GATEWAY-AGENT-GUIDE.md) владеет использованием,
[native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md) — API/policy,
[backlog](../BACKLOG-IMPROVEMENTS.md) — незавершёнными задачами,
[датированное evidence](../../fortis_approvals/evidence/OWNER-SHELL-RELEASE-AND-GET-DATE-20261110.md)
— точными owner outputs и границами подтверждения.

**Release Labels / Trusted Publisher — owner-reported live E2E PASS,
2026-11-19.** Владелец активировал отдельный `release-label-publisher-v1`
в текущем Gateway, изолированный одноразовый runner и Gateway-only TLS relay.
После закреплённого `preview` по [PR #118](https://github.com/AlexPastukhh/fortis-approvals/pull/118)
owner создал ровно один ASK, подтвердил его WebAuthn, затем выполнил
read-only original-receipt проверку. Исходный intent
`7a1017be-9171-5ee5-9db5-1b62e1f1dea0`, request
`ed0dce76-8402-4230-941e-a89b5639460d`:
`P34_ORIGINAL_CORE_REQUEST_EXECUTED_PASS`,
`P34_ORIGINAL_UUID_BOUND_RECEIPT_VERIFIED_PASS`,
`P34_ORIGINAL_RECEIPT_AND_LIVE_LABELS_MATCH_PASS`,
`P34_PUBLISHER_PR118_E2E_ORIGINAL_RECEIPT_READBACK_PASS`.
Независимый GitHub readback подтвердил добавление ровно
`release:no-deployment` на прежний HEAD
`c6f6cf09cecf825c0d4c7595a2bdb153b129ce00`; PR оставлен
OPEN, merge и deployment не выполнялись. Private IntentJournal:
один intent, одна попытка, без повторного request/reconcile.

Принятый one-shot runner image
`fortis-publisher-runtime:p34-e349d2aa-pydeps7`,
Docker manifest image `sha256:17718280a289cbd5a94e406af36ab7738173a00d25aa96515a2eb0ecbf5b9591`,
source `e349d2aa37ce1bbd5ac86b31107b6e4412cf9607`.
Установленный основной Gateway **не** отождествлять с этим runner image
или поздним GitHub `main`. TLS relay ранее остановился с exit 137,
владелец восстановил тот же контейнер и подтвердил TLS route/deny direct
egress; устойчивость после restart/reboot и unattended mode этим не приняты.
Нельзя повторно запускать исходный `request`.

**Scope:** owner-invoked, один PR/операция, fixed `fortis-approvals`,
`ASK` add/remove существующих управляемых меток, read-only `preview/inspect`.
Live E2E **добавления** подтверждён; отдельного E2E удаления, нескольких
targets, scheduler/webhook, автоматических повторов, CD Queue и Deployment
Publisher нет. Подробные контракты и запреты —
[Publisher review](../RELEASE-LABEL-PUBLISHER-P3-REVIEW.md),
[UC-GW-011](../use-cases/integrations.md#uc-gw-011),
[Primary operations](../PRIMARY-GATEWAY-OPERATIONS.md).
Нормативный Release Impact/labels остаётся у
`fortis-container/docs/RELEASE-PLANNING-CONTRACT.md`, единый
валидатор — `fortis-release-impact-action`; дальнейшие задачи —
в [общем roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#fortis-release-planning--cd-queue).

## Развёрнутые контуры

| Контур | Endpoint / роль | Последнее подтверждение |
| --- | --- | --- |
| Primary `fortis-gateway` | Owner `http://localhost:19203`; machine `https://host.docker.internal:19204` | 2026-11-18 owner `PROMOTED`, Repo typed TLS API/capabilities readback PASS; точный host `docker inspect` после Promote не предоставлен |
| Legacy `fortis-approvals-gateway` | Бывшие 19103/19104 | Owner остановил контейнер, `restart=no`, image/state сохранены; не штатный endpoint |
| Fortis Repo `fortis-repo-test` | Machine client и native workspace worker | Отдельный контейнер; canonical `Repos/<repo>` и linked `Worktrees/<repo>/<task>` |

## Исторический Primary — owner-verified PR #62 (2026-11-10)

| Факт | Подтверждение |
| --- | --- |
| Source | PR #62, merged `main` `8403c63297f78e38294899c6bd094cc9f9eac66f`; PR и merged-main CI: success |
| Windows Check | `SOURCE_STATE_PREFLIGHT_READ_ONLY`, `FORTIS_APPROVED_SCOPE_FORWARD_VERIFIED` и `status: READY` без missing credentials |
| Apply | `FORTIS_INTEGRATIONS_ACTIVATED`, `active=true`, `previousRetained=true`, отдельный production baseline без изменений |
| Image | `sha256:cdd7c22308d9e5820545f9ead2f71c3543c29b6f4ee7886d3b1b6cbc8f24d66c` |
| Protected release record | `%LOCALAPPDATA%/Fortis/GatewayReleases/31bdca259de84757a2a0f164a9e494bd/record.json` |
| Backup | `FORTIS_PRIMARY_BACKUP_PASS fortis-gateway-backup-b7d972135c774928bbedd19975072df7` |
| Promote/host | `FORTIS_PRIMARY_PROMOTED`; owner `docker inspect`: `/fortis-gateway | running | healthy | unless-stopped`, bind `127.0.0.1:19203/19204` |
| Global machine readback | `globalRequestInventory.readOnly=true`, `crossActorDetails=true`; `list_requests(unresolved_only=True)`: 2 APPROVED, оба доступны через `details(UUID)` с audit, без worker job/receipt |

**Значение результата:** `APPROVED`
`ba299f4f-f49c-4ef7-80cf-e1f31a232024` и
`49bcd340-8d21-4a7c-906a-ea5ea56ba748` перенесены
**без автоматического исполнения/отмены**. Исторический
`CLAIMED` `2df32a24-efb1-4dac-97f6-3b66147d8944`
оставался в exact preservation scope; отсутствие heartbeat/receipt
не доказывает исход. Права на owner decisions у AI не появились.

**Ограничение live:** global list и `details` проверены с существующим
машинным доступом; все 1482 записи полной истории в текущей базе
принадлежат одному actor. Доступ второго AI actor к чужой карточке
проверен тестами, но пока не отдельным live обращением другого grant.
Owner Portal browser cancel/assess click и restart/autostart после
Docker Desktop reboot также остаются непроверенными.

**PowerShell live readback, 2026-11-19:** typed Gateway
`powershell.capabilities()` вернул `configured=true`, `policy=ASK`,
`machineExecutionAutoApprove=false`, `version=1`. Датированное owner
Machine ASK Get-Date/Reject E2E — 2026-11-18; full forged proof/replay/
timeout/lost-ACK/restart fault-injection **OPEN**, от одного live
capabilities не следует полная security acceptance. Действующий V1
**требует ASK для каждой команды**. Новая цель — независимые слои:
общий owner method-policy editor и отдельный Executor-only Dynamic ASK
для точной команды. Оба **ещё не реализованы**; текущий V1 на ALLOW
не переключён. Канонический [Gateway plan](../BACKLOG-IMPROVEMENTS.md#powershell-plan)
и [Executor backlog](https://github.com/AlexPastukhh/fortis-powershell-executor/blob/main/docs/BACKLOG-IMPROVEMENTS.md#executor-dynamic-ask).

## Историческая owner acceptance — PS-V1-09 (предыдущий релиз)

**Предыдущий OWNER-REPORTED** guarded image release (PS-V1-09, 2026-11-10):

| Проверка | Подтверждено владельцем |
| --- | --- |
| Источник | PR #53; image source `9481699faaa297d8ec1fb45b4f14be50ae17406f` |
| Release | `Check -Build`, `Apply -Build -EnableOwnerShell`, verified staged Windows mTLS, activation `FORTIS_INTEGRATIONS_ACTIVATED` |
| Образ | `sha256:03b258618e515988aaee17362889329c9b26d128012f13e62b733b99a3d5a273` |
| Protected record | `%LOCALAPPDATA%\Fortis\GatewayReleases\fa449e3ee689466a818c1e730dc3787f\record.json` |
| Backup / Promote | `fortis-gateway-backup-4920ada96279425e8d45b4a9eed15d0a`, `PS_V1_09_BACKUP_READBACK=PASS`, `FORTIS_PRIMARY_PROMOTED`, `PS_V1_09_PROMOTE_READBACK=PASS` |
| Owner Portal | V1 PowerShell owner opt-in включён; первая команда `Get-Date` — `EXECUTED`, exit `0` (PS-V1-10 **частичная** приёмка) |

**Исторический Repo readback после PS-V1-09:** authenticated Gateway
capabilities и GitHub READ работали, `incidentInventory.readOnly=true`,
actor-owned `list_uncertain` вернул
три сохранённых `UNCERTAIN`; одна историческая Core-заявка
`CLOSED_UNCONFIRMED` имеет сохранённый worker `CLAIMED`.
Также наблюдался `workerActivity.readOnly=true` и успешный read-only
`activity()`; это не доказательство worker quiescence и не подтверждает
конкретный Docker image для возможного последующего релиза.
Точный список UUID, owner output и границы приёмки — в
[датированном evidence](../../fortis_approvals/evidence/OWNER-SHELL-RELEASE-AND-GET-DATE-20261110.md)
и [UC-GW-009](../use-cases/incidents.md#uc-gw-009).

**MANUAL-PENDING:** после PR #62 независимо проверить Owner Portal
browser отмену/автопроверку, живой cross-actor read под вторым grant,
Docker Desktop restart/autostart, Windows Executor restart/receipt
persistence и отрицательные owner session/CSRF/UUID проверки. Эти открытые задачи ведутся только в
[backlog](../BACKLOG-IMPROVEMENTS.md).

The owner-confirmed 2026-11-09 PR #39 release (image
`sha256:69be667a654882f6b073eb89827a4be28e2f28b355838cc9325d2c66cc14bec8`)
and older releases are historical, **not** current image pins. Owner-only reboot acceptance of the new image
was not established; do not infer it from `healthy` or restart policy.
История первоначального cutover — в
[dated evidence](../../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md).

Четыре согласованные старые `UNCERTAIN` были разово удалены после проверенной
холодной копии; сохранены native `FAILED` tombstones против повторного исполнения.
Rescue volume: `fortis-gateway-rescue-four-03e0c29d99df4cd09e2a0d46175da319`;
owner maintenance record:
`%LOCALAPPDATA%\Fortis\GatewayReleases\owner-retire-four-7cae534f-20261108\record.json`.
Повторный запуск старого recovery остановлен на `PRIMARY_SOURCE_POINTER_CHANGED`
до изменений: Primary уже перешёл на новый release record. Это завершённая
операторская exception-процедура, не общий способ закрывать заявки; расследование
и штатный lifecycle принадлежат [backlog](../BACKLOG-IMPROVEMENTS.md).

<a id="что-завершено"></a>

## Что подтверждено через Repo

- Live capabilities: `dynamicRepositories=true`, присутствует
  `workspace.update_main_from_pr`; documented task push/PR creation прошли
  через typed Gateway, но policy всегда проверять для текущих actor/target.
- Live `cleanupTask` соответствует [native cleanup contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md#task-worktree-cleanup).
  Одноразовый пустой task создан и удалён без owner ASK; `fetch/create/cleanup`
  имеют `EXECUTED`, task path отсутствует. Четыре retired request ID возвращают
  `NOT_FOUND`; GitHub READ после Promote работает. Это live-проверка merged
  ALLOW, не полный новый цикл всех deny/ASK/owner решений.
- Реальные task commit/push/PR и owner UI merge с обновлением Docker main
  проверены для Gateway, Container, Mirror, Tunnel, Script Center и Tab Notifier.
  Это не обещание прав записи для всех обнаруженных GitHub repos.
- Provider credentials остаются в Gateway; native bundle сохраняет SHA локальных
  Git-коммитов. Точные policy/preconditions находятся только в native contract.
- Первоначальные Sonar READ и owner ASK Approve/Reject проверены в
  [Sonar evidence](../../fortis_approvals/evidence/FORTIS-SONAR-LIVE-E2E-20261104.md),
  native bootstrap — в [native evidence](../../fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md).
  Не считать эти датированные циклы новой полной проверкой Owner Portal после
  каждого image. В этом аудите owner WebAuthn ceremony не запускалась.

## Граница доверия и исполнения

Machine grant/public trust в Repo, provider tokens/TLS private key/owner state
в Gateway имеют разные роли. RO mount и `0600` не изолируют процессы одного UID.
Local workspace effect исполняет Repo worker после Core authorization; approval,
dispatch и подтверждённый receipt — разные стадии. Общий process tool Repo не
становится автоматически ограниченным Gateway policy.

<a id="известные-ограничения"></a>

## Действующие ограничения

- Sonar default-branch Quality Gate не доказывает PR/SHA binding; доступные
  операции определяются live profile, не наличием source package.
- Legacy Repo PAT/helper removal не подтверждён. Это не разрешённый fallback:
  применять [UC-CONT-003](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-003).
- Для PENDING status у текущего клиента действует HTTP 202 caveat из
  [native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md); при UNCERTAIN
  сверять исходный UUID и receipt, не повторять эффект вслепую.

Незавершённая разработка и ожидающие acceptance ведутся только в
[единственном backlog](../BACKLOG-IMPROVEMENTS.md). Здесь — подтверждённые
факты, границы их проверки и ограничения выбора операции.

## Работа с исходниками и восстановление

Canonical source — standalone `AlexPastukhh/fortis-approvals`; старый RDG subtree
сохранён и не является местом разработки. [Package map](../../fortis_approvals/README.md)
и [deployment index](../../fortis_approvals/deploy/README.md) ведут к коду и контроллеру.
Provisioning/enrollment/client mount не повторять из старого runbook.
Использовать текущие controller records для Resume/Return/Backup/Promote по
[Primary operations](../PRIMARY-GATEWAY-OPERATIONS.md). Не очищать bootstrap,
retained states и credentials, пока от них зависят owner deployment records.
Git и image не заменяют backup persistent state и secrets.


## Own API operational READ snapshot — 2026-11-16

Canonical onboarding and reusable tools: [UC-GW-012](../use-cases/own-api.md#uc-gw-012),
[Doctor / one-shot Acceptance](../templates/own-api/TOOLS.md). This snapshot
is operational evidence, not another onboarding procedure or release approval.

- Repo source reviewed: Approvals main `c52736aec5861c67b7ce2b2a58304a821cf8e413`;
  Mirror main `109c6e8184c5bfb5293e84127ab1b3e794e85f0e`. These do not prove installed SHAs.
- Authenticated catalog for the audited machine actor exposed only
  `mirror.get_repository`, version `1`, target `fortis-approvals`, ALLOW,
  ready with credential READY. `providerPermissions` still says UNVERIFIED.
- Fresh typed READ `9fbb988d-fcd8-4fae-ab47-58a55edf36ea` returned EXECUTED;
  the packaged closed result schema and exact repo identity validated.
- The accepted Mirror provider fixes HTTPS/443, hostname verification,
  service-specific pinned CA and separate Bearer. This audit did not independently
  inspect the installed image, certificate/ACLs, protected release or restore.
  It does not close the full TLS/negative/owner-host acceptance matrix.
- This is strict v1 READ, not unified v2, shared-Core cutover or ASK Pull.
  No Observatory operation was exposed to this actor; other actors are not covered.
  Its legacy HTTP/18756 adapter is not a current DOCKER-HTTPS admission.
  The separate direct Repo-to-Observatory client also uses HTTP/18756 in source;
  its live use was not audited. No retirement or migration was authorized here.
- Doctor saw 3 UNCERTAIN requests and 1 claimed worker, with owner quiescence
  unproven. Re-read the global inventory before any shared Gateway release;
  this dated count is not current clearance. No runtime/config/credential changed.
- 42 targeted onboarding/tool, Mirror TLS and Observatory definition tests passed.
