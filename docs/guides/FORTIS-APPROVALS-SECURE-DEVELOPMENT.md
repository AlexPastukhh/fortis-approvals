# Fortis Approvals Gateway — текущее состояние

**Срез 2026-11-10.** Последний подробно подтверждённый владельцем Windows
image release — PS-V1-09; отдельно есть более поздние authenticated Repo
machine readbacks. Это **не** независимый Windows Docker inspect после всех
последующих изменений. Точные current container/image/state/volume при
host-операциях устанавливать по protected records и свежему owner readback.
[Agent guide](../GATEWAY-AGENT-GUIDE.md) владеет использованием,
[native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md) — API/policy,
[backlog](../BACKLOG-IMPROVEMENTS.md) — незавершёнными задачами,
[датированное evidence](../../fortis_approvals/evidence/OWNER-SHELL-RELEASE-AND-GET-DATE-20261110.md)
— точными owner outputs и границами подтверждения.

## Развёрнутые контуры

| Контур | Endpoint / роль | Последнее подтверждение |
| --- | --- | --- |
| Primary `fortis-gateway` | Owner `http://localhost:19203`; machine `https://host.docker.internal:19204` | Owner post-promote: healthy, restart `unless-stopped`; Repo typed operations работают |
| Legacy `fortis-approvals-gateway` | Бывшие 19103/19104 | Owner остановил контейнер, `restart=no`, image/state сохранены; не штатный endpoint |
| Fortis Repo `fortis-repo-test` | Machine client и native workspace worker | Отдельный контейнер; canonical `Repos/<repo>` и linked `Worktrees/<repo>/<task>` |

Последний **OWNER-REPORTED** guarded image release (PS-V1-09, 2026-11-10):

| Проверка | Подтверждено владельцем |
| --- | --- |
| Источник | PR #53; image source `9481699faaa297d8ec1fb45b4f14be50ae17406f` |
| Release | `Check -Build`, `Apply -Build -EnableOwnerShell`, verified staged Windows mTLS, activation `FORTIS_INTEGRATIONS_ACTIVATED` |
| Образ | `sha256:03b258618e515988aaee17362889329c9b26d128012f13e62b733b99a3d5a273` |
| Protected record | `%LOCALAPPDATA%\Fortis\GatewayReleases\fa449e3ee689466a818c1e730dc3787f\record.json` |
| Backup / Promote | `fortis-gateway-backup-4920ada96279425e8d45b4a9eed15d0a`, `PS_V1_09_BACKUP_READBACK=PASS`, `FORTIS_PRIMARY_PROMOTED`, `PS_V1_09_PROMOTE_READBACK=PASS` |
| Owner Portal | V1 PowerShell owner opt-in включён; первая команда `Get-Date` — `EXECUTED`, exit `0` (PS-V1-10 **частичная** приёмка) |

**LIVE-VERIFIED Repo machine:** authenticated Gateway capabilities и GitHub READ
работают, `incidentInventory.readOnly=true`, actor-owned `list_uncertain` вернул
три сохранённых `UNCERTAIN`; одна историческая Core-заявка
`CLOSED_UNCONFIRMED` имеет сохранённый worker `CLAIMED`.
Также наблюдался `workerActivity.readOnly=true` и успешный read-only
`activity()`; это не доказательство worker quiescence и не подтверждает
конкретный Docker image для возможного последующего релиза.
Точный список UUID, owner output и границы приёмки — в
[датированном evidence](../../fortis_approvals/evidence/OWNER-SHELL-RELEASE-AND-GET-DATE-20261110.md)
и [UC-GW-009](../use-cases/incidents.md#uc-gw-009).

**MANUAL-PENDING:** независимый host inspect после будущих изменений, Windows
Executor restart/receipt persistence и отрицательные owner session/CSRF/UUID
проверки. Эти открытые задачи ведутся только в
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
