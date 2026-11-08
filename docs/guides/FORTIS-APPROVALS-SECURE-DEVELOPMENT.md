# Fortis Approvals Gateway — текущее состояние

Датированный срез 2026-11-08: последний owner-provided Windows release output
и последующие Repo machine readback. Это не свежий Docker inspect с Windows:
перед runtime-операцией сверить protected records и реальную identity.
Этот документ владеет deployment status; [agent guide](../GATEWAY-AGENT-GUIDE.md)
— применением, [native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md)
— операциями/policy, [backlog](../BACKLOG-IMPROVEMENTS.md) — будущими задачами.

## Развёрнутые контуры

| Контур | Endpoint / роль | Последнее подтверждение |
| --- | --- | --- |
| Primary `fortis-gateway` | Owner `http://localhost:19203`; machine `https://host.docker.internal:19204` | Owner post-promote: healthy, restart `unless-stopped`; Repo typed operations работают |
| Legacy `fortis-approvals-gateway` | Бывшие 19103/19104 | Owner остановил контейнер, `restart=no`, image/state сохранены; не штатный endpoint |
| Fortis Repo `fortis-repo-test` | Machine client и native workspace worker | Отдельный контейнер; canonical `Repos/<repo>` и linked `Worktrees/<repo>/<task>` |

Последний подтверждённый owner image release:

| Поле | Значение из owner output |
| --- | --- |
| Source SHA образа | `7cae534f8617482511bf486a6133563e8bcd2ae8` |
| Image ID | `sha256:877c93ef1d4ff970bd8e6ebfad961ef9dc2345fbc71f767b6528a0aa20b585e4` |
| Container ID | `241c00cfb1becc62d152d26806034f4643b22877fe9839c80a326721191618f9` |
| Complete release record | `%LOCALAPPDATA%\Fortis\GatewayReleases\96349e7910dd4f89a334af9a4459f3cb\record.json` |
| Verified controller backup | `fortis-gateway-backup-5b51f6566d764e13905a45e4675c6e2e` |
| Host result | Apply activated, live merged-task cleanup PASS, Backup PASS, Promote PASS, `FORTIS_CLEANUP_POLICY_DEPLOYED_AND_PRIMARY_HEALTHY` |

Последующие documentation/source merges меняют Git `main`, а не этот image.
Owner read-only аудит после перезагрузки 2026-11-08 подтвердил Repo, прежний
Primary, `unless-stopped`, HTTP Owner Portal и целостность пяти БД; затем был
установлен указанный выше image. Его финальные identity/health/restart проверены
после Promote, но этот результат не является новым reboot-тестом нового image.
История первоначального cutover — в [dated evidence](../../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md).

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
  `workspace.update_main_from_pr`, ordinary task push и PR creation — ALLOW.
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
