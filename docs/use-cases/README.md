# Fortis Approvals — действующие локальные Use Cases

Общие Docker/GitHub/AI правила: [главный Fortis UC реестр](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/README.md). Этот файл перечисляет **только UC, действительно принятые в `fortis-approvals/main`**. Сценарии из отдельных task worktrees не считаются опубликованными, и не должны появляться здесь раньше merge. Технические обязанности Gateway — в [agent guide](../GATEWAY-AGENT-GUIDE.md), [native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md) и [deployment runbook](../PRIMARY-GATEWAY-OPERATIONS.md); здесь не копировать их правила.

| ID | Когда | Действия |
| --- | --- | --- |
| [UC-GW-001](sonar.md#uc-gw-001) | Sonar Quality Gate, issues и привязка к PR | Контекстный READ и проверенный результат, не домыслы о PR-проверке |
| [UC-GW-002](integrations.md#uc-gw-002) | Подключить новый внешний provider | Проверенный extension package, минимальные scopes, owner acceptance |
| [UC-GW-003](integrations.md#uc-gw-003) | Добавить операцию, клиентский метод или machine API | Версионированный контракт, отрицательные тесты, сохранение старых вызовов, CI и live release |
| [UC-GW-004](credential-lifecycle.md#uc-gw-004) | Добавить или ротировать provider credential | Owner-controlled secret lifecycle без утечки и обходов |
| [UC-GW-005](releases.md#uc-gw-005) | Обновить Gateway с сохранением UNCERTAIN/CLAIMED и отдельной проверкой APPROVED | Owner Check/Apply с защищённым append-only admission, byte-exact transfer, Backup/Promote |
| [UC-GW-006](recovery.md#uc-gw-006) | Resume/Return после неопределённой фазы | Исходный record, без слепого повторения эффекта |
| [UC-GW-007](primary.md#uc-gw-007) | Primary/restart/autostart и Legacy | Owner-confirmed healthy и retained rollback |
| [UC-GW-008](owner-passkey.md#uc-gw-008) | Владелец хочет добавить ещё один passkey к действующему Owner Portal | Только owner-local guarded Preview/Issue, одноразовая регистрация, проверка обоих passkey; не доступно AI/Gateway machine API |
| [UC-GW-009](incidents.md#uc-gw-009) | Любой авторизованный ИИ читает **все** заявки (включая других инициаторов) и разбирает «Требуют разбора» | Global `list_requests()` + cross-actor `details()`; решения, отмена/closure — только в Owner Portal |
| [UC-GW-010](incidents.md#uc-gw-010) | Наблюдать actor-owned worker activity без claim/retry и не путать heartbeat с доказательством простоя | Read-only `activity()` наблюдался live; код worker diagnostics требует отдельной owner acceptance |
| [UC-GW-011](integrations.md#uc-gw-011) | Типизированные GitHub Release Labels: читать, определять и изменять метки открытого PR | Строго закрытый API, ASK/receipt/UNCERTAIN; после Merge source ещё не означает установленный Primary, live по UC-GW-005 |
| [UC-GW-012](own-api.md#uc-gw-012) | Подключить собственный Windows/Docker API через Gateway | Выбор WIN-HTTPS/DOCKER-HTTPS, pinned CA + отдельный vault alias, source lint, owner release и только реальный typed READ |
| [UC-GW-013](recovery.md#uc-gw-013) | Аварийный выпуск при отсутствии прежнего image | Однократный owner-accepted emergency mode, restore не считается проверенным |
| [UC-GW-014](powershell-executor.md#uc-gw-014) | Repo AI отправляет Windows PowerShell через ASK | Typed client → PENDING → owner WebAuthn; никакого ALLOW или прямого Windows proxy |
| [UC-GW-015](powershell-executor.md#uc-gw-015) | Проверить одобрение/Reject и связанную квитанцию | Core audit + typed result + исходная Windows SQLite без нового эффекта |
| [UC-GW-016](powershell-executor.md#uc-gw-016) | Timeout, lost ACK, UNCERTAIN и восстановление | Исходный UUID, no-replay, изолированные fault-injection и owner recovery |

Каждый новый чат читает короткий вход главного реестра и полностью
UC-CONT-002, UC-CONT-003 и [UC-GW-009](incidents.md#uc-gw-009);
просматривать весь каталог не нужно. Выбор контекста — по
исходному запросу, локальные сценарии — по задаче. Принятые UC имеют одного
владельца; при расширении обновлять этот индекс, не создавать второй реестр.

Обычный разбор `UNCERTAIN`: [UC-GW-009](incidents.md#uc-gw-009); будущие улучшения: [единый backlog](../BACKLOG-IMPROVEMENTS.md). Исторические результаты — [разбор multi-repo rollout](../MULTI-REPO-WORKFLOW-REVIEW-20261107.md).
