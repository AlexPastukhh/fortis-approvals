# Fortis Approvals — действующие локальные Use Cases

Общие Docker/GitHub/AI правила: [главный Fortis UC реестр](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/README.md). Этот файл перечисляет **только UC, действительно принятые в `fortis-approvals/main`**. Сценарии из отдельных task worktrees не считаются опубликованными, и не должны появляться здесь раньше merge. Технические обязанности Gateway — в [agent guide](../GATEWAY-AGENT-GUIDE.md), [native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md) и [deployment runbook](../PRIMARY-GATEWAY-OPERATIONS.md); здесь не копировать их правила.

| ID | Когда | Действия |
| --- | --- | --- |
| [UC-GW-001](sonar.md#uc-gw-001) | Sonar Quality Gate, issues и привязка к PR | Контекстный READ и проверенный результат, не домыслы о PR-проверке |
| [UC-GW-002](integrations.md#uc-gw-002) | Подключить новый внешний provider | Проверенный extension package, минимальные scopes, owner acceptance |
| [UC-GW-003](integrations.md#uc-gw-003) | Добавить операцию, клиентский метод или machine API | Версионированный контракт, отрицательные тесты, сохранение старых вызовов, CI и live release |
| [UC-GW-004](credential-lifecycle.md#uc-gw-004) | Добавить или ротировать provider credential | Owner-controlled secret lifecycle без утечки и обходов |
| [UC-GW-005](releases.md#uc-gw-005) | Установить новый image/config, сохранив ожидающие APPROVED | Exact SHA/owner scope, guarded state transfer, Backup/Promote и live readback |
| [UC-GW-006](recovery.md#uc-gw-006) | Resume/Return после неопределённой фазы | Исходный record, без слепого повторения эффекта |
| [UC-GW-007](primary.md#uc-gw-007) | Primary/restart/autostart и Legacy | Owner-confirmed healthy и retained rollback |
| [UC-GW-008](owner-passkey.md#uc-gw-008) | Владелец хочет добавить ещё один passkey к действующему Owner Portal | Только owner-local guarded Preview/Issue, одноразовая регистрация, проверка обоих passkey; не доступно AI/Gateway machine API |
| [UC-GW-009](incidents.md#uc-gw-009) | Любой авторизованный ИИ читает **все** заявки (включая других инициаторов) и разбирает «Требуют разбора» | Global `list_requests()` + cross-actor `details()`; решения, отмена/closure — только в Owner Portal |
| [UC-GW-010](incidents.md#uc-gw-010) | Наблюдать actor-owned worker activity без claim/retry и не путать heartbeat с доказательством простоя | Read-only `activity()` наблюдался live; код worker diagnostics требует отдельной owner acceptance |
| [UC-GW-011](integrations.md#uc-gw-011) | Типизированные GitHub Release Labels: читать, определять и изменять метки открытого PR | Строго закрытый API, ASK/receipt/UNCERTAIN; после Merge source ещё не означает установленный Primary, live по UC-GW-005 |

Каждый новый чат читает короткий вход главного реестра и полностью
UC-CONT-002, UC-CONT-003 и [UC-GW-009](incidents.md#uc-gw-009);
просматривать весь каталог не нужно. Выбор контекста — по
исходному запросу, локальные сценарии — по задаче. Принятые UC имеют одного
владельца; при расширении обновлять этот индекс, не создавать второй реестр.

Обычный разбор `UNCERTAIN`: [UC-GW-009](incidents.md#uc-gw-009); будущие улучшения: [единый backlog](../BACKLOG-IMPROVEMENTS.md). Исторические результаты — [разбор multi-repo rollout](../MULTI-REPO-WORKFLOW-REVIEW-20261107.md).
