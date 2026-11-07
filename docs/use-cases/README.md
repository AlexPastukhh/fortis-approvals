# Fortis Approvals — действующие локальные Use Cases

Общие Docker/GitHub/AI правила: [главный Fortis UC реестр](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/README.md). Этот файл перечисляет **только UC, действительно принятые в `fortis-approvals/main`**. Сценарии из отдельных task worktrees не считаются опубликованными, и не должны появляться здесь раньше merge. Технические обязанности Gateway — в [agent guide](../GATEWAY-AGENT-GUIDE.md), [native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md) и [deployment runbook](../PRIMARY-GATEWAY-OPERATIONS.md); здесь не копировать их правила.

| ID | Когда | Действия |
| --- | --- | --- |
| [UC-GW-002](integrations.md#uc-gw-002) | Подключить новый внешний provider | Проверенный extension package, минимальные scopes, owner acceptance |
| [UC-GW-003](integrations.md#uc-gw-003) | Добавить операцию, клиентский метод или machine API | Версионированный контракт, отрицательные тесты, сохранение старых вызовов, CI и live release |
| [UC-GW-008](owner-passkey.md#uc-gw-008) | Владелец хочет добавить ещё один passkey к действующему Owner Portal | Только owner-local guarded Preview/Issue, одноразовая регистрация, проверка обоих passkey; не доступно AI/Gateway machine API |

Если в текущем `main` нет других локальных UC, **не** создавать фиктивные разделы UC-GW-001–007: их документационные кандидаты находятся в отдельных ветках. При принятии таких UC дополнить именно этот индекс и убрать дублирующий registry, а не создавать второй файл.

Будущая разработка и расследование `UNCERTAIN`: [единый backlog](../BACKLOG-IMPROVEMENTS.md). Исторические результаты — [разбор multi-repo rollout](../MULTI-REPO-WORKFLOW-REVIEW-20261107.md).
