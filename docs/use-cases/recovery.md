# Gateway recovery

## UC-GW-006

**Когда:** Apply/Promote/Backup не завершились либо результат uncertain.

**Цель:** возобновить фазу без двойной мутации или безопасно остановиться.

**Как:** сверить original protected attempt, immutable ID/image/state,
writer exclusivity, release pointers и реальные receipts по
[Primary runbook](../PRIMARY-GATEWAY-OPERATIONS.md) и
[extension contract](../INTEGRATION-EXTENSIONS.md). Resume использует
original attempt record, а не новый произвольный ID. Возврат после effect
не автоматический: новая state могла принимать запросы, GitHub PR/merge не
отменяются volume restore. Отдельно проверить восстановимость по
[UC-CONT-022](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/docker.md#uc-cont-022).
Сохранить ресурсы/секреты/историю. Не переключать Repo на старый `19104`.

**Готово:** восстановленный healthy state с доказательствами или точный
`RECOVERY_REQUIRED`, без потери records и повторного внешнего эффекта.
