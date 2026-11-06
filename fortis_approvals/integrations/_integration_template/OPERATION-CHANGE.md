# Карточка изменения операций

Скопировать в evidence/рабочую документацию конкретного изменения. Это вход для
[общего workflow](../../../docs/OPERATION-ONBOARDING-WORKFLOW.md), а не второй
каталог контрактов/политик или runtime status. Для существующего provider не
копировать весь integration template.

| Поле | Значение изменения |
| --- | --- |
| Provider / цель / минимальный работающий результат | Заполнить |
| Тип изменения | Client-only / config-only / code / credential / state migration |
| Новые или изменяемые operation IDs | Ссылки на authoritative contract/schema; эффект read/mutation и execution/approval path по отдельности |
| Actor, target scope, effective policy | Ссылки на trusted config/policy; точный ALLOW/ASK/DENY |
| Обязательные реальные IDs/bindings | Где установлены; неизвестные значения — BLOCKED |
| Upstream permissions / credential availability | Подтверждено / owner action / UNKNOWN; ссылка на Gateway-side reference, без token |
| ASK preview, effect/readback, replay/uncertain | Ссылки на implementation/tests; применимость |
| State/dependency/packaging changes | Inventory/migration, image allowlist; либо явно отсутствуют |
| Activation config / release inputs | Полный public config + source/image references; без placeholders |
| Проверки до owner run | Targeted tests, exact command/import/config checks и preflight probes |
| Новые live probes / ASK acceptance | Какие эффекты/чтения доказывают требуемый результат |
| Return / resume | Проверенный runtime record и границы возврата |
| Blockers | Список либо «обязательных blockers нет» |
| Evidence и итог | Ссылки; source/image/config/live по отдельности |

Имена, поля, bounds и policies принадлежат code contracts и trusted composition.
Текущий статус принадлежит current-state документу; в карточке сохраняется
исторический результат конкретного изменения и ссылки на владельцев данных.
