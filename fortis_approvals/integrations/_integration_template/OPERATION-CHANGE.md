# Карточка изменения операций

Короткая секция на пакет изменений/PR; отдельный файл не обязателен. Ссылаться на
contract/config/evidence владельцев, не копировать весь integration template
для расширения существующего provider. [Общий workflow](../../../docs/OPERATION-ONBOARDING-WORKFLOW.md).

| Обязательное поле | Значение изменения |
| --- | --- |
| Provider, цель и минимальный результат | Заполнить |
| Уровень завершения и target | Source-only / review activation / release в указанном контуре |
| Тип изменения и IDs | Client / поддержанный config / server code / credential / state; ссылки на contract delta |
| Actor, scope, effective policy | Изменения и ссылки на trusted composition/config; либо «без изменения» |
| Проверки результата | Применимые source/live/denial/ASK checks; уровень подтверждаемого эффекта |
| Blockers | Неизвестные обязательные inputs либо «нет»; отдельно ожидаемые LIVE-PENDING |

Ниже заполняется только то, что затронуто. Остальное переиспользуется из принятого
provider/deployment record со ссылкой; не требует повторного согласования.

| Условное поле | Значение изменения |
| --- | --- |
| Новый effect / approval path | Read/mutation отдельно от ALLOW/ASK; preview, retry/uncertain, actor-bound result contract |
| IDs/bindings/discovery | Реальные inputs и способ получить их; требования каждой capability независимо |
| Новые permissions / credential | Confirmed / owner action / LIVE-PENDING; Gateway-side reference без token; reload/restart semantics |
| Registration/result/preview wiring | Validators, intent builder, result projection/delivery, composition и owner strong approval |
| State/dependency/packaging | Inventory/migration, test collection, image allowlist; затронутые source/client/owner artifacts |
| Runtime activation | Public config и source/image/client versions, credential references, release/return inputs |
| Итог | Evidence links и source/image/config/live статус изменённых IDs отдельно |

Текущий runtime status принадлежит current-state документу. Карточка сохраняет
решения и исторический результат конкретного изменения. Source-only не требует
Windows run; отсутствие проверки нового чтения не блокирует mutation-only с
другим достаточным способом подтвердить согласованный результат.
