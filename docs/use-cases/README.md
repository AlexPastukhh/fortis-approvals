# Fortis Gateway — локальный реестр Use Cases

Статус: `ACTIVE` как проектный каталог сценариев, но сам файл начинает действовать
в принятом `main`; до merge используется изолированная task branch. Состояние
работающего Primary нельзя определять из commit — проверить
[Current State](../guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) и live API.

**Сначала** [главный реестр Fortis](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/README.md):
обязательное чтение [UC-CONT-002 — доставка](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-002)
и [UC-CONT-003 — GitHub через Gateway](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-003),
без просмотра всех UC. Репозиторий выбирается по исходной задаче; см.
[UC-CONT-001](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/orientation.md#uc-cont-001).

Этот локальный реестр — карта целей Gateway. **Реализация, policies, exact CLI
и source paths остаются в документах-владельцах и исходниках**; не повторять их здесь.

| ID | Когда / ситуация | Ожидаемый результат | Owner |
| --- | --- | --- | --- |
| UC-GW-001 | Прочитать Sonar quality/issues для нужного context | Разрешённый READ и доказуемая привязка | [Sonar](sonar.md#uc-gw-001) |
| UC-GW-002 | Подключить provider | Принятый typed provider/catalog | [Integration](integrations.md#uc-gw-002) |
| UC-GW-003 | Расширить операцию | Schema/policy/handler/receipt приняты | [Integration](integrations.md#uc-gw-003) |
| UC-GW-004 | Добавить/сменить credentials | Защищённый credential и readback | [Credentials](credential-lifecycle.md#uc-gw-004) |
| UC-GW-005 | Обновить image/config | Принятая активация с receipt | [Release](releases.md#uc-gw-005) |
| UC-GW-006 | Возобновить неудачное обновление | Reconciled state без двойного эффекта | [Recovery](recovery.md#uc-gw-006) |
| UC-GW-007 | Primary / автозапуск / сохранённый Legacy | Healthy Primary, проверенный backup | [Primary](primary.md#uc-gw-007) |

Gateway-specific задачи, не являющиеся самостоятельной повторяемой операцией,
описывать в [technical docs map](../README.md) и [package source map](../../fortis_approvals/README.md).
[Создание UC / DRY](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/orientation.md#uc-cont-024)
не означает автоматического создания нового реестра в любом репозитории.
