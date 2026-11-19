# Gateway image/config release

## UC-GW-005

**Когда:** принятый Gateway image/config нужно активировать в работающей
среде, в том числе когда есть ранее одобренные, но ещё не исполненные заявки.

**Цель:** установить только точную версию из принятого GitHub `main` с
защищённым release record, не исполнив повторно, не удалив и не
сфальсифицировав состояние незавершённых заявок.

**Как:** доставить PR/CI/owner merge и проверить точный source SHA по
[UC-CONT-002](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-002).
Если Windows — получатель controller source, сначала выполнить guarded Mirror
Pull; исходный GitHub/Docker merge сам по себе не обновляет Windows или Primary.
Для штатного owner-managed выпуска в **Windows PowerShell 5.1** использовать
существующий контроллер: **SelfTest → Check -Auto → отдельно подтверждённый
Apply -Auto → live owner/machine readback → Backup -Auto → Promote -Auto →
host docker inspect**. Полный порядок, вопросы подтверждения и STOP/Return —
только в [Primary runbook](../PRIMARY-GATEWAY-OPERATIONS.md#lightweight-owner-release-path-pr4b).
Перед Apply проверить доступность обязательных upstream для release-probes
из нужного сетевого контура, с действующими TLS/credential и scope.
`Check READY` подтверждает image/config/catalog, но **не** upstream READ.
Проверка не должна создавать новый Core-effect после Check и менять
зафиксированный request scope; недоступный обязательный upstream означает
STOP до остановки исходного Gateway.
ИИ не исполняет owner-команды за владельца.

**Что делает -Auto:** Check строит image и защищённый immutable
binding; Apply использует **тот же** image ID без повторной сборки.
Config/probes берутся из защищённого Complete record, Gateway READ
собирает исходные `UNCERTAIN/CLAIMED` scopes. Совместимый
контроллер проверяет допустимый append-only рост `UNCERTAIN` по
защищённому исходному снимку, audit и остальным данным, а не
автоматически доверяет Repo READ.
При `PENDING/DISPATCHED/APPROVED`, неполных данных, drift SHA/config/state
или отсутствии сохранённого previous image — STOP/owner review. Владелец
независимо подтверждает worker quiescence и отдельно даёт GO на Apply.
Ни inventory, ни исторический `CLAIMED`, ни успешный Check не доказывают
quiescence. `UNCERTAIN` нельзя повторно исполнять, очищать или подменять
доказательством отсутствующего эффекта; см. [UC-GW-009](incidents.md#uc-gw-009).
Ошибочный/неопределённый Apply не повторять: использовать исходный
protected attempt по [UC-GW-006](recovery.md#uc-gw-006).

**Сохранение `UNCERTAIN`:** штатный `Check -Auto → Apply -Auto`
использует [bounded append-only проверку](../UNCERTAIN-GROWTH-RELEASE-2026-11-17.md):
допустимые новые заявки добавляются к исходному защищённому набору;
старые заявки, audit и остальные данные остаются неизменными.
Флаг `-AllowUncertainGrowth` для `-Auto` **не передают** — его применяет
совместимый контроллер. Drift worker/receipts, `APPROVED` или старых
заявок остаётся STOP. Ручной проверенный Check/Apply допускает явный
`-AllowUncertainGrowth`; без него действует строгое сравнение.
Поддержку проверять по установленному source SHA, SelfTest и protected
Check record, а не по наличию кода в Git `main`.

Конкретные выпуски, SHA/image/backup и границы live-проверки принадлежат
[датированным evidence и current state](../guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md),
а не этому повторяемому UC.

**Ручные исключения:** когда `-Auto` не допускается по его предусловиям,
оператор использует отдельно проверенный полный контракт из runbook:
точные `-PreserveApprovedRequest`, `-PreserveClaimedJobs`,
`-PreserveUncertainRequests` и quiescence; затем Check `-Build`,
Apply с checkedImageId/checkedImageRecord **без** `-Build`.
Старый вариант Check `-Build` + Apply `-Build` собирает дважды.
Перенос `APPROVED` требует точного набора, отсутствия dispatch/job/receipt
и отдельного owner review. Исключения не отключают state admission,
previous-image retention, Backup/Promote и fail-closed recovery.

**Отдельные owner-opt-in mounts/identities:** если меняется состав
приватных mounts или machine grants, обычный `-Auto` не является
первичным разрешением на их включение. Для Publisher использовать
[защищённый owner mount-контракт](../P3-4-PUBLISHER-GATEWAY-MOUNT-RELEASE.md)
с ручным bound Check/Apply и независимой host-проверкой.
Source merge не создаёт credential/volume и не доказывает их установку;
доступный режим определяет точный установленный контроллер. Даже после
CI/merge controller fix остаётся source-only и не считается live до
отдельной owner-установки на Windows с exact SHA, PowerShell SelfTest
и защищённым Check/Apply; UC-GW-013 требует отдельного owner GO.

**Несколько чатов:** совместимые принятые PR могут входить в один
проверенный merged `main` SHA и один owner release.
Нельзя смешивать Docker images/SQLite/attempt records разных чатов.
Межчатовая автоматизация не заменяет единый owner release window и
live проверку защищённых pointers; развитие координации — в
[едином backlog](../BACKLOG-IMPROVEMENTS.md).

**Готово:** exact source SHA/image digest и protected Complete record;
owner `FORTIS_INTEGRATIONS_ACTIVATED`, отдельные успешные Backup/Promote,
host `running/healthy/unless-stopped`, и фактический Repo readback
включая необходимые live capabilities. Любая `APPROVED` переносится
без изменения state/audit; последующая отмена — отдельно владельцем.
Не считать `Apply` эквивалентом `Promote` или source commit —
обновлением работающего образа.

**Редкое исключение:** если старый immutable image отсутствует, обычный
UC-GW-005 останавливается. Допускается только явно owner-accepted
сценарий [UC-GW-013](recovery.md#uc-gw-013)
с точными rescue image/TAR, локальным offline smoke, protected Check
binding, новой проверкой source state и задокументированным **непроверенным**
restore. Согласие на пропуск изолированного restore не означает
возможность автоматически восстановиться. Нельзя обходить остановку
`RELEASE_PREVIOUS_IMAGE_MISSING` простым `-Image` или правкой records.
