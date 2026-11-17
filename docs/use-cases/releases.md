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
ИИ не исполняет эти owner-команды за владельца.

**Что делает -Auto:** Check строит один проверенный image и сохраняет
owner-protected binding; Apply использует **тот же** immutable image ID, без
повторной сборки. Публичные config/probes берутся из существующего protected
Complete record; Gateway READ собирает точные `UNCERTAIN/CLAIMED` scopes.
При `PENDING/DISPATCHED/APPROVED`, неполных данных, drift SHA/config/state
или отсутствии сохранённого previous image — STOP/owner review. Владелец
независимо подтверждает worker quiescence и отдельно даёт GO на Apply.
Ни inventory, ни исторический `CLAIMED`, ни успешный Check не доказывают
quiescence. `UNCERTAIN` нельзя повторно исполнять, очищать или подменять
доказательством отсутствующего эффекта; см. [UC-GW-009](incidents.md#uc-gw-009).
Ошибочный/неопределённый Apply не повторять: использовать исходный
protected attempt по [UC-GW-006](recovery.md#uc-gw-006).

**Состояние:** owner-reported `SelfTest`, `Check -Auto READY`,
`FORTIS_INTEGRATIONS_ACTIVATED`, `FORTIS_PRIMARY_BACKUP_PASS` и
`FORTIS_PRIMARY_PROMOTED` для PR #94 / source
`c473edb88737f773d2f9ec0a9943235ebb18aa3a` (2026-11-14).
Real sourceReceipt из 260 хешей прошёл serialization preflight; Repo
machine READ после Promote отвечает. Это **не** заменяет независимый
host `docker inspect` после Promote, реальный Docker Desktop restart,
WebAuthn browser acceptance или provider mutation acceptance. Датированная
и текущая evidence — в [current state](../guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md);
подробные защищённые записи остаются у владельца.

**Опциональное расширение UNCERTAIN (source candidate, ещё не установлено):**
[контракт append-only Check/Apply](../UNCERTAIN-GROWTH-RELEASE-2026-11-17.md)
допускает только новые записи Core UNCERTAIN с неизменными старыми SQL-строками,
audit и всеми остальными файлами состояния. Режим — только вручную с
`-AllowUncertainGrowth`, проверкой владельца и окончательной сверкой после
остановки Gateway. При изменении worker, receipts или APPROVED — STOP.
Без флага прежний строгий Check/Apply не меняется.

**Ручные исключения:** когда `-Auto` не допускается по его предусловиям,
оператор использует отдельно проверенный полный контракт из runbook:
точные `-PreserveApprovedRequest`, `-PreserveClaimedJobs`,
`-PreserveUncertainRequests` и quiescence; затем Check `-Build`,
Apply с checkedImageId/checkedImageRecord **без** `-Build`.
Старый вариант Check `-Build` + Apply `-Build` собирает дважды.
Перенос `APPROVED` требует точного набора, отсутствия dispatch/job/receipt
и отдельного owner review. Исключения не отключают state admission,
previous-image retention, Backup/Promote и fail-closed recovery.

**P3.4 Publisher (только source candidate):** отдельный защищённый
[volume-opt-in контракт](../P3-4-PUBLISHER-GATEWAY-MOUNT-RELEASE.md)
предусматривает вручную подтверждённый owner Check -Build и связанный
Apply -CheckedImageRecord с одним уже подготовленным приватным volume.
Обычный -Auto не умеет впервые включать отдельный publisher machine grant.
Никакая публикация исходников не создаёт секреты и не доказывает
фактический Docker mount; без отдельного owner release Publisher выключен.

**Несколько чатов:** совместимые принятые PR можно включить в один
проверенный merged `main` SHA и один логический owner release;
смешивать Docker images/SQLite разных чатов нельзя. Межчатовый
release coordinator не внедрён; см. [единый backlog](../BACKLOG-IMPROVEMENTS.md).

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
