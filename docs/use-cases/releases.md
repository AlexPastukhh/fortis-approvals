# Gateway image/config release

## UC-GW-005

**Когда:** принятый Gateway image/config нужно активировать в работающей
среде, в том числе когда есть ранее одобренные, но ещё не исполненные заявки.

**Цель:** установить только точную версию из принятого GitHub `main` с
защищённым release record, не исполнив повторно, не удалив и не
сфальсифицировав состояние незавершённых заявок.

**Как:** доставить PR/CI/owner merge и проверить точный source SHA по
[UC-CONT-002](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-002).
Выбрать [Docker preflight](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/docker.md#uc-cont-021),
[verified backup](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/docker.md#uc-cont-022)
и [операционный controller](../../fortis_approvals/deploy/README.md).
Проверить source/image digest, config, credentials, единственного writer,
protected record, Owner Portal и machine TLS/READ.

**Незавершённые состояния:** перед выпуском прочитать глобальный реестр
по [UC-GW-009](incidents.md#uc-gw-009). Если есть `APPROVED`,
указать *точный, явно рассмотренный владельцем* набор UUID через
`-PreserveApprovedRequest` (строка через запятую, не wildcard).
Выпуск разрешён только после независимого подтверждения отсутствия
активного старого worker и при обязательных preflight-проверках каждого
UUID: нет `DISPATCHED` в audit, результата, worker job или receipt;
набор равен всем текущим `APPROVED`. `PENDING/DISPATCHED` блокируют
state admission. Исторический `CLAIMED` сохранять своим точным
`-PreserveClaimedJobs` и quiescence attestation; это не Core approval.
`UNCERTAIN` и непроверенный внешний эффект не перезапускать и не
редактировать в SQLite. Точные аргументы, ограничения и восстановление —
в [Primary runbook](../PRIMARY-GATEWAY-OPERATIONS.md).

Owner выполняет `SelfTest → Check -Build → Apply -Build` по **одному**
проверенному merged `main` SHA, затем live machine/Owner readback,
`Backup -ConfirmWorkerQuiescent` и `Promote -ConfirmWorkerQuiescent`,
а также итоговый host `docker inspect`. `Apply` действительно
останавливает прежний Gateway и переносит state; `Check` лишь
проверяет, не обновляет контейнер. Ошибка/неизвестная фаза — STOP,
использовать original attempt record и UC-GW-006, не повторять Apply.
Исходный Gateway и backup сохраняются для контролируемого возврата.

**Несколько чатов:** если работы совместимы и PR приняты, можно включить
их в **один** source `main` и один build/image. Сводить Docker
image или SQLite разных чатов нельзя. Общая Git/CI-доставка —
UC-CONT-002; автоматический межчатовый coordinator пока
**не внедрён**, это отдельная задача.

**Готово:** exact source SHA/image digest и protected Complete record;
owner `FORTIS_INTEGRATIONS_ACTIVATED`, отдельные успешные Backup/Promote,
host `running/healthy/unless-stopped`, и фактический Repo readback
включая необходимые live capabilities. Любая `APPROVED` переносится
без изменения state/audit; последующая отмена — отдельно владельцем.
Не считать \`Apply\` эквивалентом \`Promote\` или source commit —
обновлением работающего образа.
