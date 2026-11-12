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

**Однократная сборка (новый source-контракт, не live до owner release):**
после READY от Check -Build можно передать только точные checkedImageId и
owner-protected checkedImageRecord в Apply -Image <sha256:id>
-CheckedImageRecord <record> -SourceSha <merged-main-sha>, без -Build.
Оба этапа должны использовать идентичные config/probes, полные UUID scopes
и свежую owner quiescence attestation. Перед STOP_SOURCE контроллер повторно
сверяет защищённые records и SHA256 состояния, привязку образа и наличие
прежнего runtime image; после остановки старого writer повторяет проверку
неизменности receipt перед копированием состояния. При его отсутствии или неподтверждённом восстановлении
остаётся STOP. Путь не отменяет Backup/Promote и проверку Owner Shell.
См. [Primary runbook](../PRIMARY-GATEWAY-OPERATIONS.md).

**Несколько чатов:** если работы совместимы и PR приняты, можно включить
их в **один** проверенный source `main` SHA и **один логический релиз**
Gateway вместо релиза на каждый PR. Сводить Docker images или SQLite
разных чатов нельзя. **Важно:** действующий контроллер при
`Check -Build` и `Apply -Build` запускает Docker build **дважды**;
повторное использование кэша не является гарантией «build once».
Для настоящей однократной сборки нужен отдельный контракт
immutable image digest, связывающий Check, Apply и owner approval,
без отключения защищённого state admission. Общая Git/CI-доставка —
UC-CONT-002; межчатовый release coordinator ещё **не внедрён**.

**Готово:** exact source SHA/image digest и protected Complete record;
owner `FORTIS_INTEGRATIONS_ACTIVATED`, отдельные успешные Backup/Promote,
host `running/healthy/unless-stopped`, и фактический Repo readback
включая необходимые live capabilities. Любая `APPROVED` переносится
без изменения state/audit; последующая отмена — отдельно владельцем.
Не считать \`Apply\` эквивалентом \`Promote\` или source commit —
обновлением работающего образа.

**Редкое исключение:** если старый immutable image отсутствует, обычный
UC-GW-005 останавливается. Допускается только явно owner-accepted
сценарий [UC-GW-013](recovery.md#uc-gw-013--аварийный-image-release-при-отсутствии-прежнего-image)
с точными rescue image/TAR, локальным offline smoke, protected Check
binding, новой проверкой source state и задокументированным **непроверенным**
restore. Согласие на пропуск изолированного restore не означает
возможность автоматически восстановиться. Нельзя обходить остановку
`RELEASE_PREVIOUS_IMAGE_MISSING` простым `-Image` или правкой records.
