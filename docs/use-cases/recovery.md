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


## UC-GW-013 — Аварийный image-release при отсутствии прежнего image

**Когда:** единственный активный здоровый Gateway имеет точный runtime
`source.runtime.image`, но команда Docker `image inspect` не находит
этот ID; прежний контейнер и его защищённые records сохранены. Владелец
осознанно решил **пропустить изолированное испытание восстановления**,
понимая возможность потери Gateway при сбое обновления.

**Цель:** разрешить *один* явно выбранный выпуск без ложного утверждения,
что старый image можно восстановить. Обычный путь UC-GW-005 остаётся
fail-closed; отсутствие старого image при обычных флагах — STOP.

**Подготовка до допуска:** сохранённый аварийный `docker commit --pause=false`
от точно осмотренного running Gateway, отдельный `docker save` TAR;
полный SHA256 TAR и новый точный image ID; чтение OCI config и
SHA256 всех uncompressed layers, совпадение с Docker RootFS и публичной
конфигурацией, offline smoke без сети, секретов, volume и Owner Shell;
отдельная актуальная проверка healthy original runtime. Показания
проверок записать в owner-local evidence; не загружать TAR/секреты в Git.
Это **не** доказательство restore и **не** включает state volumes.
Проверить ранее существующий owner-protected `primary-backup.json`
и связанный backup volume/receipt; если нет надёжной копии state,
НЕ продолжать. Не вызывать `Backup` ради создания копии, когда
старый image отсутствует: Backup останавливает Gateway.

**Допуск (source-only до принятого PR/Windows Pull):** `-Action Check
-Build -SourceSha <merged-main>` с обычными public `-Config`,
`-Probes`, точными `-PreserveUncertainRequests` и
`-PreserveClaimedJobs`, текущими approved UUID (если есть),
`-ConfirmWorkerQuiescent` и требуемыми opt-in флагами;
дополнительно `-EmergencyRescueImage <full-sha256>`,
`-EmergencyRescueArchiveSha256 <64hex>` и
`-AcceptUnverifiedRestore`. Архив проверяется в фиксированном
owner-local пути `%LOCALAPPDATA%\Fortis\GatewayRecovery\fortis-gateway-rescue-<first-12-hex>.tar`,
без пользовательских URL/путей. Rescue image должен быть inspectable
по точному ID и пройти offline smoke *снова*. В Windows этот smoke
передаётся через штатный Base64-wrapper команды `python -c`:
`Private-Process` запрещает буквальные двойные кавычки в аргументе.
Ошибка `PILOT_NATIVE_ARGUMENT_DENIED` означает STOP/source fix, а не
проблему с сохранённым rescue image или разрешение обойти контроллер.
Если прежний image
появился, аварийный режим отказывается запускаться.
Стандартный Check выдаёт owner-protected `checkedImageId` и
`checkedImageRecord`.

`-Action Apply -Image <checkedImageId> -CheckedImageRecord
<checkedImageRecord> -SourceSha <merged-main>` получает те же
public config/probes, scopes, quiescence, opt-ins и три emergency
аргумента. Контроллер **не собирает повторно** новый образ в Apply.
Он перепроверяет runtime image, rescue image, SHA256 архива, offline
smoke, source state receipt, immutable bindings и отсутствие дрейфа
перед STOP_SOURCE. При рассогласовании — STOP. Не подставлять rescue
image вместо исходного в protected records и не считать его source
revision текущего merged main.

**Критический риск:** Apply всё ещё останавливает исходный writer,
копирует state и переключает контейнеры. `Return-Source` может суметь
запустить сохранённый контейнер, но при потере его layers/identity
не существует проверенного способа загрузить старый image. После
неуспешного Apply НЕ повторять действие и не реконструировать
request/audit/release pointers вручную. Сохранить original attempt
record и перейти в UC-GW-006 `RECOVERY_REQUIRED`.
Не считать восстановление проверенным. Аварийная запись
`emergencyRecovery.isolatedRestoreTested=false` в защищённом
release record означает, что риск принят, **не** что откат работает.

**После единственного owner-authorized Apply:** live host/image/config,
native/Core/Owner Shell, machine TLS и typed provider READ с негативными
тестами; отдельно штатные Backup/Promote с новым image, текущим
state/quiescence и retention. Если действие получилось ambiguous,
никакого replay/повторного Apply. Дальнейшие обычные релизы возвращаются
на UC-GW-005, где точный предыдущий image уже должен существовать.

**Готово:** единственный protected Complete release с явным
`ownerAcceptedUnverifiedRestore=true`, новыми full image/source SHA,
live provider readback и отдельно успешными Backup/Promote.
`RESTORE_TESTED` и `DISASTER_RECOVERY_VERIFIED` **НЕ** заявлять.
Другие чаты не наследуют согласие владельца на риск автоматически:
новое решение только для конкретного runtime/image/archive/выпуска.
