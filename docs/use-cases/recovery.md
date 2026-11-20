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


<a id="uc-gw-013"></a>

## UC-GW-013 — Аварийный image-release при отсутствии прежнего image

**Когда:** единственный активный здоровый Gateway имеет точный runtime
`source.runtime.image`, но команда Docker `image inspect` не находит
этот ID; прежний контейнер и его защищённые records сохранены. Владелец
осознанно решил **пропустить изолированное испытание восстановления**,
понимая возможность потери Gateway при сбое обновления.

**Цель:** разрешить *один* явно выбранный выпуск без ложного утверждения,
что старый image можно восстановить. Обычный путь UC-GW-005 остаётся
fail-closed; отсутствие старого image при обычных флагах — STOP.

**Как:** выполнить только нижеописанный guarded rescue image/TAR
preflight и отдельный owner-managed Check/Apply с точными SHA,
действующими credentials и защищёнными records; риск отсутствия
изолированного restore явно принимает владелец. Никакой auto retry.

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

**Допуск (owner-managed; контроллер на Windows должен соответствовать этому source):** `-Action Check
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

**SOURCE_ADMISSION при отсутствующем старом image (исправление UC-GW-013):**
обычный `Check -Build` останавливается с
`RELEASE_PREVIOUS_IMAGE_MISSING` **до выдачи READY**, если точный
старый image не доступен. В явно owner-accepted emergency после
проверок `Assert-Previous-Image-Retained` только два **offline
content-digest preflight** для томов Publisher и Machine PowerShell
могут выполняться в проверенном `EmergencyRescueImage`.
Для обоих сохраняются `--network none`, `--read-only`, `--pull never`,
UID 10001, readonly mounts и сравнение с исходными pinned digest.
Полный Docker metadata admission по-прежнему использует оригинальный
контейнер, его ID, provenance и исходный `source.runtime.image`.

Rescue image, архив SHA256, source backup receipt и offline smoke
перепроверяются **перед первым SOURCE_ADMISSION и повторно перед
STOP_SOURCE**; неизменяемые bindings/source receipts дополнительно
проверяются непосредственно до STOP и после него. Rescue не становится
production image, не подменяет $P.image в protected record и не
снимает Publisher/Machine-проверки. Если original image снова
доступен, emergency отклоняется `RELEASE_EMERGENCY_UNNECESSARY`.

**P4 инцидент 2026-11-19:** прежний image
`sha256:60febecf08f1aafabd7369914141b779250b786a74a1d21500c54cbdc0642fb3`
отсутствует. Старый `Check READY` был выдан до исправления
и НЕ подходит для нового release после source fix: нужны новый
Git commit, CI/owner merge, owner Windows exact-main update,
PowerShell 5.1 SelfTest и отдельный bound Check/Apply.
Старый rescue TAR от 2026-11-13 с несовпадающими image ID/RunId
не подходит. Новую owner-local rescue image/TAR допустимо
готовить только после исправления незащищённого ACL `GatewayRecovery`
(owner review, наследование выключено, без постороннего чтения).
При небезопасном ACL — STOP, не снимать защиту ради выпуска.
До аварийного Apply нельзя останавливать **старый** Gateway ради Backup,
когда прежний image отсутствует; после успешного Apply допускается
штатный Backup **новой кандидатной версии** с доступным новым image.
Наборы `15 UNCERTAIN`, `1 CLAIMED` и `2 APPROVED` требуют
отдельной owner-проверки exact preservation и worker quiescence;
новый P4 scope через `-Auto` запрещён.

**Завершение через Backup/Promote после успешного аварийного Apply:**
`Backup` относится уже к **новому** активированному Gateway с доступным
новым image, а не к остановленному старому экземпляру. Его
`primary-backup.json` указывает на новый backup, поэтому вызов
`Assert-Emergency-Rescue` из Check/Apply с этой записью был бы неверным:
он требовал историческую копию прежнего Gateway. Оригинальные backup
volume и owner-protected `primary-backup-<id>/record.json` сохраняются
отдельно; не заменять старый backup новым и не переписывать указатели.

Штатный `Promote -ConfirmWorkerQuiescent` после отдельного owner GO
сначала проверяет действующий Complete release, новую `primary-backup.json`
и точный receipt нового backup, running/healthy кандидат и единственного
writer. Если предыдущий image доступен по **оригинальному** ID,
проверка прежнего контейнера идёт обычным `Admit` без исключения.
Если original image отсутствует, аварийное продолжение разрешается
**только при всех условиях**:

- вызов `Promote` ручной, без `-Auto`, новых rescue/restore-флагов и
  `-Build`; владелец заново удостоверил отсутствие активной работы;
- неизменённая owner-protected запись **этого** Complete/activated/probed
  выпуска содержит `emergencyRecovery.ownerAcceptedUnverifiedRestore=true`,
  `isolatedRestoreTested=false` и точные `rescueImage`/`archiveSha256`;
- сохранённые в выпуске `source.path`, `source.hash` и вся предыдущая
  runtime identity совпадают с прежним `primary.json`, прежний original
  source record не изменился; old container имеет исходные ID/image,
  provenance, имя `fortis-gateway` и статус `exited`;
- существует как минимум один сохранённый owner-protected **исторический**
  `primary-backup-<id>/record.json` для того старого primary,
  привязанный к прежнему source/image/container/state, с совпадающим
  актуальным digest его backup volume. Текущий P4 backup проверяется
  штатным Promote **отдельно**;
- rescue image по точному SHA256 inspectable, архив в зафиксированном
  owner-local каталоге с закрытым ACL имеет прежний SHA256; повторно
  проходит offline smoke без сети и секретов.

Только после этих проверок старый контейнер проходит полный Docker
metadata admission под своим **исходным** image ID. Для двух offline
проверок Publisher/Machine PowerShell допускается проверенный rescue image,
но оригинальный image ID в records и ожидаемом runtime **не меняется**.
Все перечисленные проверки выполняются **до первого**
`docker rename`/`docker update` и изменения `primary.json`.
Любая ошибка означает STOP без начала переключения, не повод запускать
повторный Apply или редактировать protected pointers вручную.
Успешный Promote не подтверждает isolated restore, возврат
`Return-Source` не расширяется и DR не объявляется.

**Для будущих релизов:** это не новый обычный метод развёртывания из
`docker commit`. Допуск относится только к ранее принятому владельцем
UC-GW-013 и к единственному конкретному Complete release. После
его Promote последующие релизы снова используют UC-GW-005 и обязаны
иметь inspectable предыдущий image. Перед использованием доработанного
Promote обязательны CI, Windows PowerShell 5.1 parser/SelfTest, owner
exact-main update и отдельный owner GO на Promote; source-тесты не
заменяют изолированную проверку восстановления.

**Ограничение аварийного возврата:** `Return-Source` не получает
автоматического права применять rescue вместо original image.
Если после первого эффекта возврат не может пройти source admission,
переходить только в UC-GW-006 `RECOVERY_REQUIRED`.
`RESTORE_TESTED` и полноценную recovery-гарантию не заявлять.
Проверка source-тестами не заменяет owner Windows 5.1
parser/SelfTest и отдельный изолированный негативный missing-image test.

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
