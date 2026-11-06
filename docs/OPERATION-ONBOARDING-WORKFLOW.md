# Добавление операций и подключений Gateway

Статус: предлагаемый общий процесс в task-ветке. Постоянная release automation
ниже ещё не реализована; доступность этого документа новым чатам через main
требует обычного review/merge и согласования с последними runtime/evidence docs.

Этот документ описывает общий workflow для новых операций любого provider. Он задаёт
порядок работы и критерий завершения. Контракты принадлежат provider packages,
текущий runtime — [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md),
результаты — dated evidence, отложенная автоматизация — implementation gaps ниже.
[Разбор задержек](audits/OPERATION-ROLLOUT-2026-11-06.md) объясняет основания.

## Вход нового чата

1. Прочитать этот workflow, Gateway agent guide и current state; проверить
   status/worktrees/branch и применимые AGENTS. Primary остаётся main.
2. Прочитать README/contract нужного provider и последнюю связанную evidence.
   Историю bootstrap читать только при реальной зависимости, а не для каждого
   нового operation. Существующие worktrees/изменения/retained records сохранять.
3. Зафиксировать ожидаемый уровень результата: source-only, активация в review
   или release в явно указанном контуре. Для source-only не требуются Windows
   deployment и live acceptance; pending live scope остаётся явным.
4. Заполнить короткую [change card](../fortis_approvals/integrations/_integration_template/OPERATION-CHANGE.md).
   Одна карточка/секция на пакет изменений, не на каждый метод. Допустима
   короткая секция в существующем provider README/evidence, без нового файла.
   Указать фактический scope, policies и blockers; переиспользовать уже известные
   настройки и решения владельца, не запрашивать их повторно.

Core, machine auth, owner WebAuthn, preview/approval/receipts и базовый ingress
переиспользуются. Наличие adapter не включает grants. Provider credentials
остаются в Gateway; новые API не реализуются через arbitrary URL/method proxy.

## Сначала классифицировать изменение

| Изменение | Что требуется | Image build |
| --- | --- | --- |
| Только Repo client для уже доступной Gateway operation | Client/source checks, обновление используемого client, live readback | Нет |
| Изменение поддерживаемых trusted config fields существующего кода | Проверенный config diff, upstream scopes, контролируемая активация и probes | Нет, только если нужный knob уже поддержан кодом. Startup config может требовать recreate/restart; hot reload не обещается |
| Новый schema/adapter/operation/registration/dependency | Код + config + tests + image packaging + release | Да |
| Новый provider credential/permission | Owner-controlled provisioning/permission grant на Gateway стороне | Только если меняется также код/зависимости; повторять enrollment на каждую operation не нужно |
| Новый durable state/schema/layout | Явный inventory/migration и проверка сохранности всей существующей state | По изменению кода; migration входит в подготовку release |

Для смешанного изменения применяются нужные строки. Если policy/grants заданы
Python composition или меняется схема config, это изменение кода с новым image,
даже когда операция уже реализована. Серверные настройки, Repo client и owner
launcher — разные артефакты: изменение host mount/launcher само по себе не всегда
требует пересборки Gateway, но требует admission/update record. Rotation может
требовать restart, если adapter кеширует credential; это устанавливается по коду.
Config-only не означает автоматический ALLOW или обход owner процедуры.

## Пять этапов одного изменения

| Этап | Работа в Repo / Gateway | Условие перехода |
| --- | --- | --- |
| 1. Определить результат и доступ | Минимальный полезный срез; реальные tenant/project/repo/workflow IDs; actor; ALLOW/ASK/DENY; upstream permissions; наличие credential на Gateway | Определены обязательные scopes и способ получить inputs. Неразрешённые обязательные config values — BLOCKED; проверки, возможные только после deploy, — LIVE-PENDING с явным планом |
| 2. Подготовить весь запрошенный срез | Contract/schema, adapter и bounded public result/errors, grants/policy wiring, typed client, preview/effect/idempotency/readback; provider README и image allowlist | Есть весь путь client → Gateway → provider → результат, включая activation config |
| 3. Подготовить проверенный release | Пропорциональные offline tests; imports/packaging; config validation; exact interpreters/argv; существующий state profile; CI/source identity; preflight/live-read plan | Готовы код, public config, credential references, grants diff, probes и возврат. Owner получает воспроизводимый candidate и заранее обозначенные live checks |
| 4. Выполнить owner update/activation | Один поддерживаемый entrypoint: проверить exact target/image/config/credential availability, transport/imports и применимые существующие reads до stop; сохранить state; применить проверенные inputs; health + feature probes | Owner-reviewed activation; failure до stop ничего не переключает; startup failure сохраняет artifacts и возвращает допустимый предыдущий runtime |
| 5. Принять запрошенный результат | Проверки соответствуют source-only / runtime activation и изменённым IDs; owner решает применимые ASK tests; evidence/current state отражают проверенные факты | Source-only завершается source evidence. Активация завершается ожидаемой доступностью или запретом и подтверждённым уровнем эффекта. IMAGE_UPDATE_PASS отдельно от feature acceptance |

Capabilities активируются независимо: Sonar-only read, CI inspection и общий
correlated report могут иметь разные необходимые inputs. Нельзя навязывать
одной operation credentials/bindings другого provider, если сама operation от
них не зависит. Общий report остаётся недоступен до проверки его связей.
Недостающий ID получают через минимальную разрешённую discovery operation;
фиктивные IDs и обход Gateway не используются для снятия config block.

Live-проверку нового provider нельзя требовать до появления работающего candidate.
Обязательные значения config должны быть реальными до activation; при этом
проверки новых response shapes/permissions могут оставаться LIVE-PENDING до
первого ограниченного live запуска. Заранее фиксируются требуемые права и
способ их проверки. Если read-only probe невозможен, используется отдельно
одобренный sandbox/ASK test; UNKNOWN не превращается в «права проверены».

Credential creation и существенное расширение upstream прав могут потребовать
отдельного owner действия на этапе 1. Это реальная зависимость, её показывают
до команды release. Время неизвестной provider настройки нельзя обещать как
обычное добавление метода в уже работающий adapter.

Read/mutation и ALLOW/ASK — разные решения. Чувствительное чтение тоже может
требовать ASK, а обычная разрешённая запись — ALLOW по согласованному контракту.
Текущий immediate read ingress сам approval не ставит: approval-bound чтение
нужно явно оформить typed operation через Core/approval lifecycle, даже если
provider HTTP method — GET. Одной пометки ASK у immediate read недостаточно.
Нужен также actor-authorized bounded result contract для approved чтения:
обычный status сейчас отдаёт лишь requestId/state, а native result допускает
только workspace/github. Для нового service эта часть требует явного server /
client wiring; возвращать raw Core snapshots/result вместо projection нельзя.

Для первого ASK family нужны понятный preview, Reject без dispatch, Approve с
проверенным эффектом и replay/stale/uncertain behavior. После появления общего
проверенного механизма не требуется заново разрабатывать owner UI/очередь или
повторять весь bootstrap при добавлении однотипного метода. Одобрение набора
новых permissions при выпуске не заменяет ASK для конкретного runtime эффекта.

## Что проверяется до Windows handoff

- Schema/target/policy denial paths и response projection; для ASK — preview,
  stable request ID, Reject/Approve, stale preconditions и отсутствие слепого
  повтора UNCERTAIN. Использовать общие fixtures для повторяемой механики.
- Contract IDs, validators, trusted intent building, bounded result projection,
  adapter/composition, owner preview/strong approval, client, grants/policies,
  test collection и Docker allowlist согласованы. Новый provider сейчас требует
  изменений shared wiring: папка и один adapter сами его не регистрируют.
- Проверяются actual client/probe source и protocol expectations, а не только
  import старого клиента. Версии Repo client, Gateway source/image и public
  config отмечаются отдельно; неизвестный runtime profile не объявляется ready.
- В image и Repo используются их реальные interpreters и cwd/import contract.
  Общий transport/import/regression probe запускается до остановки источника
  и после запуска замены. Новая ещё не установленная operation проверяется
  после candidate activation; preflight не требует её успеха на старом runtime.
- Обязательный config полон, валидирован целевым кодом, не содержит фиктивных IDs/секретов.
  Provider discovery выполняется разрешёнными Gateway reads. Недостающая discovery
  operation — явный blocker/отдельный минимальный slice, а не обход через connector/helper.
- State inventory учитывает Core/owner DB, native tasks/jobs/artifacts и provider
  receipt stores. Credential mounts отделены от копируемой state; transient auth
  files/journals/unfinished effects блокируют unsafe snapshot.

Применяется [validation policy](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/VALIDATION-POLICY.md):
local deterministic checks по изменению, без тяжёлой имитации Windows/Docker.
Host/credentials/WebAuthn/provider checks остаются реальными owner/live checks.
Один запуск группы независимых проверок предпочтительнее множества RPC/polls;
повторять полный suite после каждого docs-only исправления не требуется.

## Один owner entrypoint и критерий Done

Routine release должен потреблять проверенный набор inputs: source SHA, image
identity/revision, config digest, operation/grant diff, exact target/state profile,
credential references, probes и return record. Runtime/profile/config меняются
контролируемо, без копирования secrets в Repo или чат. Повторный вызов продолжает
тот же record/процедуру, а не создаёт вслепую ещё один container/volume.
Возврат после начала пользовательской работы с новой state требует отдельного
рассмотрения её effects/receipts; startup return не означает произвольный rollback.

Владелец получает короткое описание эффекта, один подготовленный запуск и ожидаемые
маркеры. AI выполняет доступную подготовку сам. Read-only preflight/health/client
checks не требуют ручного копирования десятков команд. Реальные ASK decisions и
новые permissions остаются явными owner действиями в согласованном scope.

Завершение различает source checked, image built, profile configured и operations
live verified. Если целью была активация, новый image с disabled profile —
промежуточный результат. Не нужно добавлять новый read или лишнее permission
только ради универсального acceptance checklist.

| Изменение | Достаточный вид проверки в согласованном scope |
| --- | --- |
| Client-only | Проверка нового client поведения на существующем server contract; без обязательного deploy |
| Read-only activation | Применимые новые reads, scope/projection и ожидаемые denial paths; ASK тесты только если менялся этот путь |
| Mutation-only activation | Изменённый action contract, нужный ASK family и существующий read/status либо проверяемый provider receipt |
| Config narrowing / DENY | Требуемые запреты действительно действуют; несвязанный доступ не расширен |
| ASK reading | Reject без provider read, Approve и безопасная выдача разрешённого результата только этому actor/request |
| Source-only | Source checks/CI и явная отметка, что runtime activation не запрашивалась/не проверена |

HTTP 202/accepted receipt доказывает принятие запроса на стороне provider,
не завершение внешнего процесса. Уровень результата определяется контрактом.
Для каждого изменённого ID отмечается source/live/pending; один probe общей
семьи не объявляет все operations live-verified. Общие Core/approval гарантии
переиспользуются, а непроверенные provider semantics остаются pending.

## Что уже есть и что ещё нужно автоматизировать

Существуют Core/typed transport, provider template, closed contracts, native Git
workflow, suite/manifests и опыт owner-run update. Принятый
[updater v3](https://github.com/AlexPastukhh/fortis-approvals/blob/143f944a67b3532eae5a2402fd51560cca091b16/fortis_approvals/deploy/Update-NativeReview.ps1)
ограничен конкретными source/image/records и не является универсальным release
runner для следующего provider. Ниже — приоритет реализации, не готовые команды:

1. Независимая activation config для capability групп и явные точки provider
   registration/result delivery. Текущий analysis-review profile связывает
   Sonar и GitHub; это отдельный source gap, не только недостающий config.
2. Постоянный release runner с data-driven inputs, поддерживаемым state inventory,
   preflight before stop, durable steps/resume и проверками именно новых operations.
   Добавление provider не должно переписывать механизм cutover/backup.
3. Проверка согласованности contract/adapter/client/grant/policy/test collection/image и actor-safe
   runtime capabilities: implemented/granted/policy/scope/config version и readiness
   без secret values. Опирается на фактические registry/config, не второй ручной каталог.
4. Release report с длительностями этапов и раздельным owner/CI/provider wait,
   attempts/failureStep; reusable fixtures и scaffolding по реальному повторению.

После review/merge документации новые чаты следуют пяти этапам, используют
существующие проверенные tools и явно называют недостающие части. Этот документ
сам не внедряет hot reload, installer, config editor или новое разрешение.
