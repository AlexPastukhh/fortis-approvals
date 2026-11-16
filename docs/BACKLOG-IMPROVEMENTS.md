# Backlog улучшений — Fortis Approvals Gateway

Исходный план согласован 2026-11-06 после native Git/worktree live цикла;
статусы актуализированы 2026-11-10 после установленного Primary, Repo machine
readback и принятого source. [Current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
фиксирует подтверждённый релиз и ограничения; этот backlog хранит
**открытые улучшения и явно помеченный исторический контекст**, не разрешает
новых runtime операций.
Общий Fortis backlog принадлежит `fortis-container`; вход — через
реестр юзкейсов в `/workspace/repo/README.md`. Наличие GitHub remote в этом repo
не означает допуск к нему действующего Gateway (UC-CONT-018).
Это **единственный backlog этого репозитория**. Пункты здесь не разрешают менять Production. Общее Docker, Tunnel, Windows/Mirror и multi-agent направление принадлежат своим репозиториям; здесь только Gateway-specific задачи. Принятый результат и техническая история остаются в датированных evidence и source runbooks.

## Mirror unified API — P0 security/contract review (2026-11-15)

[P0 Mirror contract][mirror-unified] — PROPOSED; accepted provider остаётся
только strict READ v1. Новое дополнение UC-GW-012 не регистрирует capabilities.

- До P1: owner review узкого делегирования UC-CONT-003 и модели B; отдельный
  security review signing-key lifecycle, trusted execute-only signer и pinned
  verifier. Core policy toggles и новый vault/release controller не требуются.
- P3: closed v2 READ без изменения v1; provider/transport/actor/target/negative
  tests, source PR/CI и отдельные Windows/Gateway owner releases/live probes.
- P4: preview/ASK/lookup и signed exact UUID/repo/SHA dispatch, deny legacy
  Bearer-only POST, shared durable receipt и timeout/replay/denial acceptance.
- Own-API toolkit: отдельный effect manifest и one-shot ASK journal/driver,
  профильные read-only Doctor probes; V1 GET/READ/ALLOW checker не ослаблять.
  Второй реальный Docker API нужен для generic reproducibility, не Mirror P3.
- Согласовать пересечение с открытым PR #87 перед merge: его Windows-only
  discovery — отдельный scope; GitHub-источник для нового Mirror Pull по
  этому ТЗ — Windows owner-managed reader, без Gateway GitHub fallback.
  Не переписывать чужую ветку и не выдавать PR #87 за accepted policy/runtime.
- P5 cutover/rollback/port/DB и все live gates остаются owner-controlled;
  source contract, installed Windows, Gateway image и real ASK — разные факты.

[mirror-unified]: https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/MIRROR_API_CONTRACT_V1.md

## Release Labels / GitHub Projects — Gateway typed API (2026-11-11)

**Status: SOURCE CANDIDATE, НЕ УСТАНОВЛЕНО.** По запросу владельца
расширяется native GitHub provider без generic HTTP/GraphQL proxy.
Предлагается READ `list_repository_labels`, `list_pr_labels`,
`get_pr_release_label_context` и owner ASK `create_release_label`,
`add_pr_release_labels`, `remove_pr_release_label`.
Контракт/Use Case: [UC-GW-011](use-cases/integrations.md#uc-gw-011).
Реализация/валидации живут в одном GitHub provider, политики — в
native `workflow/runtime.py`; описание не дублирует полный контракт.

**Незакрытые gates:** source tests/CI, Owner Merge, Primary image
UC-GW-005, live capabilities + реальный scope/readback и negative
actor/repository tests. Привилегированный автоматический publisher
остаётся выключенным до отдельной trusted CI admission, no-PR-code
review, race/UNCERTAIN E2E и owner принятия. GitHub Projects V2 —
следующая типизированная операция только после проверки owner Project
ID и GraphQL token scope; **никаких живых Project writes сейчас**.
Нормативный Release Planning контракт один —
`fortis-container/docs/RELEASE-PLANNING-CONTRACT.md`.

## P0 — Подключение собственных API через Gateway: ПЕРВОЕ В ОЧЕРЕДИ (2026-11-10)

**Статус:** PLANNED / TOP PRIORITY. **Рабочий подробный план:**
[Fortis → API: onboarding, UC, безопасность, автоматизация](/workspace/repo/Workfiles/fortis-api-onboarding-priority-20261110/PLAN.md)
(локальный Workfiles в постоянном Fortis workspace; путь не является GitHub-ссылкой).

**Предварительное блокирующее улучшение (2026-11-11, SOURCE CANDIDATE):**
добавить типизированную операцию github.update_pull_request для изменения только
описания уже открытого PR через Gateway. Цель — не требовать от владельца
ручного GitHub UI Edit при исправлении PR Release Impact. Операция имеет
отдельную политику ASK, точные PR/HEAD/task/repo, проверку исходного описания,
readback и receipt; не даёт права менять код, ветки, title или merge.
Пока изменение не прошло source PR/CI, owner merge и отдельный Gateway release,
в живом Gateway метод **недоступен**. Не использовать GitHub-коннектор в обход.

**Цель:** сделать подключение собственного API через существующие typed Gateway
extensions повторяемым: проверка совместимости транспорта, контракт операций,
actor/target/policy, credential lifecycle, idempotency/receipts, тесты, штатный
PR/CI/owner release и независимая live приёмка. Не строить новый универсальный
HTTP/PowerShell канал и второй Docker/release controller.

**Очередность внутри P0:** актуализировать устаревшие статусы Gateway/PS-V1
по owner evidence; уточнить действующий [UC-GW-002](use-cases/integrations.md#uc-gw-002)
без дублирования технического owner; выбрать один безопасный реальный API,
провести intake/transport-fit и typed provider; пройти CI, owner-managed install
и live readback; только по результатам пилота решить, какие onboarding checks
имеет смысл автоматизировать. Пока API не выбран, возможна документационная
часть; нельзя объявлять интеграцию готовой или изменять runtime.

**Направление «внешнее приложение → Fortis Gateway»:**
**ACKNOWLEDGED — DEFERRED**, не входит в P0, не требует нового route, actor/grant
или отдельного UC сейчас. При подтверждённом запросе использовать
[UC-CONT-008](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/authorization.md#uc-cont-008).

**Граница:** первенство в backlog не является разрешением на production-изменения:
owner credentials и WebAuthn, live release admission, backup/rollback,
сохранение UNCERTAIN/CLAIMED и stop-on-unknown остаются обязательными.

## UNCERTAIN: административно закрыты; расследование и worker остаются (2026-11-09)

**Установлено:** после PR #37/#38/#39, на owner-confirmed Primary с image
source `a200137775eb6c6b8dcec81f31206b0d481d9003`,
`WorkflowClient.details(UUID)` возвращает actor-owned полную заявку,
preview/audit/worker/receipt только для чтения. Owner Portal получил
`Закрыть заявку` через действующую owner-сессию и CSRF без второй
WebAuthn-проверки, backup ID, пояснения или требования `worker=FAILED`.
Это административное `UNCERTAIN → CLOSED_UNCONFIRMED`, **не** утверждение,
что исходная Git/GitHub-операция была или не была исполнена. См.
[UC-GW-009](use-cases/incidents.md#uc-gw-009) и
[текущее состояние](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).

**Live readback 2026-11-09:** все шесть исторических UUID теперь
`CLOSED_UNCONFIRMED` — `18af495b…`, `35ac68df…`, `31e8f60b…`,
`7b2ea090…`, `2df32a24…`, `ee9c5e73…`. Оригинальный
`REMOTE_OUTCOME_UNCONFIRMED` остался в failure; три native jobs `FAILED`,
у двух GitHub push нет native job. Отдельно критично: у
`2df32a24-efb1-4dac-97f6-3b66147d8944` (`workspace.create_task`)
native worker job **всё ещё `CLAIMED`** без локального receipt.
Закрытие Core **не** завершает, не отменяет и не повторяет worker job.
При последующих release/backup сохранять exact protected scope,
owner-attested worker quiescence и проверенный closure audit.
Не удалять claim, не переписывать SQLite и не подделывать receipt.

**LIVE ACCEPTED 2026-11-10:** PR #52 слит, CI success, общий source
`9481699faaa297d8ec1fb45b4f14be50ae17406f` установлен владельцем через
Check / Apply / Backup / Promote. Repo machine readback проверил
`incidentInventory.readOnly=true`, `list_uncertain.total=3`, три исходных UUID,
диагностику `details(UUID)` и неизменность исторического `CLAIMED`.
Изображение: `sha256:f8fc333be0f1201441088b8386cb2cc409a3a390eb5fd8aef2f76c70032d02d8`.
Backup: `fortis-gateway-backup-4b27b6c67d7740aea1c9310efd0be478`.
См. [исследование](../fortis_approvals/evidence/UNCERTAIN-DIAGNOSTIC-INVESTIGATION-20261110.md).
Функция классифицирует стадии, но не устанавливает исходный эффект.

**SOURCE MERGED; READ-ONLY LIVE OBSERVED (2026-11-10):** PR #54 принят в
`main`, а authenticated Repo увидел live `workerActivity.readOnly=true` и
успешно вызвал bounded `activity()`. Источник новых кодов исключений,
heartbeat semantics и запреты описаны в
[контракте](../fortis_approvals/evidence/WORKER-OBSERVABILITY-20261110.md)
и [UC-GW-010](use-cases/incidents.md#uc-gw-010). **Не подтверждены:** точная
post-merge Windows image/release identity и полный end-to-end тест heartbeat/
error code на новом worker failure. Нельзя называть это завершённой live
приёмкой или доказательством quiescence. Старая `CLAIMED` не получает
задним числом heartbeat. `-ConfirmWorkerQuiescent` и protected scope нужны по-прежнему.

**Открытые задачи:** определить причины потери acknowledgement и появления
`UNCERTAIN` между Gateway/worker/provider; связать каждый исторический
эффект с доказательствами его конкретного UUID (позднее похожее действие
не доказывает первоначальное); улучшить безопасные worker receipts/journals
и диагностику ошибок; отдельно оценить обнаружение активного executor
вместо одного `-ConfirmWorkerQuiescent` (это owner attestation),
обработку осиротевшего `CLAIMED` и UI acceptance.
`CLOSED_UNCONFIRMED` не означает завершённого технического расследования.
Код и WebAuthn тесты для кнопки пройдены; переходы в Core прочитаны live,
но **ручная проверка конкретного browser click** отдельно не документирована.

## Owner Portal: защищённая отмена APPROVED и пассивная автопроверка — image установлен

**Установлено на Primary 2026-11-10:** PR #62 / merged `main`
`8403c63297f78e38294899c6bd094cc9f9eac66f`. Owner
`Check READY → Apply ACTIVE → Backup PASS → Promote PASS` и host
`running/healthy/unless-stopped`; Repo подтвердил глобальный read-only
API и полные карточки 2 `APPROVED` без исполнения/изменения состояния.
Owner-only guarded `APPROVED → CANCELLED_BEFORE_DISPATCH` доступен
в новом образе: Core writer lock, проверка отсутствия `DISPATCHED`
в audit и worker job, owner session/CSRF; никакой новой подписи за ИИ.
Отдельный owner-only пассивный `incidents/assess`
не выполняет операцию и не делает reconcile/auto-resubmit.

**Не подтверждено отдельно:** нажатие реальной кнопки cancel/assess
в браузере владельца после PR #62, второй machine grant на чтение
чужой карточки, autostart после Docker Desktop restart. Исторические
`CLAIMED`/`CLOSED_UNCONFIRMED` нельзя автоматически считать
исполненными/неисполненными. Глобальная `list_requests` включает
`PENDING` вместе с `APPROVED/DISPATCHED/UNCERTAIN`, а раздел
«Требуют разбора» включает только последние три. Значения и разрешения
зафиксированы в [UC-GW-009](use-cases/incidents.md#uc-gw-009).

**Дальнейшая автоматизация (OPEN, отдельные PR):** реестр независимых
readback-верификаторов для *конкретных* typed операций с bounded запросами
и привязкой к requestId, target, expected/new SHA и неизменяемым receipts:
`workspace.create_task/edit/stage/commit/update_main_from_pr`, GitHub
`push_commits/create_pull_request`, Sonar provider effects, Windows owner
PowerShell и Docker image/record pointer. Для GitHub отсутствие ветки или PR
в текущем состоянии **не доказывает**, что исходная операция никогда не
была выполнена; там нужны provider audit/receipt и защита от позднего эффекта.
Автоматический статус может быть `EXECUTED_PROVEN`,
`NON_EXECUTION_PROVEN`, `UNKNOWN` или `MANUAL_REVIEW`, но не
псевдоподтверждение по эвристике. Не делать auto-resubmit до отдельной
проверки безопасности, owner approval policy и тестов race/timeout/lost ACK.
Расследование редких неизвестных исходов остаётся у ИИ по UC-GW-009.

<a id="powershell-plan"></a>

## PowerShell — единый план первой версии для Repo AI и будущих улучшений

**Порядок уточнён:** сначала самостоятельный `fortis-powershell-executor`,
затем machine ASK и настраиваемые ограничения. Перенос принят в план,
source-пакет и изменения Script Center подготовлены; bootstrap нового repo
и Windows cutover ещё не пройдены.

Актуализировано **2026-11-17** по исходникам, истории и решениям владельца
в текущей задаче. Это **план**, не новая machine capability и не разрешение
активировать Windows/Gateway. Выполнение из Repo пока не реализовано.

### Согласованная цель и граница версии

**Первая версия для ИИ:** Fortis Repo отправляет точную одноразовую PowerShell
команду через typed Gateway; допустимая команда **всегда ASK**, включая
`Get-Date`. Владелец видит полный текст и target в Owner Portal и подтверждает
конкретный запуск через WebAuthn. Только после этого работает Windows Executor;
ИИ получает связанный с заявкой результат. Автоматического ALLOW для исполнения
нет, в том числе у «безопасных» команд и при повторном запуске того же текста.

**Ограничения редактирует владелец в настройках.** Разрешённые/запрещённые
команды и параметры — данные versioned policy, а не зашитый в код список.
Допущенная правилами команда идёт в ASK; запрещённая или непонятная — DENY.
ASK не отменяет ограничения. ИИ не меняет правила и не выбирает себе policy.

| Название | Смысл и статус |
| --- | --- |
| OwnerShell baseline, исторические `PS-V1-01…10` | Уже реализованный owner-only Portal → Windows one-shot; один функциональный запуск подтверждён, полная security/recovery acceptance открыта |
| Repo AI V1, новые `PS-AI-V1-01…10` | Планируемая первая версия доступа ИИ: ASK для каждого запуска + настройки ограничений + проверяемый dispatch/receipt |
| После Repo AI V1 | Расширение языка/изоляции, Analyzer, сервисный запуск и удобство; отдельная приёмка |

Историческое «policy engine после V1» относилось к **OwnerShell baseline**.
Для новой Repo AI V1 настраиваемые ограничения входят в обязательный scope.
Существующий ручной owner-only режим не становится machine API по этому плану.
Если позже ручной ввод переведут на общий ASK-путь, это отдельное явно
описанное изменение UX/контракта; текущую сессию владельца ИИ не использует.

### Подтверждённая основа и открытые проверки

| Часть | Подтверждение | Что это не доказывает |
| --- | --- | --- |
| Portal и Windows Executor source | Approvals PR #35; Mirror PR #9; текущие `owner_shell_portal.py`, `owner_shell.py` | Наличие машинного ASK или policy editor |
| mTLS/Bearer и guarded Gateway opt-in | Owner-reported PS-V1-06/08/09, 2026-11-10; Approvals PR #53 | Свежую идентичность/настройки работающего Windows процесса |
| Первый запуск | PS-V1-10: `Get-Date`, `EXECUTED`, exit 0; [датированное evidence](../fortis_approvals/evidence/OWNER-SHELL-RELEASE-AND-GET-DATE-20261110.md) | Полную session/Origin/CSRF, replay и restart acceptance |
| Durable SQLite UUID/command digest | Исходник Executor и offline tests | Проверку сохранности на реальном Windows после restart |
| Запуск через Script Center | [Owner launch/setup runbook][ps-script-center]: отдельное окно, форма путей, ACL, существующая DB, non-admin, loopback | Service/autostart или owner-host acceptance только по source |
| Лимиты baseline | 8 KiB команды, 60 с, 64 KiB каждого stdout/stderr, one-shot PS 5.1 | Настройки ограничений команд, sandbox или Analyzer |

Последние Gateway image/host факты остаются в [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md);
исторический image и один `Get-Date` не переобъявляются текущим runtime.
Свежий read-only workspace capabilities в этой задаче не содержал PowerShell
операции; отсутствие её в этом каталоге само по себе не полный аудит всех ingress.

### Ответственность и подключение собственного API

| Владелец | Ответственность |
| --- | --- |
| `fortis-approvals` | Typed machine API/client, Core ASK/WebAuthn, policy editor и версии, preview, transport, общий audit/receipt readback |
| `fortis-powershell-executor` (планируемый repo) | Windows Executor, launcher, tests/CI, API, process/identity и durable receipt DB; до завершения переноса действующий source находится в `docke-windows-mirror` |
| `script-control-center` | Удобный owner-controlled запуск и настройки путей; не второй executor, policy store или approval queue |
| `fortis-container` / `tunnel` | Общая изоляция Repo и worker/Guard boundaries; отдельный будущий container-control broker |

Это направление **Fortis → собственный Windows API** по
[UC-GW-012](use-cases/own-api.md#uc-gw-012) и
[UC-GW-002/003](use-cases/integrations.md#uc-gw-002).
Текущий onboarding V1 GET/READ/ALLOW и его manifest checker **не покрывают**
PowerShell POST/ASK/execute. Нужен reviewed effect-профиль и transport
существующего mTLS/10443; нельзя выдавать этот endpoint за обычный HTTPS/443 READ.
Переиспользуются Core, owner identity, grants, очередь и release controller;
новые Core, vault, worker/receipt store ради второго клиента не создаются.
Совместимость нового ledger с существующими UUID должна быть описана отдельно.

**Независимость от зеркалирования:** рабочая схема — Repo AI → Gateway с ASK →
Windows PowerShell Executor. Browser Mirror, Mirror API и Git Pull в ней не
участвуют. Название `docke-windows-mirror` здесь обозначает только нынешний
репозиторий исходников Executor, не зависимость от функций зеркалирования.

### Первый этап: выделение Windows Executor

**PS-AI-V1-00 — обязательный первый этап, PLANNED.** Перенести Windows
исполнитель в отдельный репозиторий **`fortis-powershell-executor`**.
Подготовлены воспроизводимый source candidate и изменения Script Center;
новый repo/clone ещё не создан и не проверен через Gateway. Windows-процессы,
credentials и установленная DB не изменены. Source-подготовка не является
завершением переноса или Windows переключением.

**Текущий результат:** 15 файлов кандидата, неизменённые байты runner,
11 extraction + 9 candidate tests и 94 Script Center tests (1 skip).
Реальные source-resolver проверки выполнены на PowerShell 7/Linux, не Windows.
Подробные SHA, scope и границы — в [source evidence](../fortis_approvals/evidence/POWERSHELL-EXECUTOR-EXTRACTION-SOURCE-20261117.md).
**Следующий prerequisite:** owner-created GitHub repo с initial main и URL
по UC-CONT-027; fresh READ нового target сейчас вернул FORTIS_HTTP_403,
а create_repository не представлен в Gateway. Не обходить этот bootstrap.
Публикация подготовленных draft PR также остановлена внешней approval review:
нужно явное согласие на recipe/plan/tests в `AlexPastukhh/fortis-approvals`
и launcher/resolver/CI в `AlexPastukhh/script-control-center`. Исходники
сохранены локально; ветки в GitHub и draft PR пока не созданы.

Задача переноса — сохранить существующее owner-only поведение и API.
Machine ASK и ограничения команд реализуются следующими этапами; перенос
не открывает новый AI-доступ и не меняет разрешения существующего клиента.

| Шаг | Что сделать | Критерий готовности |
| --- | --- | --- |
| MOVE-01 | Зафиксировать baseline | Точные source SHA/хеши Executor, launcher и тестов; installed source/identity/bind/TLS и существующая receipt DB; текущие unresolved/in-flight эффекты. Читать только безопасные metadata |
| MOVE-02 | Подготовить самостоятельный source repo | Перенести `mirror_api/owner_shell.py`, `Start-OwnerPowerShellExecutor.ps1`, профильные тесты и документацию; нейтральное имя Python package, отдельный Windows release target/CI и provenance к исходному commit. Сохранить лицензию/авторство; секреты и DB остаются вне Git |
| MOVE-03 | Проверить API compatibility | Те же `/owner-shell/v1/*`, request/result schema, digest/UUID semantics, loopback `127.0.0.1:10443`, mTLS/Bearer и process privileges. Меняются расположение source и module/launcher references; функциональных расширений и DB migration в этом этапе нет |
| MOVE-04 | Перепривязать Script Center | Launcher/resolver проверяет новый clean/synchronized Windows clone `%USERPROFILE%\Repos\fortis-powershell-executor` и его origin/main; прежняя зависимость от Mirror path и `Get-FortisMirrorWindowsMain` устранена. Сохранены non-admin, ACL, port и source-change preflight |
| MOVE-05 | Сохранить установленные данные | Использовать те же cert/key/CA/secret files, protected config и **ту же существующую receipt DB**. Отдельно проверить paths/ACL; не создавать пустую DB, не перевыпускать credentials и не заставлять владельца настраивать все пути заново |
| MOVE-06 | Доставить source и подготовить Windows переключение | Exact-head tests/CI, owner merge и новый Windows clone по общему guarded workflow; согласованный rollback и recovery copy. Старый установленный вариант доступен до приёмки, source-перенос не считается Windows cutover |
| MOVE-07 | Переключить один Windows listener | После owner-controlled quiescence остановить старый Executor и запустить новый на прежнем endpoint с прежними данными; одновременно два исполнителя не запускаются. Неизвестные эффекты/дочерние процессы сначала расследовать, не сбрасывать blocking |
| MOVE-08 | Принять работу и отвязать старый source | Gateway capabilities/owner-only вызов и bound receipt подтверждены; старые UUID читаются из той же DB, replay/conflict/auth/timeout/restart negatives проверены. После приёмки удалить/retire старую реализацию по отдельному source change; не оставлять два независимо развиваемых Executor |

**Проверки переноса:** существующие Executor tests плюс проверки нового
module/launcher, Script Center resolver, чтения старой квитанции, конфликта
UUID/command и сохранения blocking после controlled restart. Owner Windows
acceptance включает Gateway → Executor по прежнему TLS endpoint и новую
безопасную команду с новым UUID из существующего owner-only Portal.
Старую команду не повторять ради проверки; machine API в этом этапе отсутствует.

**Rollback:** сначала остановить новый listener, затем вернуть прежний source/
launcher с **той же актуальной DB** и TLS/config. Нельзя откатывать DB на более
раннюю копию и терять новые UUID/receipts. При несовместимости schema или
неизвестном эффекте — STOP и reviewed recovery, не автоматическая подмена DB.

Gateway использует HTTPS-контракт и не импортирует Windows package.
При доказанно неизменных API/config для самого source-переноса новый Gateway
image не требуется; это подтвердить compatibility/readback. Следующий
machine ASK release проходит отдельно по PS-AI-V1-02…10.
Функции Mirror и Browser Pull не становятся зависимостями нового компонента.

### Обязательный контракт Repo AI V1

- Machine grant допускает только явно зарегистрированного actor и Windows
  target; caller не передаёт URL, port, credential, process identity,
  interpreter flags, policy или путь receipt DB.
- Операция исполнения имеет только ASK для допущенного запроса либо DENY.
  Catalog/capabilities и чтение готовой квитанции могут быть READ/ALLOW,
  если они **не запускают PowerShell**. Новая команда для диагностики тоже ASK.
- Preview показывает actor, target, полный исполняемый текст без обрезания,
  командный SHA256, версию/ digest правил, identity/profile, рабочий каталог,
  ограничения времени/вывода и известные доступы. Никакой скрытой команды,
  автоматически дописанной ИИ после решения владельца.
- Approval связывает UUID с точной командой, параметрами, target и правилами.
  Изменение команды, правил, исполнения или target делает preview устаревшим:
  новая проверка и новое ASK; старое решение не расширяется.
- Windows исполняет один раз только после проверяемой авторизации Gateway.
  mTLS + bearer + UUID не доказывают owner approval. Новый machine путь
  требует reviewed dispatch proof, привязанного к actor/target/UUID/digest,
  сроку и версии правил, либо отдельно доказанной эквивалентной границы.
  Формат proof, ключи/rotation и негативные тесты принять на PS-AI-V1-02;
  Proof другой операции не считается автоматически применимым к PowerShell.
- Текущий owner-local execute route нельзя использовать как AI proxy.
  Старый клиент сохраняется только в своей owner boundary; его credentials
  не выдаются Repo. Новый протокол/route version не должен обходить проверку.
- Один Windows runner и существующая durable DB: резервирование до эффекта,
  конфликт UUID/command запрещён; параллельные/повторные dispatch не дают второй
  запуск. Перезапуск/обновление сохраняет квитанции и незавершённые состояния.
- ИИ получает exit code, ограниченные stdout/stderr и command digest,
  UUID, target/actor/policy binding и статус. История не содержит ключей/grants.
  Команды/вывод могут быть чувствительными: не переносить их в публичные логи.
- Timeout, потерянный ACK, падение/restart и незавершённый дочерний процесс
  дают неизвестный исход и блокируют новый эффект в соответствующем scope.
  Читать/расследовать исходный UUID; не повторять команду автоматически,
  не создавать замену под новым UUID и не переносить generic Git retry сюда.
  Ненулевой exit code не означает отсутствие побочных действий.

### Настройки ограничений — обязательны в первой версии

Owner Portal получает отдельный защищённый раздел настроек, использующий
существующую owner authentication/CSRF/WebAuthn. ИИ имеет только разрешённое
чтение effective policy; запись/импорт правил через machine API запрещены.

| Настраиваемые данные | Требование V1 |
| --- | --- |
| Scope | Разрешённые actor/target/profile; неизвестное значение DENY |
| Команды | Явные allow/deny правила имён; отсутствие правила DENY; нет fallback «любая команда через ASK» |
| Аргументы | Допустимые параметры и ограничения literal values/типов; unknown параметры/формы DENY |
| Файлы и контекст | Разрешённые canonical roots, рабочий каталог и доступные script/module/executable identities там, где профиль умеет это проверять |
| Ресурсы | Timeout и output/command limits в пределах reviewed верхних ceilings; значения по умолчанию учитывать из baseline |
| Изменения правил | Проверка схемы, preview diff, owner WebAuthn, audit, immutable version/digest и повторная проверка pending requests |

Сами имена разрешённых команд и пользовательские scopes не компилируются
в приложение. Код определяет строгую схему, проверяющий механизм и безопасные
верхние ceilings. Editor не предлагает ALLOW для PowerShell execution.

Первый evaluator поддерживает **ограниченный явно описанный PowerShell
профиль**, а не обещает разбор любого скрипта. При проектировании зафиксировать
допустимые AST nodes, literal arguments и pipeline semantics; aliases,
dynamic/encoded invocation, `Invoke-Expression`, dot-sourcing, запуск дочерних
процессов, .NET/COM, redirection, alternate providers/paths и другие формы,
которые нельзя надёжно проверить, отклоняются. Расширять профиль отдельно.
Проверку выполнять до ASK и перед эффектом; Windows должен проверить ту же
версию/результат правил либо независимо проверить подписанное policy binding.
Решение о расположении evaluator и защита TOCTOU входят в PS-AI-V1-02/03.

AST/allowlist не являются OS sandbox: разрешённый cmdlet/module сам может
иметь широкие права. В настройках и preview явно показывать эту границу.
Если file/network/process scope не обеспечивается выбранным профилем/OS,
соответствующий доступ не объявляется ограниченным и не включается молча.
Приёмочные escape tests обязательны для заявленных ограничений.

### Последовательность реализации и критерии готовности

PS-AI-V1-00 сейчас **IN PROGRESS / SOURCE CANDIDATE**; bootstrap и live
cutover ещё не приняты. Остальные новые пункты **PLANNED**.
Старые owner PASS их не закрывают.

| ID | Шаг / владелец | Проверяемый результат |
| --- | --- | --- |
| PS-AI-V1-00 | **IN PROGRESS / SOURCE CANDIDATE** — выделение `fortis-powershell-executor`; Executor + Script Center | Для завершения нужны MOVE-01…08: самостоятельный source/CI, новый resolver, совместимый Windows cutover, прежние TLS/config/receipt DB и проверенный rollback; Mirror не нужен для запуска |
| PS-AI-V1-01 | Повторная сверка baseline после переноса; Gateway + Executor + Script Center | Точные source/installed версии, identity/bind/TLS/DB metadata без секретов; список незавершённых эффектов; сохранён recovery path. Не запускать release или старую команду повторно |
| PS-AI-V1-02 | Контракт и threat review; Gateway + Executor | Закрытые submit/status/result schemas, actor/target, ASK-only, полный preview, policy/proof versions, dispatch trust и совместимость owner route/DB; owner-reviewed спецификация до activation |
| PS-AI-V1-03 | Policy model/evaluator; Gateway + Executor | Versioned owner settings, консервативный AST-профиль, fail-closed отрицательные тесты, pre-ASK/pre-execute binding и TOCTOU; нет захардкоженного списка разрешённых команд |
| PS-AI-V1-04 | Owner settings UI; Approvals | Просмотр/редактирование правил, diff/validation/WebAuthn/audit, stale approval на смене версии; machine policy write и ALLOW execution отклоняются |
| PS-AI-V1-05 | Machine adapter и typed Repo client; Approvals | Реальный Core PENDING без execute до решения; Reject без эффекта; новый authenticated actor не получает доступ сам по себе; fixed reviewed transport |
| PS-AI-V1-06 | Windows dispatch/runner; Executor | Проверка proof/policy/target, один runner/DB, durable reserve/result и migration/restart; старый owner route не является machine bypass |
| PS-AI-V1-07 | Сквозные offline/source проверки; оба repo | Матрица ниже, совместимость baseline, source manifests/CI; отдельно исправленный CLIXML progress без потери настоящих stderr |
| PS-AI-V1-08 | Source delivery; владельцы repo | Task → exact-head CI/Release Impact → owner GitHub merge → clean Docker main; Windows source sync только для изменяемого consumer. Source ещё не live |
| PS-AI-V1-09 | Раздельный owner release | Windows install и Gateway Check/Apply/Backup/Promote по UC-GW-005, свежие TLS/ACL/config/capabilities и сохранённые native/OwnerShell unresolved scopes; один согласованный release window |
| PS-AI-V1-10 | Windows/Gateway live acceptance | Настройки изменены владельцем; Get-Date: PENDING → WebAuthn → один запуск → bound receipt; Reject, forbidden command, stale rules, replay/conflict, timeout/lost ACK и restart negatives подтверждены |

Dependencies: 00 (MOVE-01…08) → 01 → 02 → 03/04; 02/03 → 05/06;
04/05/06 → 07 → 08 → 09 → 10.
Реализация разных repo может идти независимо после общего контракта;
shared production release и vault не меняются несколькими задачами одновременно.

### Обязательная матрица приёмки

| Проверка | Ожидаемый результат |
| --- | --- |
| Нет machine grant / чужой actor/target / лишнее поле | Отказ до dispatch |
| Любая допустимая команда, в том числе Get-Date | PENDING; счётчик runner = 0 до owner WebAuthn |
| Reject / expired / revoked / stale approval | Ни одного запуска |
| Нет owner session / wrong Host/Origin/CSRF на owner routes | Отказ; machine credential не подменяет owner |
| Правило запрещает команду/аргумент, неизвестный AST/alias/path | DENY; ASK не снимает запрет |
| Смена command/target/policy/proof/identity после preview | Отказ/stale; требуется новое ASK |
| Нет/неверный mTLS, bearer или dispatch proof; proof replay | Отказ; bearer/UUID не служат подтверждением решения |
| Двойной клик, одинаковый UUID, concurrent executor/restart | Максимум один effect; изменённая команда под UUID даёт конфликт |
| Timeout/kill/lost ACK, detached child, crash после reserve | Нет автоматического повтора; uncertain и проверяемый lookup/blocking |
| Recovery/upgrade при существующей DB и старых receipts | Сохранены старые UUID, результаты и blocking; новая пустая DB запрещена |
| Изменение настроек без кодовой правки | Новые правила реально применяются; старое approval не расширяется |
| Получение stdout/stderr/receipt в Repo | Exact binding, bounds, правильная кодировка; ошибка/неизвестность не превращаются в success |

Repo AI V1 завершена только после PS-AI-V1-10 и отдельного dated evidence.
Offline PASS, owner-reported baseline и live machine acceptance имеют разные
пометки; runtime факт нельзя закрыть одним source CI.

### Будущие улучшения после Repo AI V1

| ID | Улучшение | Граница / критерий |
| --- | --- | --- |
| PS-FUT-01 | Отдельная минимальная Windows identity, JEA/CLM, WDAC/AppLocker, NTFS ACL | Сравнить подходы; реальные read/write/traversal/reparse/child-process escape tests. Не считать non-admin sandbox; не включать все технологии формально |
| PS-FUT-02 | CA/staging hardening и recovery | Проверенная offline backup/изоляция issuer keys и cleanup Windows-staged Gateway client key/bearer; не удалять единственные копии. PS-V1-07 остаётся OPEN/DEFERRED до evidence |
| PS-FUT-03 | Расширенный policy/AST профиль | Более сложные pipelines/scripts/modules/executables, bounded filesystem/network/children, environment; каждая возможность с enforcement/negative tests. ASK-only execution сохраняется |
| PS-FUT-04 | Analyzer для команд и других Portal requests | Объяснение риска/эффекта и второй AI advisory; не approval, не замена deterministic DENY и не существующий Sonar analysis_review. Не отправлять секреты модели |
| PS-FUT-05 | Windows service/autostart и удобный restart/status | Учитывать уже существующий Script Center adapter/setup UI; та же DB/identity, health и controlled shutdown, проверка после reboot |
| PS-FUT-06 | Полноценная lifecycle-защита дочерних процессов | Process-tree containment/cleanup и cancellation semantics с доказуемым outcome; kill родителя сам по себе не rollback |
| PS-FUT-07 | Интерактивный PTY/долгие задачи | Отдельный контракт: approval scope, prompts, output, cancel/reconnect/receipt; V1 остаётся one-shot |
| PS-FUT-08 | Ротация ключей/сертификатов и восстановление | Owner-managed lifecycle, revoke/expiry, backup/restore с прежней DB, без повторных эффектов |
| PS-FUT-09 | Узкие typed Windows операции и container-control broker | Самостоятельные API/scopes; не generic Docker shell/socket. Container lifecycle, mounts/networks/volumes остаются у [Fortis Container][ps-container-plan] |
| PS-FUT-10 | Наблюдаемость и UX | Поиск заявок/receipts, bounded safe diagnostics, stale settings diff; не создавать вторую историю/очередь или секретные payload logs |

Бывший PS-FUT-11 (выделение Executor) перенесён в обязательный
**PS-AI-V1-00 / MOVE-01…08**; это уже не отложенное улучшение.

Отдельная Windows identity и перенос issuer keys были отложены владельцем
для функционального baseline. Это решение не означает выполненную изоляцию
и не даёт новых прав AI. Перед PS-AI-V1-09 повторно оценить пригодность
identity/credential boundary: конкретный неприемлемый scope блокирует activation,
даже если улучшение в целом остаётся отдельным проектом.

### Происхождение решений и замена исторических указаний

| Источник | Что переносится / как читать теперь |
| --- | --- |
| [OwnerShell contract](OWNER-POWERSHELL.md), Approvals commits `b4957af76`, `33a51e643`, `9fc33329d` / PR #35 | Owner-only baseline, one-shot/mTLS/receipts; старое «source only» описывало 2026-11-08, не отменяет поздний функциональный owner PASS |
| [Mirror executor contract][ps-mirror-contract], PR #9 / `85a5a68` | Windows runner/TLS/DB; старое «not deployed» не является свежим host фактом |
| Approvals `fe4337a92` / PR #45; существующие PS-V1-01…10 | Историческая установка baseline; PS-V1-01…06/08/09 owner/source PASS, 07 deferred, 10 functional PASS/security OPEN. ID не переименованы в AI этапы |
| [Evidence 2026-11-10](../fortis_approvals/evidence/OWNER-SHELL-RELEASE-AND-GET-DATE-20261110.md), PR #53 | Установленные материалы/release и Get-Date; UUID/image/backup остаются в evidence, не копируются как новые preconditions |
| [Script Center launch/setup][ps-script-center], PR #7/#10; текущий runbook | Уже существующие adapter/config UI и дальнейшая main-trust модель; настройки путей не являются настройками разрешённых команд |
| [Container backlog][ps-container-plan], [исторический архив][ps-container-archive], [изоляционный аудит][ps-container-audit] | Identity/AST/deterministic DENY, network/children и Docker broker идеи; PowerShell roadmap теперь здесь, общий container scope остаётся там |
| [UC-GW-012](use-cases/own-api.md#uc-gw-012), [UC-GW-002/003](use-cases/integrations.md#uc-gw-002) | Reuse Gateway/Core, separate effect/transport review и live acceptance; READ onboarding не расширен на shell |
| Tunnel G2/G3 документы 2026-10-13…16 | История Windows sessions/launchers/listeners; не контракт этого OwnerShell API и не разрешение Repo → host shell |
| Решения владельца в этой задаче, 2026-11-17 | Все исполнения из Repo через ASK; ограничения меняются в настройках; консолидировать первую версию и будущие улучшения; обновить план с выделением Executor в отдельный `fortis-powershell-executor` первым этапом |

Датированные evidence/archives и старые Git revisions сохраняются. Актуальные
entrypoints ведут сюда; исторические deferred требования не становятся DONE.
Не повторять прежний PS-V1-06 publish UUID `ef7c2a2d-d8bb-57c1-a1aa-f111e0610b57`
ради актуализации плана: исторический UNCERTAIN — самостоятельный инцидент.

[ps-script-center]: https://github.com/AlexPastukhh/script-control-center/blob/main/docs/OWNER-POWERSHELL-EXECUTOR-LAUNCH.md
[ps-mirror-contract]: https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/OWNER-POWERSHELL.md
[ps-container-plan]: https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#optional-host-powershell-and-container-control-bridge-planned
[ps-container-archive]: https://github.com/AlexPastukhh/fortis-container/blob/main/docs/FUTURE-IMPROVEMENTS-ARCHIVE-2026-11-05.md
[ps-container-audit]: https://github.com/AlexPastukhh/fortis-container/blob/main/docs/audits/AI-CONTAINER-ISOLATION-2026-11-04.md

## Исторические инциденты 2026-11-07 — не список текущих UNCERTAIN

Здесь сохраняется evidence о прежних сбоях; не использовать его как
актуальное правило owner dismissal. Текущий безопасный маршрут —
[UC-GW-009](use-cases/incidents.md#uc-gw-009). `details()` — read-only,
`reconcile` может зафиксировать receipt и **изменить Core state**,
поэтому не является обязательным шагом просмотра.

- Разобрать заявку `5f8db475-c503-4a32-8d5f-118f32370f1c` (`workspace.stage` в `fortis-approvals`, task `local-use-case-registry-20261107`). Core стал `UNCERTAIN`, Gateway job `FAILED / UNCERTAIN`, worker receipt был `NULL`; тогдашний `reconcile` не смог подтвердить результат и не изменил state. Позднее worktree имел чистый Git HEAD, но это **не доказывает** исходный stage effect.
- Повторное наблюдение 2026-11-07 при аудите документации: `workspace.create_task`
  для `tunnel`, task `docs-dry-audit-20261107`, request
  `b32222b5-4a84-4816-bd39-625ab6c9995d` вернул
  `UNCERTAIN / REMOTE_OUTCOME_UNCONFIRMED`. В том наблюдении `reconcile` не изменил статус;
  соответствующие worktree и ветка не найдены. 2026-11-08 этот UUID вместе со
  старыми Tab Notifier `inspect`/`commit` и Mirror `sync_task` разово retired
  после отдельного owner approval, verified cold copy и проверки отсутствия
  активного исполнения. Native tombstones сохранены; подробности завершения и
  protected record — в [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).
  Первопричина не установлена: сохранить этот случай для расследования, а не
  повторять исходный запрос или считать его успешно исполненным.
- Исследовать точную первопричину с безопасными снимками ошибок: worker journaling между `DISPATCHED` / `git add` / receipt, исключения после частичного эффекта, timeout, stale precondition, отсутствие error detail. Не полагаться на `job.result IS NOT NULL`: это может быть JSON-строка `null`, не receipt.
- Исторические требования вывести `UNCERTAIN` в раздел «Требуют разбора» и
  дать владельцу административное завершение без фиктивного `EXECUTED` теперь
  **реализованы** (PR #37/#38/#39, [UC-GW-009](use-cases/incidents.md#uc-gw-009)).
  Не планировать повторную реализацию прежних сложных gates с обязательным
  backup или `worker=FAILED`; оставшийся пункт — owner-browser UI acceptance.
- Разделить `Backup` admission на проверку **активных** запросов и управление **историческими неразрешёнными** эффектами. Холодная копия volume защищает байты, но не является проверкой логического состояния; нельзя ослаблять весь release guard для одной ошибки.
- Исторический инцидент был разово закрыт после owner-requested холодной verified копии; Production сейчас здоров. Не восстанавливать удалённую заявку из старой копии при штатном релизе. Это *исследовательская задача*, не срочная новая миграция.

## Согласование нормального UI-merge с последующими операциями

- Завершить **live acceptance cleanup ASK для неслитой задачи**: отдельный
  disposable task, фактический PENDING без удаления до WebAuthn, owner decision,
  exact HEAD/dirty/ignored/lock и replay guards. Установленный cleanup profile
  и merged ALLOW уже подтверждены в [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md);
  отрицательные/ASK сценарии покрыты offline TLS/Core/worker тестами. Не выдавать
  их за новый live owner цикл и не повторять image release ради этой проверки.
- При следующем согласованном reboot проверить новый установленный image;
  pre-release reboot-аудит старого Primary не является его reboot acceptance.
- Gateway Mirror provider находится в отдельном `task/mirror-provider-20261107`,
  а не в принятом `main`. Его перенос/activation, scoped credentials и acceptance
  принадлежат этому repo. Кандидат Pull привязан к Gateway merge request; перед
  поддержкой обычного owner UI merge требуется согласовать proof и тесты.
  Mirror Windows/UI задачи принадлежат
  [Mirror backlog](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/BACKLOG-IMPROVEMENTS.md).

## Улучшение детерминированного релиза (2026-11-07)

- **Build-once для штатного `-Auto` — OWNER-REPORTED PASS 2026-11-14:**
  `Check -Auto` создал pinned checkedImageId, `Apply -Auto` использовал
  его без второй сборки, затем прошли Backup/Promote. Source PR #94 /
  `c473edb8…`, checked image `sha256:900456dd…`. Legacy `Check -Build` +
  `Apply -Build` **по-прежнему** собирает дважды; для immutable ручного пути
  использовать protected checked-image binding по
  [Primary runbook](PRIMARY-GATEWAY-OPERATIONS.md). Host/reboot acceptance
  остаются отдельными проверками.
- **Краткий owner entrypoint — реализован для штатного `-Auto`:**
  SelfTest → Check/Apply/Backup/Promote по отдельным защищённым фазам;
  нет автоматического production deploy. Открыта лишь оценка нужности
  улучшений ручного exception-пути, а не второго release controller.
- Устранить caller-scope side effects dot-sourced operator helpers: подтверждён
  конфликт типизированного `[string]$Record` с ad-hoc build metadata dictionary.
  Сохранять metadata отдельной переменной, проверять JSON-object round-trip и
  обязательные поля до PASS; повторный запуск выбирать по protected phase/identity,
  а не повторять законченный Apply. Разовая запись уже исправлена, образ повторно
  не собирался; reusable source entrypoint остаётся задачей этого раздела.
- При Docker/PowerShell ошибках сохранять и безопасно редактировать **весь ограниченный stderr** и exit status; не обрывать traceback на первой `NativeCommandError`. Отделить owner-preflight, immutable image build, offline smoke и live acceptance, чтобы не дублировать длинные команды вручную.
- Формализовать условие `FORTIS_PRIMARY_ALREADY_ACTIVE`: считать успехом только при совпадении protected `primary.json`, точного image/container ID, `healthy`, `unless-stopped`, multi-repo capability и реальных Gateway READ.
- Для нового GitHub repo не заводить второй allowlist. Проверять доступность токену, owner/`main`, canonical worktree, origin и действующие API policies; чтение не является доказательством Contents write. Отсутствующие required status rules не обходить при merge.
- При будущих релизах distinguish snapshot-копию state от controller-managed `Backup` (последний требуется для `Promote`); не создавать rescue volume без необходимости, но не удалять защищённую rollback-копию автоматически.


## GitHub Actions в native профиле — частично проверено live (2026-11-09)

Принятый в `main` source (коммит `9e5a72b6`, вошёл в последний
owner-confirmed image `a200137775eb6c6b8dcec81f31206b0d481d9003`)
содержит семь GitHub Actions READ и четыре CI-control операции
без обязательного SonarCloud binding. CI-control выключен по умолчанию;
при явном opt-in — `ASK`. В отличие от исторического source candidate,
**`get_workflow_run` действительно проверен на установленном Gateway**:
авторизованный machine READ вернул реальный `rd-graphs` run
`42542630753`, attempt 1, `completed/failure`, head SHA
`3c22ecb45fc5ad32f3caac0f1c9be5f2e1f2af87`.

**Не считать весь профиль LIVE VERIFIED:** остальные GitHub Actions READ
(особенно jobs/logs, artifacts, Checks), repo-denial boundaries,
четыре CI-control операции, opt-in/ASK и provider effects требуют
отдельных адресных live-проверок по policy/scope. Успешный
`get_workflow_run` **не** доказывает доступ GitHub Checks или
полномочия на CI-control. Не запускать новый Gateway image release
лишь ради изменения статуса этой документации.

## Следующие задачи

Это **внутренняя очередность после P0**, а не замена первому приоритету
[Fortis → API](#p0--подключение-собственных-api-через-gateway-первое-в-очереди-2026-11-10).

| Порядок | Задача | Что должно получиться |
| --- | --- | --- |
| 1 | Sonar operations: source candidate реализован; live acceptance впереди | Сопоставить реальную работу с issues/analysis/quality gate с доступными API и текущими контрактами; решить, что оставить/изменить/добавить, определить ALLOW/ASK/DENY и scope. Отдельно разобрать branch/PR/analysis/SHA binding; нынешний default-branch `OK` этого не доказывает |
| 2 | Оценка получившегося GitHub workflow | Разобрать путь worktree → commit/push → PR/CI → ready/merge → main/cleanup: лишние шаги, число подтверждений, ожидание worker, resume/reconcile, ограничения bundles и нужные чтения. Сохранить согласованный обычный task push ALLOW; обосновать изменения остальных политик до реализации |
| 3 | Обратная связь Owner Portal после Approve/Reject | Сразу показать принятие решения и обработку, исключить повторное нажатие, затем показать результат или ошибку. Различать owner decision, ожидание worker и завершение эффекта; не убирать запрос как успешный до подтверждения исполнения. Проверить оба решения и медленные/ошибочные ответы |
| 4 | Проверка корректности кода, затем необходимый рефакторинг | Проверить контракт/политики/scope, гонки состояний, idempotency, SHA/CI/receipt binding, обработку сбоев и границы credential. Убрать найденное дублирование и лишнюю сложность; рефакторить по результатам, с проверками поведения |
| 5 | Gateway-side Mirror integration | Только перенос/activation provider и proof границы из раздела выше. Windows/API/UI задачи — у [Mirror backlog](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/BACKLOG-IMPROVEMENTS.md), не второй список здесь |
| 6 | Проверка полноты Mirror для согласованного workflow | Проверить repo/worktree inventory и точный target действий, чистоту/branch/SHA/расхождения Docker/GitHub/Windows, получение только одобренного merged main. Составить фактический gap list и подтвердить Windows сценарии; не считать проверку Docker доказательством поведения WinForms/NTFS |

Симптом UI установлен со слов пользователя. Причину паузы между решением и
исчезновением из Pending нужно измерить; HTTP 202 само по себе не доказывает
причину задержки UI.

Source-кандидат первого пункта описан в [analysis-review contract](ANALYSIS-REVIEW-CONTRACT.md): там живут операции, scopes, политики opt-in и ограничения binding. Отдельно требуется owner-reviewed deployment, CI manifest и live-проверка реальных ответов/permissions; прежний Sonar default-branch OK не заменяет такую проверку.

## Незавершённое сопровождение принятого native этапа

- **Завершено в main (коммит b265838e):** WorkflowClient.result(UUID)
  уже передаёт accept_202=True; нативный клиент корректно принимает PENDING.
  Предыдущая запись про незакоммиченный task/native-client-pending-status-20261106
  устарела. Не создавать новый PR и не делать новый Gateway image release для
  исправления, уже принятого в source.
- Bootstrap worktree пока сохраняется: owner-run record ссылается на его точный
  source path/SHA. Перенести источник будущего пакета на принятый merged source
  отдельно, затем решить вопрос очистки. Старые M1–M3 methods сохраняются для
  совместимости, но не возвращаются в основной native путь.

## Отложенные направления

- Управляемый владельцем редактор политик отдельно для Sonar/GitHub с областью
  actor/project/repository/branch/file; сейчас правила заданы trusted config/code.
- **Primary promotion и остановка Legacy выполнены 2026-11-07**
  ([live evidence](../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md)).
  Следующие image releases, отработанное восстановление/DR вне Docker host,
  общая миграция других репозиториев и закрытие legacy helper/PAT — отдельные задачи.
- Более широкие multi-agent identities, scheduler, RDG writer enforcement,
  supply-chain review и backup/rotation — в общем Fortis backlog.

Матрица текущих разрешений живёт только в [native contract](NATIVE-WORKTREE-GATEWAY-2026-11-06.md).
Mirror владеет общим [workflow](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/WORKFLOW.md);
здесь не создаётся новая система Windows-команд и не меняется его source.

## Повторяемое подключение операций

Общий source mechanism ALLOW/ASK + именованные Gateway credentials описан в
[extension contract](INTEGRATION-EXTENSIONS.md). Owner controller принят на реальном
Windows/Docker с пустым catalog; [результаты и границы](../fortis_approvals/evidence/EXTENSIONS-LIVE-ACTIVATION-20261106.md)
не подтверждают конкретный новый provider/token/effect. Их acceptance и отдельное
включение Sonar/CI analysis profile остаются будущей работой.

## Use-case navigation and owner interaction

Общие сценарии контейнера ведутся в `fortis-container/docs/use-cases/README.md`,
достижимом через `/workspace/repo/README.md`. ASK-заявки в порученной задаче
отправляются без предварительного устного разрешения; эффект подтверждается
в Owner Portal. После этих двух шагов PR ALLOW реализован отдельным source
commit для exact actor/repository и внедрён в review. Результат — в
[live evidence](../fortis_approvals/evidence/PR-CREATION-ALLOW-LIVE-20261106.md);
прочие задачи оценки GitHub workflow остаются в пункте 2.
С 2026-11-07 принятый review-runtime переименован в действующий Primary;
вспомогательный Legacy остановлен ([cutover evidence](../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md)).
