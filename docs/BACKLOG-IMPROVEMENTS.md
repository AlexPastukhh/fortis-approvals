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

**Статус на 2026-11-14:** Mirror pilot **LIVE TYPED READ VERIFIED**;
специализированный [UC-GW-012](use-cases/own-api.md#uc-gw-012), manifest/lint,
Doctor, одноразовый Acceptance и шаблоны **приняты в main**. Второй
DOCKER-HTTPS API — только offline fixture, его реальный релиз НЕ выполнен.
Ранее этот P0 был `PLANNED`; следующая задача — использовать UC для новых API,
а не заново проектировать общую процедуру. **Рабочий подробный план:**
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

**Следующий шаг P0:** применять [UC-GW-012](use-cases/own-api.md#uc-gw-012)
к следующему реальному API: intake → фиксированный transport/provider →
source tests/PR/CI → отдельный owner release → live typed READ. Из готовой
автоматизации использовать существующие [manifest/linter и Doctor/Acceptance](templates/own-api/TOOLS.md),
не создавать дублирующие Gateway/vault/deployment controllers.
Все rights/target/scope — только по новому reviewed API; offline фикстура
не означает live deployment.

**Направление «внешнее приложение → Fortis Gateway»:**
**ACKNOWLEDGED — DEFERRED**, не входит в P0, не требует нового route, actor/grant
или отдельного UC сейчас. При подтверждённом запросе использовать
[UC-CONT-008](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/authorization.md#uc-cont-008).

**Граница:** первенство в backlog не является разрешением на production-изменения:
owner credentials и WebAuthn, live release admission, backup/rollback,
сохранение UNCERTAIN/CLAIMED и stop-on-unknown остаются обязательными.

## Mirror follow-up: READ всех Windows-клонов и будущий ASK Pull (2026-11-14)

**Сейчас:** принятый отдельный Windows GET-only listener, Script Center
launcher и live Gateway `mirror.get_repository` разрешают **только** target
`fortis-approvals`. Это был scope первого пилота, **не** требование
ограничивать доступ ИИ к остальным зарегистрированным Windows-клонам.
Первый typed Mirror READ живой, но GitHub verification остаётся `NOT_CHECKED`,
а Windows↔Docker relation может быть `unknown`. Browser Pull — независимая
ручная owner-local операция; **Gateway ASK Pull отсутствует**.

1. **MIR-READ-ALL — безопасный просмотр зарегистрированных Windows-клонов.**
   После отдельного source review расширить Windows listener allowlist,
   Script Center launcher и trusted Gateway actor/target policy согласованно:
   получать read-only инвентарь **всех зарегистрированных Mirror репозиториев**,
   по возможности одним bounded/paginated typed READ, плюс адресный GET.
   Разрешённый набор выводить из проверенного registry, а не `*`, arbitrary
   path или каталога файлов по запросу AI. Для каждого клона проецировать
   `exists/branch/HEAD/clean/originValid/checkedAt`, сравнение с Docker
   только при наличии доказательств; GitHub READ проверять **отдельно**.
   Никаких fetch/Pull/WRITE из GET; тесты wrong actor/target, leakage,
   large inventory/timeout, отказов и полного Windows↔Gateway E2E.
   **До owner merge + контролируемого Gateway/Windows rollout — NOT ENABLED.**
2. **MIR-PULL-ASK — разрешённый владельцем Pull Windows через Gateway.**
   Спроектировать **отдельную typed эффектную операцию** для конкретного
   зарегистрированного repo, по [UC-GW-003](use-cases/integrations.md#uc-gw-003),
   с policy `ASK` и Owner Portal WebAuthn, **не** расширяя READ до WRITE.
   Preview должен замораживать repo/origin, чистоту Windows+Docker `main`,
   проверенное актуальное GitHub `main` (через штатный Gateway), ожидаемые
   SHA и scope эффекта; перед выполнением перепроверить frozen conditions.
   Windows выполняет только guarded fetch/`--ff-only` по принятому Mirror
   workflow, выдаёт durable receipt и точный readback. Для timeout,
   потерянного ACK и `UNCERTAIN` — сверить исходный UUID/upstream receipt,
   **никакого автоматического повторного Pull**; отдельно тестировать
   конкуренцию, недоступность Windows, отказ owner, dirty/diverged/ahead.
   Ручной Browser Pull не превращать в machine authorization и не ломать.
   **Никакой ASK Pull сейчас не зарегистрирован и не разрешён.**

Обе задачи — **backlog**, не новые права текущего Gateway, не разрешение
на Windows/Gateway production update и не основание менять vault/Owner Shell.
Текущий общий маршрут подключения нового собственного API остаётся
[UC-GW-012](use-cases/own-api.md#uc-gw-012); реализация этих улучшений имеет
собственные source/CI/owner release gates.

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

## Owner Portal PowerShell — V1: текущий backlog и критерий приёмки (2026-11-10)

**Цель V1:** владелец входит в действующий Owner Portal через WebAuthn,
открывает вкладку PowerShell, отправляет точную одноразовую команду (первый
контрольный пример — `Get-Date`), получает реальный exit code/stdout/stderr и
сохранённую SQLite-квитанцию; повтор исходного UUID **не запускает** команду
второй раз. Команды не проходят Analyzer, не выполняются через machine/AI API
и не образуют интерактивный терминал. Исходный [контракт и границы](OWNER-POWERSHELL.md).

**Решение владельца для V1:** Windows Executor работает под существующей
**неповышенной** Windows-учётной записью. Выделенная Windows-учётная запись
**не является блокером V1** и отложена как усиление изоляции. Это осознанный
компромисс: произвольная команда имеет доступ к обычным файлам и сетевым
возможностям текущего пользователя. UAC/отсутствие администратора — **не**
песочница. Нельзя считать Windows ACL, разрешающие доступ тому же пользователю,
способом спрятать от Executor ключи, оставшиеся в его профиле.

Статус `SOURCE` означает исходники в `main`, **не live-развёртывание**;
`OWNER PASS` — результат сообщённой владельцем локальной проверки, не
самостоятельный Docker/Gateway live acceptance. `OPEN` — без подтверждённого
завершающего readback. Пункты ниже — последовательные V1 gates, а не право
на изменение Primary без [UC-GW-005](use-cases/releases.md#uc-gw-005).

| ID | Статус | Шаг и подтверждение | Что дальше / критерий готовности |
| --- | --- | --- | --- |
| PS-V1-01 | **SOURCE ACCEPTED / RELEASED** | Owner Portal и Windows Executor source приняты; Gateway opt-in установлен владельцем на PS-V1-09 | Не считать source/CI доказательством отрицательных browser/receipt тестов (PS-V1-10) |
| PS-V1-02 | **OWNER PASS** | Владелец подтвердил обновление Browser Mirror и наличие `Start-OwnerPowerShellExecutor.ps1` на Windows; версия/поведение Executor в живом процессе ещё не проверены | Перед активацией проверить локальные SHA/исходник и отсутствие запуска от администратора |
| PS-V1-03 | **OWNER PASS** | TCP loopback preflight `10443` подтверждён, последующие authenticated HTTPS/mTLS проверки проведены на PS-V1-08/09 | Bind должен оставаться **только `127.0.0.1:10443`**; новый host deployment требует свежей проверки |
| PS-V1-04 | **OWNER PASS** | OpenSSL на Windows найден; созданы отдельные server/client CA, сертификаты, ключи и независимый bearer; `SERVER_TLS_IDENTITY`, `CLIENT_TLS_IDENTITY`, обе key-pair проверки и `BEARER_SECRET_MATCH` — PASS | Сохранить текущие материалы, не пересоздавать при ошибках следующего шага; проверить реальные TLS рукопожатия |
| PS-V1-05 | **OWNER PASS** | Действующий `fortis-gateway` сообщён `healthy`, UID:GID `10001:10001`, `fortis-review-secrets` смонтирован только RO; исходные четыре Gateway-файла были staged на Windows | Последующая установка материалов в Docker подтверждена отдельно в PS-V1-06 |
| PS-V1-06 | **OWNER PASS (2026-11-10)** | Владелец подтвердил `OWNER_SHELL_TARGET_PREFLIGHT=PASS`, `OWNER_SHELL_PRIVATE_DIR_PREPARED=PASS`, `OWNER_SHELL_VOLUME_INSTALL=PASS`, `GATEWAY_UID10001_READONLY_VERIFY=PASS`, `GATEWAY_UNCHANGED=PASS`, `OWNER_SHELL_CLIENT_MATERIAL_READY` для четырёх файлов `/run/fortis-secrets/owner-shell/` | Root volume **не** изменён (`root:root / 0755`); приватный подкаталог UID `10001` `0700`, четыре файла `0600`. Это Docker materials, **не** Gateway релиз |
| PS-V1-07 | **DEFERRED AFTER V1 — owner decision** | Владелец решил отложить offline backup/изоляцию `issuer/server-ca.key` и `issuer/client-ca.key`, а также удаление временных Gateway staging key/bearer из Windows profile, **только для функциональной V1**. Инвентаризация `WINDOWS_TLS_FILES=PASS`, `PS_V1_07_INVENTORY_COMPLETE`; зашифрованного внешнего накопителя нет | Не считать защиту CA/staging выполненной. До безопасного резервирования **не** удалять ключи; arbitrary PowerShell под `alexa` может читать доступные файлы и использовать Docker. До реальных пользовательских скриптов повторно оценить риск; отдельная post-V1 hardening задача обязательна |
| PS-V1-08 | **OWNER PASS (2026-11-10)** | Windows Mirror SHA `747ffaa8830a1bcbc12838ada0b5dccbd9b1e08e`, `OWNER_SHELL_MTLS_READY`, локальные valid/invalid bearer, missing cert, wrong server CA и Gateway HTTPS capabilities GET — PASS | Это preflight TLS; первый реальный execute отдельно подтверждён в PS-V1-10. При смене хоста/сертификатов проверки повторять по контракту |
| PS-V1-09 | **OWNER PASS / PROMOTED (2026-11-10)** | PR #53 / `9481699faaa297d8ec1fb45b4f14be50ae17406f`: `Check -Build`, `Apply -Build -EnableOwnerShell`, staged mTLS, `FORTIS_INTEGRATIONS_ACTIVATED`, protected Backup и `FORTIS_PRIMARY_PROMOTED` с readback PASS | Точный image/record/backup и preserved `UNCERTAIN`/`CLAIMED` — в [датированном evidence](../fortis_approvals/evidence/OWNER-SHELL-RELEASE-AND-GET-DATE-20261110.md). **Не** запускать релиз повторно и не выдавать это за завершённый PS-V1-10 |
| PS-V1-10 | **OWNER FUNCTIONAL PASS / SECURITY OPEN** | Из авторизованного браузерного Portal `Get-Date`: `EXECUTED`, exit `0`, UUID `349937f9-d7b6-436d-9a9a-773b9164970e` и реальный Windows stdout. Отдельного per-command подтверждения не было; это не доказательство API bypass | **OPEN:** отрицательные session/Origin/CSRF, UUID replay/conflict, timeout/lost ack, restart/receipt persistence; убрать лишний CLIXML progress/кодировку stderr, не скрывая настоящие ошибки. [Evidence](../fortis_approvals/evidence/OWNER-SHELL-RELEASE-AND-GET-DATE-20261110.md) |

**Owner-reported PS-V1-06/08 evidence (2026-11-10):** первый подготовленный
установщик остановился на preflight из-за `root:root / 0755` в непустом
`fortis-review-secrets`; исправленный установщик подготовил **только**
отдельный приватный `owner-shell/`, оставив корень и существующий Gateway
неизменными. После этого владелец запустил Windows Executor без elevation
и подтвердил локальные отрицательные mTLS/Bearer проверки и HTTPS/mTLS
capabilities GET из Docker Gateway. Это исторический preflight **до** PS-V1-10:
последующая реальная команда `Get-Date` подтверждена отдельно. Windows service/
autostart и безопасный restart Executor не приняты.

**Publication warning:** отдельный предшествующий task commit
`d37417ef773be1499fc94d4b70dbeb0a07317e5b` для PS-V1-06 evidence
имеет Gateway publish UUID `ef7c2a2d-d8bb-57c1-a1aa-f111e0610b57`
со статусом `UNCERTAIN / REMOTE_OUTCOME_UNCONFIRMED`. Его публикацию не
повторять автоматически и не объявлять её receipt из этого изменения.

**Граница V1:** допускается документированный ручной запуск Executor. Автоматизация
Windows service/autostart, отдельный ограниченный Windows account, Analyzer,
«Мнение ИИ», общая policy engine для скриптов, интерактивный PTY, расширенная
изоляция и автоматическая ротация сертификатов/секретов — **после V1**.
Кнопки Analyzer/AI сейчас отключены, скрипты не проходят security verdict;
само наличие mTLS не делает выполнение PowerShell безопасным. Независимые
Mirror-specific исходники, UI/Windows acceptance и их дальнейший backlog
принадлежат [Mirror](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/BACKLOG-IMPROVEMENTS.md);
здесь фиксируется только сквозная готовность функции Owner Portal.

**Как обновлять:** у каждого PS-V1 ID после проверенного изменения обновлять
статус и конкретный source SHA / receipt или owner-reported PASS. Не отмечать
`DONE` по одному коду, локальному `git main` или отсутствию ошибки. После
успешного browser acceptance пометить V1 `ACCEPTED` с датой и ссылкой на
отдельное evidence, не стирая незавершённые V2 улучшения.

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

- **Build-once (OPEN):** текущие `Check -Build` и `Apply -Build` вызывают
  Docker build по отдельности; они используют один исходный SHA, но
  не доказывают проверку **одних и тех же immutable байтов** без
  повторной сборки. Нужны однократный source build, pinned image digest,
  отдельные Check/Apply по этому digest, проверка исходного SHA/owner scope
  и неизменные fail-closed state admission/backup/rollback guards.
  Не пропускать `Check` ради экономии времени. Группировка PR нескольких
  чатов — общее направление центрального UC-CONT, не дублировать здесь
  multi-repo coordinator.
- Подготовить единый Windows PowerShell 5.1 operator entrypoint: `SelfTest → Check/Build exact SHA → Apply → live READ/Owner Portal → Backup → Promote → readback`, с учётом фазы protected release, кратких PASS-маркеров и остановки без повторного Apply при ambiguity.
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
