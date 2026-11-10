# Backlog улучшений — Fortis Approvals Gateway

Исходный план согласован 2026-11-06 после native Git/worktree live цикла;
статусы актуализированы 2026-11-09 по установленному Primary, Repo machine
readback и принятому source. [Current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
фиксирует подтверждённый релиз и ограничения; этот backlog хранит
**открытые улучшения и явно помеченный исторический контекст**, не разрешает
новых runtime операций.
Общий Fortis backlog принадлежит `fortis-container`; вход — через
реестр юзкейсов в `/workspace/repo/README.md`. Наличие GitHub remote в этом repo
не означает допуск к нему действующего Gateway (UC-CONT-018).
Это **единственный backlog этого репозитория**. Пункты здесь не разрешают менять Production. Общее Docker, Tunnel, Windows/Mirror и multi-agent направление принадлежат своим репозиториям; здесь только Gateway-specific задачи. Принятый результат и техническая история остаются в датированных evidence и source runbooks.

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
| PS-V1-01 | **SOURCE** | В `fortis-approvals/main` есть Owner Portal PowerShell routes, WebAuthn/Origin/CSRF, фиксированный mTLS client и тесты; в `docke-windows-mirror/main` — отдельный Windows Executor с bearer, durable UUID receipt и неадминским запуском | Включить в проверенный image release; **текущий Primary не объявлять обновлённым** |
| PS-V1-02 | **OWNER PASS** | Владелец подтвердил обновление Browser Mirror и наличие `Start-OwnerPowerShellExecutor.ps1` на Windows; версия/поведение Executor в живом процессе ещё не проверены | Перед активацией проверить локальные SHA/исходник и отсутствие запуска от администратора |
| PS-V1-03 | **OWNER PASS** | На Windows порт `10443` свободен, Docker Gateway видит временный TCP listener на `127.0.0.1:10443` через `host.docker.internal` (`GATEWAY_TO_WINDOWS_LOOPBACK=PASS`); отдельный Windows Firewall ingress на Ethernet не нужен | Использовать bind **только `127.0.0.1:10443`**; подтвердить повторно после запуска HTTPS |
| PS-V1-04 | **OWNER PASS** | OpenSSL на Windows найден; созданы отдельные server/client CA, сертификаты, ключи и независимый bearer; `SERVER_TLS_IDENTITY`, `CLIENT_TLS_IDENTITY`, обе key-pair проверки и `BEARER_SECRET_MATCH` — PASS | Сохранить текущие материалы, не пересоздавать при ошибках следующего шага; проверить реальные TLS рукопожатия |
| PS-V1-05 | **OWNER PASS** | Действующий `fortis-gateway` сообщён `healthy`, UID:GID `10001:10001`, `fortis-review-secrets` смонтирован только RO; четыре Gateway-файла пока **staged на Windows** | Не путать preflight тома с фактом установки файлов |
| PS-V1-06 | **OPEN — следующий шаг** | Без перезапуска Primary положить `server-ca.pem`, `client.pem`, `client.key`, `secret.txt` в отдельный `/run/fortis-secrets/owner-shell/` внутри существующего volume, не изменяя прочие credentials | Нужны readback от UID 10001:10001, directory `0700`, files `0600`, совпадение/валидность; **нет подтверждённого `OWNER_SHELL_CLIENT_MATERIAL_READY`** |
| PS-V1-07 | **OPEN** | После подтверждённой установки убрать из обычного Windows staging дубли клиентского ключа и bearer и вынести **закрытые CA-ключи** в защищённое offline-хранилище/резервную копию, не доступную запущенному Executor | Не удалять единственную копию до проверенного Docker readback и резервного сохранения; серверный ключ и bearer Windows остаются у учётной записи Executor по определению |
| PS-V1-08 | **OPEN** | Вручную запустить отдельный `Start-OwnerPowerShellExecutor.ps1` **без elevation** на `127.0.0.1:10443`, с защищёнными Windows-серверными файлами и SQLite receipts вне Git | Проверить mTLS: отказ без сертификата/с неверным CA, отказ с неверным bearer, правильный capabilities read с клиентским сертификатом; без команд на этом этапе |
| PS-V1-09 | **OPEN** | Проверенный Gateway image/release: Owner Portal содержит PowerShell tab/routes и trusted `FORTIS_OWNER_SHELL_CONFIG` с ровно `port,serverCA,clientCert,clientKey,secretFile`, отдельный RO mount и exact source SHA | CI/source admission, штатные Check/Apply/Backup/Promote и live readbacks по UC-GW-005; **не** редактировать текущий контейнер вручную и не ослаблять существующие guards/uncertain preservation |
| PS-V1-10 | **OPEN — приёмка V1** | Из браузера owner WebAuthn → PowerShell `Get-Date` → реальный результат Windows + exit code + UUID/receipt | Отрицательные session/CSRF проверки, тот же UUID не повторяет выполнение, неверный UUID/команда не подменяет receipt, тайм-аут/сбой не объявляет успехом; проверить безопасную ручную остановку/повторный запуск и сохранность receipts |

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

## Own API onboarding — Observatory и единый workflow собственных API (2026-11-10)

**SOURCE PLAN / не Production approval.** Этот раздел — единственный Gateway-specific backlog для подключения собственного Observatory API и будущего общего Use Case. Нормативные механизмы уже принадлежат [UC-GW-002/003](use-cases/integrations.md), [UC-GW-004](use-cases/credential-lifecycle.md), [UC-GW-005](use-cases/releases.md), [UC-GW-009](use-cases/incidents.md) и [extension contract](INTEGRATION-EXTENSIONS.md); не создавать параллельный список в README/UC. Источники PowerShell Executor/его V1 этапы и Windows actions принадлежат другому чату и [Mirror backlog](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/BACKLOG-IMPROVEMENTS.md). Owner Shell — второй архитектурный пример, **не** часть разрешённых изменений этой задачи. [Датированный handoff](HANDOFF-OBSERVATORY-OWN-API-2026-11-10.md) — снимок передачи контекста, не нормативный backlog.

**Текущее evidence:** [PR #46](https://github.com/AlexPastukhh/fortis-approvals/pull/46) (provider `bf7cc3f419e58661a90f22bf9b1014ae2e57cd05`), [PR #47](https://github.com/AlexPastukhh/fortis-approvals/pull/47) (исправление `reporting_session_id`, `eaf675df81c948729df70ebbc73487d1aa57c25e`) замержены; CI успешны. `fortis_approvals/integrations/observatory/` содержит **только read-only source** `health`/`list_sessions`; фактический extensions catalog Primary пуст, Observatory ещё не активирован. Прямой авторизованный Repo → Observatory `health`/`sessions` работал (9 сессий после запуска контейнера), но это **не** acceptance маршрута Approvals → Observatory. `observatory_and_notifier/main` на проверке `3ec3f725a7d5bd4d2e7a43798d56f275a72745ae` (Initial commit); установленный Observatory image не привязан к проверенному Git source.

**Общий блокер credentials (OWNER PASS, без независимого Docker Engine readback от этого чата):** владелец сообщил об установке четырёх mTLS-файлов в `fortis-review-secrets/owner-shell/` (подкаталог `10001:10001/0700`, файлы `0600`), в то время как корень volume — `root:root/0755` и **непустой**. `extensions/vault.py:CredentialVault.initialize()` отвергает такой корень с `CREDENTIAL_ROOT_NOT_EMPTY`. Owner Shell — работа другой задачи; **не менять корень, каталог, файлы, mounts или PS-V1 статусы**. Его PS-V1-06 evidence находится в чужом task worktree; публикация этого task по сообщению владельца имела `UNCERTAIN`. Не переносить чужой коммит, не повторять push/merge и не выполнять cleanup — расследовать только по UC-GW-009 владельцем соответствующей задачи.

### Задачи и проверяемые критерии

Все ID `OWNAPI-01`–`OWNAPI-09` закреплены здесь; статус означает **состояние всей задачи**, а не наличие отдельного теста. Общий запрет до отдельного owner GO: **никакого** `Credential`/`Apply`/`Backup`/`Promote`, `chown/chmod`, миграции vault, изменения TLS/сети/volume, перевыпуска mTLS, перезапуска сервисов, отзыва прямого Repo token и внешних write/POST. Документальные PR/CI — отдельно по UC-CONT-002/003.

**OWNAPI-01 — исходники и воспроизводимый релиз Observatory.** **BLOCKED (provenance missing)**; owner: Observatory API source + владелец Docker host; предпосылки: безопасный owner-provided read-only image/container inventory, не требуется изменение Gateway. Проверить `observatory_and_notifier/main`, `fortis-container/tools/observatory-api/README.md`, Docker image ID/labels/entrypoint/mounts без secret values; сопоставить фактические исполняемые файлы, Dockerfile, locked dependencies, тесты и CI с Git SHA. **Готово:** задокументирован единственный действующий source owner; принят Git commit с воспроизводимой сборкой и image provenance, immutable image digest, проверенной схемой данных и rollback/upgrade контрактом, подтверждённым отдельно от runtime rollout. **STOP:** исторические `tunnel/observatory` и `fortis-workflow-v1-20261024/observatory` не объявлять live и не переписывать работающий image/архив.

**OWNAPI-02 — доверенный transport Approvals → Observatory.** **PROPOSED (plaintext HTTP не принят)**; owners: Observatory server + `integrations/observatory/transport.py` в Fortis; зависит от OWNAPI-01 (фактический server build/compatibility), согласования trust boundaries. Подготовить threat model, TLS 1.3 с проверкой имени/CA, private Docker network/ingress allowlist, server cert lifecycle и negative TLS/Host/redirect tests; оценить штатный `extensions/http.py:JSONAPI` либо scoped transport при нестандартном порту. **Готово:** принятый source PR обеих сторон, отсутствие unverified/plaintext bearer, отказ wrong cert/identity и проверенная route allowlist. **STOP:** не принимать `HTTPConnection(host.docker.internal,18756)` как Production, не открывать произвольные URL.

**OWNAPI-03 — сетевой маршрут именно из Approvals.** **OPEN (Repo-only verified)**; owners: Fortis runtime/network + Observatory runtime; зависит от согласованного варианта OWNAPI-02 для финального acceptance, начальный preflight независим. Проверить read-only Windows Docker `inspect` networks/listeners/ports обоих контейнеров, current Primary identity, ingress и DNS без secrets; отличить доступность Repo → `18756` от Approvals → upstream. **Готово:** точная проверенная топология и после отдельного rollout успешный pinned identity/HTTPS health из Gateway, отрицательный тест нерегистрированного клиента. **STOP:** не подключать bridge/не изменять published ports без owner-approved change.

**OWNAPI-04 — отдельный upstream-клиент и его жизненный цикл.** **BLOCKED (credential не выпускался)**; owners: Observatory API + owner-only provisioning, Gateway vault binding; зависит от OWNAPI-01/02/03/05. Исследовать установленный `clients.json` contract через безопасные metadata/исходники, определить service principal `fortis-approvals`, минимальные `read:metadata`/нужные scopes, chat policy, future-session policy, ввод нового ключа только через владельца и `UC-GW-004`. **Готово:** owner-provision receipt, новый alias `observatory-api` в поддерживаемом vault, readback через Gateway, документированный revoke/rotate/recovery без token disclosure. **STOP:** не использовать Windows owner/Repo token, не создавать secret в Git/Workfiles/AI.

**OWNAPI-05 — vault compatibility с Owner Shell (общая зависимость).** **BLOCKED (не выбран дизайн)**; owners: Fortis `extensions/vault.py` + `deploy/Manage-Integrations.ps1` и owner с консультацией Owner Shell team; начальный шаг **только read-only**, до OWNAPI-04/07. Предварительно сверить labels `io.fortis.credentials`, корневой UID/GID/mode, **только имена/типы** существующих entries, mounts/consumers/rollback records; не читать содержимое ключей. Выбрать и записать owner decision:
A) контролируемое изменение метаданных **только корня** существующего volume (минимум source/mount изменений, но затрагивает shared root);
B) `/run/fortis-secrets/credentials/` с изменением runtime/CLI/controller (разделяет ключи, больше source/CI/release работ, защищает текущие metadata);
C) второй volume + явно два verified mounts и release records (текущий `-VaultVolume` **заменяет**, а не добавляет mount);
D) перенос Owner Shell (максимальный риск, вне scope этой ветки).
**Готово:** read-only evidence, выбранный owner-reviewed контракт, отдельные тесты непустого vault, migration dry-run/backup/rollback/alias generations/rotation, проверенное сохранение Owner Shell материала. **STOP:** не выполнять `Credential`, `Apply`, `chown/chmod`, миграцию или PS-V1 изменение только по этому плану.

**OWNAPI-06 — прямой Repo → Observatory и обход Gateway.** **OPEN (direct READ VERIFIED, effective write grants need inventory)**; owners: `fortis-container/tools/observatory-api` + Observatory authorization, согласование с Gateway; зависит от OWNAPI-01, перед отключением write — OWNAPI-07/08. Изучить `fortis_observatory_client.py`, `Enable-FortisObservatoryRepoClient.ps1`, список потребителей POST `/v1/events` и `/v1/messages`, серверные разрешения и конкретные chats; построить ACL matrix для read/receipt/write через direct и Gateway. **Готово:** owner-approved migration matrix, read-only direct credential или документированное исключение, отрицательный тест прямого unauthorized write и отсутствие потери доставки. **STOP:** не отзывать текущие права, не удалять direct client до полного dependency/readback.

**OWNAPI-07 — release admission и live provider acceptance.** **BLOCKED (source merged, catalog empty)**; owner: Fortis Approvals image/config + owner-controller; зависит от OWNAPI-02/03/04/05 и оценки OWNAPI-06; точный Docker/GitHub main сверять заново. Проверить `integrations/observatory/extension.py`, public config `health(service)`/`list_sessions(registry)`, `deploy/Manage-Integrations.ps1`, `docs/PRIMARY-GATEWAY-OPERATIONS.md`, UC-GW-005; подготовить exact SHA, source manifests, CI, protected records, read-probes и rollback plan. **Готово:** отдельно подтверждён owner-run `Check → Apply/activation → Backup/Promote`, healthy Primary, catalog + authenticated read/deny from Repo, immutable acceptance evidence; не называть source merge Production. **STOP:** не применять по одному успешному CI или Repo direct health.

**OWNAPI-08 — writes, receipts, идемпотентность и UNCERTAIN.** **OPEN (design before code)**; owners: Observatory API + `integrations/observatory/extension.py` + Fortis Core; зависит от OWNAPI-01/06 для текущего upstream effect contract, от OWNAPI-02/04/07 для live acceptance. Специфицировать typed POST для events/messages, `requestId` и replay scope, preview + exact intent, durable stage/actual-effect receipts, server idempotency, read-only lookup и `result(reconcile=False)`/UC-GW-009 при `UNCERTAIN`; `staging_only` не означает delivery/archive. **Готово:** отдельный source PR, негативные retry/timeout/lost-response/wrong-actor/target/receipt tests и owner-approved policy для каждого write; позже live stage + verified readback без двойного эффекта. **STOP:** не тестировать новые POST на пользовательских сессиях, не ставить `ALLOW` для опасных effects без отдельного решения.

**OWNAPI-09 — общий Use Case для собственного API.** **PROPOSED (UC-GW-010 свободен в принятом локальном реестре на 2026-11-10)**; owner: `fortis-approvals/docs/use-cases/` и его [локальный registry](use-cases/README.md); зависит от анализа OWNAPI-01/02/05/06/08 и подтверждения границ Owner Shell командой-владельцем. Кандидат `UC-GW-010` должен описывать `Когда/Цель/Как/Готово`, server **и** Gateway source-of-truth, trust boundaries/risk classification, mutual identity, credential/bypass inventory, fixed schemas, preconditions/receipts/UNCERTAIN, CI, owner release, live acceptance, restore/rotation. **Ветки:** machine API (Gateway extension + ALLOW/ASK/DENY) и owner-only API (owner authorization/WebAuthn, не generic machine provider). Ссылаться на UC-GW-002/003/004/005/009 и UC-CONT-002/003, не копировать контракты; PowerShell V1 — только второй пример. **Готово:** отдельный нормативный UC PR + exact-SHA CI + owner merge, запись в локальном реестре **только после принятия**, единый owner без второго backlog. **STOP:** не назначать `UC-GW-010` статус ACTIVE и не менять Owner Shell источники по этому документальному PR.

**Рекомендуемая последовательность:** параллельный read-only preflight OWNAPI-01, OWNAPI-03, OWNAPI-05 и inventory OWNAPI-06 → owner review для OWNAPI-02/05 → OWNAPI-04 → OWNAPI-07 (первый read-only live путь) → OWNAPI-08 (write отдельно). OWNAPI-09 готовить по мере фиксации инвариантов, не утверждая его до merge. Каждое вмешательство в Windows/Docker/credential требует отдельной owner authorization; отсутствие прямого эффекта Git/docs не даёт такого разрешения.

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

- **Открыто:** `WorkflowClient.result(UUID)` в `main` по-прежнему не
  передаёт `accept_202=True` в transport. В
  `task/native-client-pending-status-20261106` есть **незакоммиченный**
  diff и регрессионный тест. Не объявлять исправление принятым: сначала
  проверить task/source/CI, затем отдельный PR и совместимость.
  Обновление только Repo-side client не требует Gateway image release.
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
