# Fortis Approvals Gateway — текущее состояние работающей системы

> **СТАТУС: ДЕЙСТВУЮЩИЙ CURRENT STATE.** Первоначальный срез 2026-11-03 дополнен live revalidation от 2026-11-04. Это нормативный источник текущего состояния Fortis, работающего Sonar-пилота и оставшихся задач. Старые планы и handoff — только архивные свидетельства.
>
> Историческая матрица проектирования и acceptance gates от 2026-11-01 сохранена в [`FORTIS-UNIVERSAL-GATEWAY-ACCEPTANCE-MATRIX-20261101.md`](../../fortis_approvals/deploy/FORTIS-UNIVERSAL-GATEWAY-ACCEPTANCE-MATRIX-20261101.md); после live Gateway/Sonar evidence она не является источником текущего статуса.

Для AI-агентов и подключения новых credentialed-сервисов используйте [Gateway agent guide](../GATEWAY-AGENT-GUIDE.md). Этот current-state документ остаётся источником фактов о том, что действительно развёрнуто и подтверждено; guide описывает целевую роль Gateway и безопасный процесс расширения, не объявляя будущие интеграции уже работающими.

## 1. Итоговый статус

**Fortis Approvals Gateway работает в live-режиме для одного AI actor и одного закреплённого SonarCloud project.** R7/P1/P2 — исторические идентификаторы реализации и развёртывания; новая схема нумерации версий сейчас не вводится. Уже выполнены trusted provisioning, запуск Fortis Approvals Gateway, регистрация owner WebAuthn, подключение Fortis Repo к Gateway через read-only client mount и реальные операции с Sonar Issues.

| Контур | Текущее состояние | Основание |
| --- | --- | --- |
| GO-1 — TLS identity, machine grant, private Sonar token provisioning | **PASS — owner-reported** | Windows provisioning завершён; секреты остаются в доверенных volumes Gateway |
| GO-2 — Gateway runtime и owner WebAuthn enrollment | **PASS — owner-reported** | Gateway запущен; owner approval реально выполнен |
| GO-3 — Fortis Repo client mount / recreate | **PASS — owner-reported** | `fortis-r7-client` подключён к Repo read-only; live typed READ/ASK работает |
| Deployed image build и installed-source audit | **PASS — owner-reported** | Image ID `sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402` |
| Live Sonar READ и report | **PASS — live** | Получены реальные projects, issues и Quality Gate |
| Live ASK → PENDING | **PASS — live** | Создана настоящая заявка `sonarcloud.accept_issue` |
| Owner WebAuthn Approve → Sonar ACCEPTED | **PASS — live** | 2026-11-04: Request `2db54607-f0c3-4f43-9597-f73f54ea46af` имеет `EXECUTED`; независимый GET Issue `AaGC4d9TJxEkuf26a_ZY` вернул `ACCEPTED`; см. evidence от 2026-11-04 |
| Live Reject без Sonar mutation | **PASS — live status + readback** | 2026-11-04: Request `2b3580dc-6a88-4f44-a1e6-9a7097c84b0c` получил `REJECTED`; независимый GET Issue `AaGC4d9TJxEkuf26a_ZX` остался `OPEN`; packet trace не снимался |
| Historical owner Approve / Reject | **PASS — live, 2026-11-03** | Предыдущие request IDs и issue readbacks сохранены в [evidence от 2026-11-03](../../fortis_approvals/evidence/FORTIS-SONAR-LIVE-E2E-20261103.md) |

**Это не означает, что весь Fortis production roadmap завершён.** Узкий одноакторный Sonar READ/ASK/Reject/Approve сценарий работает. Multi-agent, автономное планирование запусков, RDG G3 и защищённая GitHub→Windows доставка — отдельные оставшиеся направления.

## 2. Как устроена работающая топология

```text
AI / ChatGPT
    │ вызывает обычную команду процесса Fortis Repo
    ▼
Fortis Repo container (недоверенная рабочая среда)
    │ typed operations over TLS 1.3
    │ client grant + public server certificate, read-only mount
    ▼
ОДИН Fortis Approvals Gateway container
    ├── authenticated machine ingress
    ├── Core / policy / durable request state
    ├── Owner Portal + WebAuthn / Pending / History
    ├── private Sonar token store
    └── typed SonarCloud adapter
             │
             ▼
         SonarCloud
```

- **Approval application находится в Fortis Approvals Gateway, а не в Fortis Repo.** Repo не содержит отдельного Approval-сервера, owner DB, owner private key или Sonar token. Repo отправляет typed request в Fortis Approvals Gateway.
- Owner Portal и machine ingress — разные защищённые маршруты одного Fortis Approvals Gateway runtime. Owner Portal: `http://localhost:19103`; machine ingress: `https://host.docker.internal:19104`.
- Repo-side client закреплён на фиксированном gateway origin, TLS 1.3 и фиксированных маршрутах. Он не принимает произвольные URL, HTTP methods, headers или upstream credentials.
- В Fortis Approvals Gateway используются четыре server volumes: `fortis-r7-state` (RW), `fortis-r7-identity` (RO), `fortis-r7-grant` (RO), `fortis-r7-sonar-token` (RO). В Repo подключён отдельный `fortis-r7-client` (RO), содержащий только client grant copy и публичный сертификат сервера.
- Machine grant доступен процессам UID 1000 внутри общего Repo container. Это приемлемая граница текущего single-actor pilot, но не изоляция нескольких независимых AI actors.

### Фактические контейнеры и volumes

Снимок owner docker inspect от 2026-11-03 зафиксировал текущий Repo container fortis-repo-test с ID 04fed7b726a8536d63c4d2533cfc7ee3072956ff0c3f571504d7f709f7909030:

| Контур | Mount / endpoint | Режим | Содержимое и роль |
| --- | --- | --- | --- |
| Repo | fortis-r7-client → /run/fortis-client | **RO** | Client grant и публичный сертификат Gateway; Sonar token отсутствует |
| Repo | fortis-repo-workspace → /workspace/files | RW | Workfiles внутри общего Repo workspace |
| Repo | fortis-repo-workspace → /workspace/repo | RW | Внутренний Docker workspace и передаваемые артефакты |
| Repo | fortis-repo-workspace → /workspace/repos | RW | Исходники, включая /workspace/repos/rd-graphs |
| Gateway | fortis-r7-state → /state | RW | approvals.sqlite, owner.sqlite, sonar-receipts.sqlite под /state/private |
| Gateway | fortis-r7-identity → /run/r7-identity | RO | server.crt и закрытый server.key |
| Gateway | fortis-r7-grant → /run/r7-grant | RO | Machine ingress grant |
| Gateway | fortis-r7-sonar-token → /run/r7-sonar-token | RO | Закрытый SonarCloud token; в Repo не монтируется |

Repo также подключён к сетям fortis-repo-egress и rdg-personal_agents. Fortis Approvals Gateway публикует только loopback-порты 127.0.0.1:19103 (Owner Portal) и 127.0.0.1:19104 (machine ingress). Existing Compose reference задаёт Gateway `read_only: true`, UID 10001:10001, cap_drop: ALL, no-new-privileges и healthcheck.

**Для текущего одноакторного пилота дополнительный volume не требуется.** Не запускать повторно provisioner/cutover и не создавать дубликаты volumes.

## 3. Что AI уже может делать самостоятельно в активной сессии

AI может вызвать существующий процессный инструмент Fortis Repo и выполнить `fortis_approvals.sonar_review_scenario`. Отдельная регистрация набора `sonar.*` MCP tools не нужна: используется уже доступный Fortis Repo process execution и фиксированный Python client.

```sh
cd /workspace/repos/rd-graphs
python3 -m fortis_approvals.sonar_review_scenario review \
  --issue-key ISSUE_KEY \
  --reason "Краткое обоснование предложения владельцу"
```

Команда выполняет через typed client:

1. Проверяет видимость закреплённой организации и проекта.
2. Читает страницу Issues и Quality Gate.
3. Делает точный GET выбранной Issue и проверяет её актуальный статус.
4. Создаёт одну Fortis ASK-заявку `sonarcloud.accept_issue`.
5. Возвращает request ID, report и состояние `PENDING`.

### Уровни и маршруты запросов

| Уровень | Что происходит | Разрешённые маршруты |
| --- | --- | --- |
| AI → Repo | AI запускает существующий процессный сценарий; token и URL не передаются | `review`, `status` |
| Repo → Gateway | TLS 1.3 machine ingress с отдельным grant | `POST /v1/reads`, `POST /v1/actions`, `GET /v1/requests/{requestId}` |
| Gateway → Sonar, READ | Отдельный GET-only adapter с allowlist маршрутов и project/org scope | `GET /api/components/search`, `GET /api/issues/search`, `GET /api/qualitygates/project_status` |
| Gateway → Sonar, WRITE | Только после owner WebAuthn Approve и повторной проверки frozen preview | один `POST /api/issues/do_transition` с `transition=accept`, затем независимый GET |

Таким образом, слово «GET» относится к реальным Sonar read-запросам. Machine ingress принимает typed envelope через POST, но не является произвольным HTTP proxy.

Проверка состояния заявки:

```sh
python3 -m fortis_approvals.sonar_review_scenario status \
  --request-id REQUEST_UUID
```

Сценарий использует организацию `alexpastukhh` и project `AlexPastukhh_obs-planning-docs`, закреплённые в коде. Он не принимает project, URL, token или transport от произвольного AI input.

**Важно:** команда читает уже существующие результаты SonarCloud. Она **не запускает новый GitHub Actions workflow и не инициирует новый Sonar analysis**. AI может запустить её в ответ на задачу в активной сессии; фонового агента, периодического мониторинга и самостоятельного пробуждения между сессиями пока нет.

## 4. Подтверждённое live Sonar E2E

**Последняя revalidation — 2026-11-04: PASS.** После запуска Gateway владельцем typed Repo client успешно прочитал Sonar, создал две реальные ASK-заявки, получил owner Reject (`REJECTED`, Issue осталась `OPEN`) и owner WebAuthn Approve (`EXECUTED`, независимый Sonar GET вернул `ACCEPTED`). Полные request IDs и Issue details: [Fortis live Sonar E2E, 2026-11-04](../../fortis_approvals/evidence/FORTIS-SONAR-LIVE-E2E-20261104.md).

Первоначальный live snapshot 2026-11-03 получил:

- один разрешённый project `AlexPastukhh_obs-planning-docs`;
- 275 Issues всего, 100 записей на первой странице, `hasMore=true`;
- Quality Gate `OK`, scope `CURRENT_DEFAULT_BRANCH`;
- PR/SHA binding `NOT_VERIFIED_D2` — этот отчёт не доказывает статус конкретного PR или commit SHA.

Подтверждённые owner decisions в текущем evidence snapshot:

| Request ID | Issue key | Fortis state | Результат |
| --- | --- | --- | --- |
| `67eaccd8-24dc-4eeb-a7da-547b334bcdc5` | `AaGC4d7SJxEkuf26a_Wg` | `REJECTED` | Sonar mutation не dispatch'ится по no-dispatch пути |
| `2b1e6b0f-7c4e-4dd2-bc4b-81c93e6c0d2f` | `AaGC4d7SJxEkuf26a_Wh` | `EXECUTED` | Sonar `ACCEPTED` после owner WebAuthn Approve и readback |

Для Reject status-команда owner portal вернула `REJECTED`. Для Approve заявка сначала была `PENDING`, затем после свежего owner WebAuthn стала `EXECUTED`; live evidence фиксирует изменение реальной Issue в SonarCloud. Отдельная трассировка пакетов не снималась, поэтому количество POST подтверждается реализационным контрактом и итоговым readback, а не сетевым packet capture.

`ACCEPTED` означает изменение статуса Issue в SonarCloud. Это **не исправление исходного кода**, не закрытие Issue как исправленной и не подтверждение, что предупреждение устранено.

Полный обезличенный evidence record: [Fortis live Sonar E2E, 2026-11-03](../../fortis_approvals/evidence/FORTIS-SONAR-LIVE-E2E-20261103.md).

## 5. Границы исполнения и безопасности

- Разрешена одна typed mutation: `sonarcloud.accept_issue` / Sonar transition `accept`.
- Каждая Issue — отдельная заявка и отдельный свежий owner WebAuthn Approve. Bulk actions, arbitrary Sonar writes, close/resolve, raw HTTP и произвольный transport не предоставляются.
- AI может читать, формировать ASK и читать status. AI не может approve/reject от имени владельца, читать Sonar token или вызывать owner/execute routes.
- До Approve выполняется read-only preview. После Approve Core повторно проверяет policy version, expiry, active grant и frozen Issue preview. Исполнитель выполняет точный transition, затем независимый GET readback и сохраняет durable execution result.
- Нормальный state machine: `PENDING → REJECTED` без adapter dispatch либо `PENDING → APPROVED → DISPATCHED → EXECUTED`; при изменении preview/policy используются `STALE`/`EXPIRED`, а неоднозначный удалённый результат остаётся `UNCERTAIN`.
- Reject не dispatch'ит adapter и не отправляет Sonar POST. Слепого повторного POST быть не должно.
- SonarCloud не предоставляет atomic compare-and-set для issue transition. Между последним GET и POST остаётся race с параллельным внешним writer; это известное ограничение.
- Sonar token хранится только в Fortis Approvals Gateway. Repo получает ограниченный machine grant и публичный сертификат; machine grant не является Sonar token.

## 6. Что действительно остаётся сделать

Следующие пункты **не являются блокерами уже работающего одноакторного Sonar E2E**. Это отдельные расширения или production-hardening gates.

| Направление | Статус |
| --- | --- |
| AI-triggered GitHub Actions `workflow_dispatch` для запуска нового scan | **NOT IMPLEMENTED**; текущий сценарий читает последний доступный Sonar результат |
| Фоновый scheduler / постоянный AI issue monitor / дедупликация повторных заявок | **NOT IMPLEMENTED** |
| Multi-agent: отдельные machine identities, grants, scopes и actor isolation | **NOT IMPLEMENTED**; текущая модель — один actor в общем Repo container |
| RDG G3: FREE/ASK enforcement через авторитетный RDG writer и Navigation Bridge | **NOT IMPLEMENTED**; RDG продолжает использовать собственный writer/guards |
| D1/D2: GitHub PR, required checks, scan/run/analysis/commit SHA binding | **NOT IMPLEMENTED** |
| D3/D4: trusted Windows Importer, quarantine/AV, exact SHA admission, обязательный owner RUN и защищённое self-update | **NOT IMPLEMENTED** |
| Полный production supply-chain review: base-image provenance, SBOM/CVE, backup/restore, adversarial prompt-injection acceptance и полный grant rotation/revocation lifecycle | **PARTIAL / OPEN** |
| Полный pinned WebAuthn/HTTPS offline suite в Linux Repo | **BLOCKED в этой среде** из-за отсутствующих pinned `cryptography`/`fido2`; это не отменяет успешный live owner WebAuthn Approve |

## 7. Эксплуатационные указания

- Не повторять GO-1 provisioning, GO-2 owner enrollment или GO-3 Repo recreate: эти действия завершены.
- Не использовать старые G2/G4/R5/A3 демонстрационные сервисы как текущий production путь. Они относятся к прежним лабораторным этапам.
- Не запускать старые `Prepare-R7-Candidate.ps1`, `Provision-R7-P1-Trusted-20261102.ps1`, `Invoke-GO3-Repo-Cutover*.ps1` или старые P1 Compose/runbook. Это одноразовые исторические операции, не команды обычной работы.
- Не удалять и не пересоздавать пять существующих Approval volumes (четыре server volumes и `fortis-r7-client`) и общий `fortis-repo-workspace`. Не менять TLS, grants, Sonar token, Gateway/Repo containers и MCP bridge без отдельной задачи и owner authorization.
- Исторические source review, preflight, provisioning и cutover материалы сохранены в `fortis_approvals/archive/20261103-pre-live-doc-cleanup/` и исходном RDG каталоге `/workspace/repos/rd-graphs/docs/handoffs/`. Их старые next-step инструкции superseded этим документом.

## 8. Исходники и тесты

Ключевые реализации: `fortis_approvals/core.py`, `owner_auth.py`, `owner_portal.py`, `r7_unified_server.py`, `r7_unified_candidate.py`, `repo_action_contract.py`, `repo_ingress.py`, `repo_sonar_tools.py`, `sonar_read.py`, `sonar.py`, `sonar_review_scenario.py`. Runtime reference: `fortis_approvals/deploy/compose-r7-p2-20261103.yaml`.

Адресные source tests: `test_r7_unified_candidate.py`, `test_r7_p2_webauthn_execute_static.py`, `test_repo_sonar_tools.py`, `test_sonar_review_scenario.py`, `test_sonar_read_adapter.py`. Их результаты не заменяют live evidence, приведённое выше.

Карта кода и текущие команды: [fortis_approvals README](../../fortis_approvals/README.md). Исторические Fortis handoffs остаются в исходном RDG checkout по пути `/workspace/repos/rd-graphs/docs/handoffs/README.md`; они сохранены отдельно от этой локальной extraction candidate и не заменяют текущий статус.


## 9. Разделение рабочей копии исходников и активного Fortis Approvals Gateway runtime

### Рабочая копия

- Оригинальная рабочая копия исходников остаётся в `/workspace/repos/rd-graphs/fortis_approvals` внутри общего Repo workspace. Этот каталог доступен AI-процессам Repo для чтения и изменения; в родительском `rd-graphs` он не отслеживается Git и окружён другими незакоммиченными изменениями.
- 2026-11-03 создана отдельная копия исходников: `/workspace/repos/fortis-approvals/fortis_approvals` (196 non-generated files, original SHA-256 manifest matched at extraction). Владелец утвердил её как canonical development source и отдельный репозиторий; локальный Git инициализирован на `main`, коммита и remote пока нет. Это не deployed copy; оригинальный RDG working tree оставлен нетронутым.
- Оба каталога являются рабочими копиями исходников, а не файловой системой работающего Fortis Approvals Gateway. Repo workspace подключён к Fortis Repo как RW. Изменение `fortis_approvals/*.py` в любой из этих копий само по себе не меняет уже работающий Gateway.

### Активная копия Gateway

- Fortis Approvals Gateway запускается из Docker image `fortis-r7-unified-read-ask-candidate:review-p2-20261103-a3e87c0c`; зафиксированный image ID: `sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402`. Эти старые image labels сохраняются здесь для точной идентификации уже собранного артефакта, а не как предлагаемая схема новых имён.
- Runtime source находится внутри image под `/opt/fortis/fortis_approvals`. Build script `Build-R7-Windows-ImageOnly-p2-20261103.ps1` pins `Dockerfile-R7-Unified-Read-Ask-Candidate` and an exact source allowlist for the supplied deployed image. Offline audit проверял SHA256 19 установленных source-файлов. Не путать его с top-level `deploy/Dockerfile`, который запускает отдельный старый `fortis_approvals.server` entry point.
- Действующий Compose reference не монтирует `/workspace/repos` или рабочий каталог исходников в Gateway. В Gateway подключены только отдельные volumes состояния и секретов, перечисленные в разделе 2.
- Следовательно, Repo AI может редактировать рабочие исходники, но не получает прямого файлового доступа к установленной копии кода активного Gateway. Для изменения работающей версии необходим отдельный процесс подготовки source package, сборки/проверки image и явно разрешённого deployment.
- В image включён runtime allowlist, а не весь каталог разработки: тесты, исторические скрипты, документация и Repo-side client не следует считать частью установленного Gateway runtime.

### Граница доступа

- AI имеет ограниченный API-доступ к Fortis Approvals Gateway через machine ingress: READ, создание ASK-заявки и чтение статуса. Это функциональный доступ через проверяемые маршруты, а не доступ к файловой системе или процессу контейнера Gateway.
- В текущей доступной среде Repo проверено отсутствие `/var/run/docker.sock`. Это подтверждает отсутствие стандартного Docker socket в проверенном контейнере, но не является аудитом всех возможных административных каналов хоста.
- Image/build/deploy-файлы в Repo являются материалами разработки и воспроизводства. Их изменение не является изменением активного runtime до отдельной процедуры сборки и развёртывания.

## 10. Фактическая доступность /run/fortis-client в Repo

Проверка выполнена из активной среды Fortis Repo 2026-11-03. Содержимое credential не читалось и не выводилось.

| Объект | Фактические права / состояние | Результат проверки |
| --- | --- | --- |
| Repo process | UID/GID `1000:1000` (`node`) | Текущий процесс работает как владелец grant |
| `/run/fortis-client` | `root:root`, mode `0755`; volume mount RO | Каталог доступен для прохода |
| `/run/fortis-client/grant` | `node:node`, mode `0600` | Читается процессом Repo с UID 1000 |
| `/run/fortis-client/server.crt` | `node:node`, mode `0644` | Читается; это публичный сертификат сервера |

- `fortis-r7-client` подключён в Repo по пути `/run/fortis-client` как read-only volume. Проверка mount показала опцию `ro`.
- Read-only mount запрещает обычную запись, замену и удаление файлов через этот путь. Поэтому случайно испортить содержимое volume обычной записью из Repo через данный mount нельзя.
- Read-only не означает unreadable: текущий Repo process действительно может прочитать `grant`, поскольку файл принадлежит UID 1000. AI-процесс в том же пользовательском контексте может получить и использовать этот machine credential.
- Grant является ограниченным credential для machine ingress, а не SonarCloud token, не owner credential и не WebAuthn private key. Его использование подчиняется серверным actor grants и policy.
- `server.crt` — публичный сертификат, используемый клиентом для проверки TLS-сервера; его доступность AI сама по себе не раскрывает закрытый ключ.
- Текущее состояние фиксируется как **RO mount, но credential readable by Repo UID 1000**. Это не следует описывать как write-доступ AI к volume и не следует описывать как секрет, недоступный AI.

На момент этой редакции mount, права, grant, сертификат и конфигурация контейнеров не изменялись.

## 11. Git и восстановление: фактическое состояние на 2026-11-03

### Текущее состояние Git

- Рабочая копия `/workspace/repos/rd-graphs` находится в Git-репозитории `rd-graphs`, ветка `main`, remote `origin` указывает на `https://github.com/AlexPastukhh/rd-graphs.git`.
- Проверенный HEAD на момент осмотра: `176ce44` (2026-10-23, `Preserve portable copies and expose one application API to Agent and Viewer`).
- Каталог `fortis_approvals/` и находящиеся в нём исходники, tests, deploy-файлы, evidence и README на момент проверки Git не отслеживались (untracked). Этот Fortis current-state документ также untracked.
- В родительском `rd-graphs` worktree присутствуют и другие staged/modified/untracked изменения, не относящиеся к Fortis. Нельзя считать весь текущий worktree чистым или готовым к единому коммиту.
- Отдельный локальный Git-репозиторий `/workspace/repos/fortis-approvals` создан и принят владельцем как canonical development source. Он находится на `main`; commit и remote пока не созданы.
- `fortis-container` также имеет отдельный локальный Git-репозиторий на `main`; commit и remote пока не созданы. Qwen остаётся в `/workspace/files/Qwen-Fortis-MCP` и отдельный репозиторий для него сейчас не планируется.
- В рамках текущей работы файлы не добавлялись в index, коммиты не создавались и push не выполнялся.

### Граница восстановления

- Git должен хранить версионируемые исходники, тесты, документацию, Dockerfile/Compose references, build/package/audit/deploy scripts и manifest/hash records.
- Docker image и его digest — отдельный артефакт сборки. Для воспроизводимого восстановления необходимо сохранить исходный build recipe, точный source allowlist, зависимости и процедуру проверки image.
- Docker volumes с рабочим состоянием, owner/approval database и receipts не входят в Git. Для них нужен отдельный проверенный backup/restore процесс.
- Machine grants, TLS private key, Sonar token и другие секреты не должны попадать в Git. Их восстановление должно опираться на отдельное защищённое owner-controlled provisioning/backup procedure.
- Поэтому одного Git remote недостаточно для восстановления всей работающей системы после потери Docker containers, images или volumes.

### Согласованный порядок дальнейшей работы (пока без внедрения)

1. Завершить и проверить первую версию документации текущего состояния Fortis.
2. Затем спроектировать Git-структуру и резервирование: определить границы репозиториев для приложения/Core, Repo-side tools, Docker/deployment и документации; сохранить build manifests; описать backup/restore volumes и секретов; проверить восстановление на отдельном чистом окружении. Решение «один репозиторий или несколько» пока не принято.
3. Отдельной, более поздней задачей рассмотреть доступ AI к `/run/fortis-client`. До этой задачи текущий RO mount и права не менять.

Этот раздел фиксирует состояние и порядок приоритетов; он не является разрешением на создание репозиториев, изменение Git history, backup volumes, ротацию секретов или изменение runtime.
