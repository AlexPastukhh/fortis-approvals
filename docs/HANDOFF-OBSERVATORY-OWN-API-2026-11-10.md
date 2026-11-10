# Handoff: Observatory / Own API onboarding — Fortis Approvals

**Снимок 2026-11-10; SOURCE CANDIDATE до owner merge.** Это передача контекста следующему чату, **не** новый backlog, runtime record, runbook или нормативный Use Case. Единственный Gateway backlog — [BACKLOG-IMPROVEMENTS.md](BACKLOG-IMPROVEMENTS.md#own-api-onboarding--observatory-и-единый-workflow-собственных-api-2026-11-10), задачи `OWNAPI-01`–`OWNAPI-09`. Перед работой перепроверить GitHub/Docker main, PR/CI, логику Gateway, runtime status и параллельные работы. История этого handoff фиксируется как документационный source candidate; его наличие в task branch не равно публикации.

## А. Роль и границы

Владелец направления в этом чате: **собственный Observatory HTTP API и его интеграция через Fortis Approvals**. Входит: API source-of-truth/build; `fortis_approvals/integrations/observatory/`; сетевой/TLS маршрут Approvals → Observatory; upstream service identity и named vault credential; policy/ACL; прямой Repo → Observatory bypass; idempotency, receipts, UNCERTAIN; CI/owner release/live acceptance; дизайн общего Use Case own API.

Другой чат ведёт **Windows PowerShell Executor**, начиная с PS-V1-08 и последующих V1 шагов. Не менять его функциональные требования, owner-only routes/UI, статусы, настройки, mTLS-ключи, Windows процессы и backlog. Owner Shell можно использовать как **второй пример own API**, но не как источник нового machine provider. Credential vault — *общая зависимость*, не разрешение вмешиваться в другой сервис.

Без отдельного owner-approved изменения запрещены: `chown/chmod`, миграция/удаление volume, `Credential`/`Apply`/`Backup`/`Promote`, выдача/отзыв токенов, перестройка networks/TLS, stop/start/restart, чтение приватных ключей, write/POST в действующий Observatory и прямой GitHub push. Git-документацию можно изменить только в собственной task-ветке, через typed Gateway и обычный PR/CI/owner merge.

## Б. Проверенный контекст и границы доказательств

- На подготовке handoff: **Docker `fortis-approvals/main` и GitHub main** `ceeb875daf066fe560f6daf828c80df41aadd658` (проверить снова: параллельная работа продолжается). Source PR #46: `bf7cc3f419e58661a90f22bf9b1014ae2e57cd05`; PR #47: `eaf675df81c948729df70ebbc73487d1aa57c25e`; оба owner-merged, GitHub CI success. Merge PR #47: `124aeec120943fa035d72120b2be7d42ce748230`. Поздние merges были после #47; **не пиновать** runtime на старые source SHA.
- GitHub `AlexPastukhh/observatory_and_notifier/main` `3ec3f725a7d5bd4d2e7a43798d56f275a72745ae` — первоначальный коммит, **не** воспроизводимые исходники установленного API; Docker primary `/workspace/repo/Repos/observatory_and_notifier` отсутствовал.
- Source provider: `fortis_approvals/integrations/observatory/extension.py`, `transport.py`, `README.md`, тесты `tests/test_definition.py` и `test_config.py`. ТОЛЬКО два read-only handlers `health` (`service`) и `list_sessions` (`registry`); перевод `reporting_session_id` → `session_id` принят PR #47.
- **VERIFIED в Repo-контейнере:** `host.docker.internal:18756` доступен, авторизованные `health` и `sessions` прямым `fortis_observatory_client.py` работали (9 сессий, `staging_only`); `host.docker.internal:19204` доступен; live `fortis_approvals.extensions.client.default_client().catalog()` показывал 0 операций / Observatory отсутствовал. Старое `ConnectionRefused` относилось к периоду остановки Observatory и больше не характеризует Repo route.
- **NOT VERIFIED:** Docker image ID/OCI label/server SHA для Observatory; source/build provenance; TLS и сеть **из контейнера Approvals** до Observatory; dedicated Gateway→Observatory client/credential; production activation/readback через Approvals; upstream write receipt/replay. Не считать Repo direct health доказательством end-to-end Gateway.
- **OWNER-REPORTED / PS-V1-06 task source:** четыре Owner Shell mTLS-файла установлены в `fortis-review-secrets/owner-shell/`, подкаталог UID/GID 10001 и `0700`, файлы `0600`, readback UID 10001 — PASS. Корень volume остаётся `root:root/0755`, **непустой**. В принятом `main` PS-V1-06 может оставаться OPEN; не менять статус чужой задачи по неслитому worktree. По сообщению владельца публикация Owner Shell evidence имела `UNCERTAIN`; её исходная заявка относится к другому чату и не повторяется.
- **Source-VERIFIED vault blocker:** `CredentialVault.initialize()` отклонит nonempty `root:root/0755` с `CREDENTIAL_ROOT_NOT_EMPTY`; `Manage-Integrations.ps1` допускает один `-VaultVolume` в `/run/fortis-secrets`. `-VaultVolume` **заменяет**, а не добавляет mount; не переключать его для Observatory, не сохранив Owner Shell.
- **Gateway risk:** в сохраняемых защищённых state records остаётся исторический `CLAIMED` worker (отмечен в `docs/PRIMARY-GATEWAY-OPERATIONS.md` и backlog). `UNCERTAIN` не означает выполнено/не выполнено; полный read-only разбор — UC-GW-009. Это влияет на любые будущие release/backup, но не на текущие документы.

## В. Обязательное чтение нового чата — строгий порядок

1. `/workspace/repo/README.md`, `/workspace/repo/AGENTS.md`; **только короткий вход** `Repos/fortis-container/docs/use-cases/README.md`, не весь каталог.
2. Полностью `Repos/fortis-container/docs/use-cases/delivery.md#uc-cont-002`, `#uc-cont-003`; полностью `Repos/fortis-approvals/docs/use-cases/incidents.md#uc-gw-009`.
3. `Repos/fortis-approvals/AGENTS.md`, `README.md`, `docs/use-cases/README.md` (принятый локальный реестр); UC-GW-002/003: `docs/use-cases/integrations.md`; UC-GW-004: `docs/use-cases/credential-lifecycle.md`; UC-GW-005: `docs/use-cases/releases.md`.
4. `docs/BACKLOG-IMPROVEMENTS.md#own-api-onboarding--observatory-и-единый-workflow-собственных-api-2026-11-10` — **приоритетный единственный план**. `docs/INTEGRATION-EXTENSIONS.md`, `docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md`, `docs/PRIMARY-GATEWAY-OPERATIONS.md`, `docs/CREDENTIAL-ROTATION.md`, `docs/SOURCE-MANIFESTS.md`.
5. При конкретной задаче: `fortis_approvals/integrations/observatory/{README.md,extension.py,transport.py,tests/}`, `fortis_approvals/extensions/{runtime.py,vault.py,cli.py,http.py,client.py}`, `fortis_approvals/deploy/Manage-Integrations.ps1`; из другого source owner — `Repos/fortis-container/tools/observatory-api/{README.md,fortis_observatory_client.py,Enable-FortisObservatoryRepoClient.ps1,add_repo_client.py}`.
6. `Repos/docke-windows-mirror/docs/WORKFLOW.md` для Docker↔GitHub↔Windows; исторические `Repos/tunnel/observatory`, `fortis-workflow-v1-20261024/observatory` не считать installed source.

Дополнительно для нового UC: `Repos/fortis-container/docs/use-cases/orientation.md#uc-cont-017` и `#uc-cont-024`. Локальный UC-реестр содержит `UC-GW-001`–`009`; `UC-GW-010` пока **только кандидат**, не действующий UC.

## Г. Карта ответственности

- `fortis-approvals`: shared policy/actor/WebAuthn/extension Core, Observatory provider source, credential vault/controller, Approvals release. Канонический backlog — `docs/BACKLOG-IMPROVEMENTS.md`.
- `fortis-container`: общий Fortis UC и Repo→Observatory client/runbook, Docker/Repo ownership; **не** источник бинарного API Observatory.
- `observatory_and_notifier`: выбранное имя будущего source owner для Observatory и Notifier; GitHub пока фактически содержит только Initial commit. Не смешивать отдельный Notifier Git repo `tabnotifier-fileautosend-autochat` с действующим backend без provenance review.
- `docke-windows-mirror`: Windows clone workflow и PowerShell Executor source/backlog другого чата.
- `tunnel`: historical Observatory snapshot/other runtime functions; не источник проверки текущего `fortis-observatory-api`.

## Д. Backlog: постоянные ID, статус, зависимости

Все задачи и подробные acceptance/STOP критерии записаны **только** в `docs/BACKLOG-IMPROVEMENTS.md`.

| ID | Статус | Основная зависимость |
| --- | --- | --- |
| `OWNAPI-01` | BLOCKED — upstream source provenance unknown | безопасный owner Docker image metadata |
| `OWNAPI-02` | PROPOSED — HTTPS identity, TLS + Docker scope | OWNAPI-01; boundary review |
| `OWNAPI-03` | OPEN — direct Repo proof, Approvals path unknown | topology read-only, затем OWNAPI-02 |
| `OWNAPI-04` | BLOCKED — отдельный upstream client/credential отсутствует | OWNAPI-01/02/03/05 |
| `OWNAPI-05` | BLOCKED — root mismatch с Owner Shell; дизайн не выбран | read-only provenance, owner decision |
| `OWNAPI-06` | OPEN — прямые POST/bypass не инвентаризированы | OWNAPI-01, до отключения прав OWNAPI-07/08 |
| `OWNAPI-07` | BLOCKED — source merged, provider не активирован | OWNAPI-02/03/04/05 и OWNAPI-06 |
| `OWNAPI-08` | OPEN — write/effect/receipt contract отсутствует | OWNAPI-01/06, потом OWNAPI-07 |
| `OWNAPI-09` | PROPOSED — UC-GW-010 draft future | lessons OWNAPI-01/02/05/06/08; owner-only branch example |

Выбор vault **не утверждён**: A) управляемое изменение metadata только root existing volume (меньше code/mount изменений, затрагивает shared root); B) новый `credentials/` подкаталог с согласованными изменениями runtime+controller (лучшее разделение, больше source/CI); C) два explicit volume mounts и release-record contract (текущий один `-VaultVolume` не годится); D) миграция Owner Shell (не входит в текущий scope, высокие риски). До owner-approved выбора — только preflight и проект/тесты.

Рекомендуемый порядок: параллельно read-only OWNAPI-01/03/05/06; затем решение OWNAPI-02/05; затем owner-only OWNAPI-04; потом read-only Approvals live acceptance OWNAPI-07; отдельно write readiness OWNAPI-08; reusable UC-GW-010 по OWNAPI-09 с двумя ветками **machine** и **owner-only**, без копирования owner-shell source.

## Е. Безопасный development/Git workflow

Работать только в зарегистрированном `/workspace/repo/Worktrees/fortis-approvals/<task>`, primary `/workspace/repo/Repos/fortis-approvals` оставлять на чистом `main`. Windows `%USERPROFILE%\Repos\fortis-approvals` — независимый clone.

Перед новым task: сравнить Docker primary `git status --short --branch` и HEAD с GitHub remote main, список `git worktree list --porcelain`, live `/v1/workspace/capabilities` и `github.get_repository/list_branches` через `fortis_approvals.workflow.client.default_client()`. Нельзя использовать GitHub connector, PAT, прямые `git fetch/push`; все GitHub эффекты — через typed Gateway. Убедиться, что worktree другого чата не менялся; **особенно** `owner-shell-v1-step06-evidence-20261110` и его публикация с reported UNCERTAIN.

`workspace.create_task` через `client.command('create_task', repo, {'task':task,'baseSha':verified_sha,'adoptHeadSha':None}, request_id=uuid, reason=...)`; exact params смотреть в native contract/live capabilities. Изменять только свой task path; `git diff --check`, нужные docs link/evidence checks; после edit `python3 scripts/update-source-manifests.py` и `python3 scripts/update-source-manifests.py --check`; `bash scripts/test-source.sh` (в Repo могут не быть всех зависимостей, CI важен). Stage/commit через typed `workspace.stage/commit` с exact tree/index preconditions. Публикация — `client.publish(repo,task,expected_remote_head,new_head,request_id=...)`; readback remote branch SHA; затем typed `github.create_pull_request`, PR HEAD + exact source CI. Owner **сам** merge в GitHub UI; после него `workspace.update_main_from_pr` на чистый primary и targeted `workspace.cleanup_task`, только при доказанном accepted HEAD; чужие tasks никогда не чистить.

При `PENDING` — ждать owner WebAuthn; при `UNCERTAIN` — сохранить **тот же UUID**, прочитать `client.details(uuid)` и независимо проверить GitHub refs/receipts/worker: **не повторять effect с новым UUID, не заменять команды нештатным каналом, не запускать reconcile как обычный read**. Не подавать от AI merge ASK.

Любая установка/релиз/активация в Windows/Docker — отдельное поручение через UC-GW-004/005 и owner-controlled `Manage-Integrations.ps1`; новые PR/doc/main не меняют image. Сохранить список исторических `UNCERTAIN`/`CLAIMED` в protected release preflight.

## Ж. Контроль рисков и STOP

1. Plaintext `HTTPConnection` с Bearer в `integrations/observatory/transport.py` — **нельзя** считать Production TLS; HTTPS server verification или мотивированное mTLS/private trust должны быть приняты отдельно.
2. Текущий image Observatory не имеет доказанного Git source SHA/build/rollback; не копировать historical `tunnel/observatory` и архив/секреты как source.
3. Прямой Repo token может обходить будущие ASK write; inventory реальных consumers до изменения scopes.
4. Vault root `root:root/0755` + `owner-shell` ⇒ `CREDENTIAL_ROOT_NOT_EMPTY`; `Check`/owner controller могут иметь preflight side effects (создать volume), их нельзя считать строгим read-only аудитом.
5. Наличие файлов `owner-shell` по OWNER PASS не разрешает редактировать их, переносить или переиздавать. Не изменять PS backlog без принятого evidence.
6. Primary provider catalog пока пуст; source PR не равен activated runtime. Любой release должен учитывать protected historical worker claims и осмысленный rollback.
7. `staging_only` и отсутствие upstream receipt запрещают заявлять exactly-once или успешную доставку AI messages.

## З. Последние действия / точка продолжения

В предыдущем чате: приняты PR #46/#47 с Source CI, появилось read-only provider source; Docker main после #47 обновлялся и затем продвинулся параллельными PR. После owner-start Observatory прямые Repo `health` и `sessions` стали работать. При аудите вскрылся vault root incompatibility; OWNER PASS нового Owner Shell материала получен извне, без каких-либо работ с ним отсюда.

В **этом** чате создан отдельный зарегистрированный worktree `/workspace/repo/Worktrees/fortis-approvals/own-api-onboarding-backlog-20261110`, base `ceeb875daf066fe560f6daf828c80df41aadd658`; изменяется **только** канонический backlog и этот датированный handoff. Статус PR/CI и final commit для этих документов должен быть получен из Gateway readback после публикации; пока не считать их merged. Задачи OWNAPI-01–09 и критерии находятся в backlog. После owner merge подтвердить точные SHA и далее продолжить с первой задачей, не повторяя исследования.

### Первая задача нового чата

**OWNAPI-01 — read-only source-of-truth inventory установленного Observatory API.** Открыть `/workspace/repo/README.md`, `AGENTS.md`, обязательные три UC, `fortis-approvals/docs/BACKLOG-IMPROVEMENTS.md#own-api-onboarding--observatory-и-единый-workflow-собственных-api-2026-11-10`, `fortis-container/tools/observatory-api/README.md` и `fortis-approvals/integrations/observatory/README.md`. Сверить чистый GitHub/Docker main и доступные source candidates **без чтения токенов**; запросить у owner только read-only Docker image/container metadata (image ID/OCI labels/entrypoint/mount names без env/секретов). **Критерий завершения:** таблица `VERIFIED/OWNER-REPORTED/UNKNOWN` с точным источником установленного image и безопасным планом восстановления reproducible build либо явным `SOURCE_PROVENANCE_UNKNOWN`. Ни одного release/write, никакого изменения Owner Shell.

**STOP после handoff:** не переходить к TLS rollout, vault migration, provisioning или PowerShell V1 operations без нового owner-go.
