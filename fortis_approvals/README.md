# Fortis Approvals — source map and operating status

> **СТАТУС: ДЕЙСТВУЮЩИЙ SOURCE ENTRY POINT.** Текущая система — live Fortis Approvals Gateway для одного AI actor / одного SonarCloud project. R7 — исторический идентификатор реализации. Нормативное описание состояния: [Fortis current state](../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).
>
> **Для AI и новых интеграций:** сначала прочитайте [Gateway agent guide](../docs/GATEWAY-AGENT-GUIDE.md). Он объясняет роль Gateway, ALLOW/ASK/DENY и порядок подключения новой авторизации/сервиса. Этот README остаётся картой текущего исходного кода и реально доступных операций.

## Что работает сейчас

- Fortis Repo обращается к Fortis Approvals Gateway по фиксированному TLS 1.3 machine ingress.
- Fortis Approvals Gateway содержит Core, policy, Owner Portal/WebAuthn, durable request state и live Sonar adapter. GitHub adapter source is prepared but is not registered in the live composition. Approval application **не размещено в Fortis Repo**.
- Четыре typed Sonar READ операции, одна typed `accept_issue` ASK proposal и чтение request status работают из Repo.
- Owner WebAuthn Approve запускает проверенную Core execution path; для Issue `AaGC4d7SJxEkuf26a_Wh` подтверждены `EXECUTED` и независимый Sonar `ACCEPTED`. Отдельный owner Reject для Issue `AaGC4d7SJxEkuf26a_Wg` дал `REJECTED` без adapter dispatch. Подробности и Request IDs: [latest live evidence](evidence/FORTIS-SONAR-LIVE-E2E-20261104.md).
- Deployed image ID `sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402` прошёл owner-reported Windows build and installed-source audit; deployment/health также owner-reported. Live Repo→Gateway→Sonar операции подтверждены отдельно.
- SonarCloud implementation has been moved into [`integrations/sonarcloud/`](integrations/sonarcloud/README.md); root-level module names remain compatibility shims. The migrated Repo client and shared machine transport passed a live Sonar GET on 2026-11-05 ([GET evidence](evidence/FORTIS-SONAR-LIVE-GET-AFTER-MODULARIZATION-20261105.md)).
- GitHub has a typed contract, fixed-origin Gateway transport, allowlisted adapter, durable receipts, registration helper, and Repo-side typed client under [`integrations/github/`](integrations/github/README.md). It is **not registered in the live R7 composition**, has no actor grants or policies, and has no Gateway token/volume. The deployed Gateway remains Sonar-only.

## Один рабочий сценарий

Из Fortis Repo:

```sh
cd /workspace/repos/fortis-approvals
python3 -m fortis_approvals.sonar_review_scenario review \
  --issue-key ISSUE_KEY \
  --reason "Обоснование для owner review"
```

Проверка результата:

```sh
python3 -m fortis_approvals.sonar_review_scenario status \
  --request-id REQUEST_UUID
```

`review` читает закреплённый project, Issues, Quality Gate и точную Issue, затем создаёт одну заявку `PENDING`. Он не запускает новый Sonar analysis, не делает Approve и не отправляет Sonar mutation. Approve/Reject выполняет владелец в Fortis Approvals Gateway Owner Portal.

### Что именно вызывается

| Слой | Разрешённые операции | Фактический маршрут |
| --- | --- | --- |
| Repo client → Fortis Approvals Gateway | `sonar.list_projects`, `sonar.list_issues`, `sonar.get_issue`, `sonar.get_quality_gate` | `POST /v1/reads` с typed envelope |
| Repo client → Fortis Approvals Gateway | `sonar.propose_accept_issue` | `POST /v1/actions`; результатом является `PENDING`, не Sonar POST |
| Repo client → Fortis Approvals Gateway | `approvals.request_status` | `GET /v1/requests/{requestId}` |
| Fortis Approvals Gateway → SonarCloud | READ | GET-only allowlist для projects/issues/quality gate |
| Fortis Approvals Gateway → SonarCloud | WRITE | Только после owner WebAuthn: один `POST .../do_transition` с `accept`, затем GET readback |

### Approval state machine

`PENDING` — frozen preview и fingerprint ждут решения владельца. `REJECTED` завершает заявку без adapter dispatch. `APPROVED` проходит final re-read/policy/grant checks, затем `DISPATCHED` и `EXECUTED` после подтверждённого Sonar readback. Изменившийся preview/policy получает `STALE` или `EXPIRED`; неопределённый удалённый результат не повторяется вслепую.

### Где читать документацию

- Каталог интеграций и их статусы: [integrations README](integrations/README.md).
- План разделения SonarCloud/GitHub и подключения GitHub credentials: [integration modularization plan](../docs/INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md).
- Роль Gateway, правила AI-клиента и подключение новых сервисов: [Gateway agent guide](../docs/GATEWAY-AGENT-GUIDE.md).
- Нормативное состояние и архитектура: `docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md`.
- Карта исходников и команды: этот README.
- Latest live request/readback evidence: `evidence/FORTIS-SONAR-LIVE-E2E-20261104.md`.
- Deployment/image/volume references: `deploy/README.md` и preserved artifact `deploy/compose-r7-p2-20261103.yaml`.
- Старые provisioning/cutover/source-review документы — архивные указатели, не runbook.

## Архитектурные entry points

| Файл | Назначение |
| --- | --- |
| `core.py` | Durable request lifecycle, policy, owner decision, execution и reconciliation |
| `owner_auth.py` | WebAuthn credential/challenge verification и owner sessions |
| `owner_portal.py` | Owner Pending/History UI и decision routes |
| `r7_unified_server.py` / `r7_unified_candidate.py` | Fortis Approvals Gateway runtime and composition (legacy module filenames retained) |
| `repo_ingress.py` | Authenticated machine ingress и typed route dispatch |
| `repo_action_contract.py` | Закрытый schema/allowlist machine intents |
| `clients/gateway_transport.py` | Shared Repo→Gateway TLS/machine-grant transport; only typed ingress routes |
| `integrations/sonarcloud/contract.py` | Sonar-only operation schemas and parameter validation |
| `integrations/sonarcloud/gateway/sonar.py` | Typed Sonar write adapter and upstream transport |
| `integrations/sonarcloud/gateway/read_adapter.py` | GET-only Sonar adapter and public projection |
| `integrations/sonarcloud/repo_client/client.py` | Repo-side typed Sonar client (legacy `repo_sonar_tools.py` shim) |
| `integrations/sonarcloud/repo_client/workflows.py` | READ/report → ASK workflow (legacy `sonar_review_scenario.py` shim) |
| `integrations/github/contract.py` | Closed GitHub READ/ACTION operation schemas |
| `integrations/github/gateway/adapter.py` | GitHub API projection, compare-and-swap writes and durable receipts |
| `integrations/github/registration.py` | Opt-in adapter registration; deliberately adds no grants or policy |
| `integrations/github/repo_client/client.py` | Typed Repo-side GitHub client; never holds GitHub token |

## Действующие ограничения

- Один actor, одна организация `alexpastukhh`, один project `AlexPastukhh_obs-planning-docs`.
- Единственная разрешённая Sonar mutation — `accept_issue` / transition `accept`; каждая Issue требует отдельного owner WebAuthn Approve.
- Нет bulk/arbitrary Sonar writes, произвольных URL/methods, token exposure или AI owner routes.
- Вызов доступен AI в активной сессии через существующий Fortis Repo process tool. Фоновый scheduler, autonomous issue monitor и AI-triggered GitHub workflow dispatch не реализованы.
- Machine grant доступен процессам общего Repo container; это не multi-agent isolation.
- Sonar Quality Gate report относится к `CURRENT_DEFAULT_BRANCH`; PR/SHA binding не подтверждён.

## Тесты

Из корня репозитория:

```sh
python3 -m pip install -r fortis_approvals/requirements-owner.txt
bash scripts/test-source.sh
python3 -B -m compileall -q fortis_approvals
```

`scripts/test-source.sh` запускает поддерживаемый offline suite: GitHub contracts/transport/adapter/Repo client/default-deny wiring, SonarCloud package compatibility, Core, Gateway, Owner Portal, Repo ingress/client, Sonar READ/ASK workflow, TLS 1.3 R6/R7 end-to-end candidate и изолированный import нового modularized Gateway image context. Исторические R4/R5/R7 Windows image audit tests остаются отдельными provenance checks; некоторые используют owner-held архивы вне этого standalone source repository и не являются deployment/build шагами.

## Старые артефакты

`deploy/` содержит preserved deployment-artifact references и исторические G2/G4/R5/A3/P1 scripts. **Не запускать** старые provisioning, preflight, cutover, build или rollback scripts как часть обычной работы. Одноразовые GO-1/GO-2/GO-3 операции завершены. Исторические документы сохранены в `archive/20261103-pre-live-doc-cleanup/`; краткий указатель deployment-файлов: [deploy README](deploy/README.md). Историческая матрица проектирования и acceptance gates от 2026-11-01: [FORTIS-UNIVERSAL-GATEWAY-ACCEPTANCE-MATRIX-20261101.md](deploy/FORTIS-UNIVERSAL-GATEWAY-ACCEPTANCE-MATRIX-20261101.md) — архивный указатель на неизменённый оригинал, не текущий release status.
