# Fortis Approvals — source map and operating status

> **СТАТУС: ДЕЙСТВУЮЩИЙ SOURCE ENTRY POINT.** Текущий основной Gateway — `fortis-gateway`: Sonar, GitHub/native и extensions на `19203/19204`. Исторический Sonar-only `fortis-approvals-gateway` на `19103/19104` остановлен и сохранён для контролируемого восстановления. R7 — исторический идентификатор реализации. Нормативное состояние: [Fortis current state](../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md), [live cutover](evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md).
>
> **Для AI и новых интеграций:** сначала `/workspace/repo/README.md` → короткий вход общего реестра (без просмотра всей таблицы; полное чтение обязательных UC-CONT-002 и UC-CONT-003), затем [Gateway agent guide](../docs/GATEWAY-AGENT-GUIDE.md). Этот README — карта исходного кода, не второй общий workflow.

## Текущая работа и документация

Primary `fortis-gateway` обслуживает Sonar, GitHub/native и extensions.
Изолированный review — исторический этап принятия native; Legacy Sonar-only
сохранён остановленным. Живой цикл merge/CI, Docker main и cleanup принят.
Точные endpoints/images и ограничения — в [current state](../docs/guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md),
результаты — в [live evidence](evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md).
Матрица политик и native CLI — только в [native contract](../docs/NATIVE-WORKTREE-GATEWAY-2026-11-06.md).
Дальнейшие задачи — в [отдельном плане](../docs/BACKLOG-IMPROVEMENTS.md).

Из корня выбранного worktree Sonar review/status доступны через canonical CLI:

```sh
python3 -m fortis_approvals.integrations.sonarcloud.repo_client.workflows review \
  --issue-key ISSUE_KEY --reason "Обоснование для owner review"
python3 -m fortis_approvals.integrations.sonarcloud.repo_client.workflows status \
  --request-id REQUEST_UUID
```

Совместимый `fortis_approvals.sonar_review_scenario` сохраняется. По умолчанию
этот клиент обращается к **Primary 19204** согласно
`clients/gateway_transport.py` и `integrations/sonarcloud/repo_client/client.py`.
`review` читает текущий Sonar report и создаёт одну ASK-заявку, не запускает
analysis и не делает owner decision. Native `workflow.client` использует тот же
**Primary TLS endpoint 19204**, а не отдельный review-runtime.

## Архитектурные entry points

| Файл | Назначение |
| --- | --- |
| `core.py` | Durable request lifecycle, policy, owner decision, execution и reconciliation |
| `owner_auth.py` | WebAuthn credential/challenge verification и owner sessions |
| `owner_portal.py` | Owner Pending/History UI и decision routes |
| `r7_unified_server.py` / `r7_unified_candidate.py` | Fortis Approvals Gateway runtime and composition (legacy module filenames retained) |
| `repo_ingress.py` | Base authenticated machine ingress и typed route dispatch |
| `workflow/runtime.py`, `workflow/ingress.py`, `workflow/adapters.py` | Native opt-in, operation grants/policies, closed routes, exact-head CI/merge/cleanup checks |
| `workflow/git_backend.py`, `workflow/common.py` | Git bundle validation/publication and isolated Git execution |
| `workflow/client.py`, `workflow/worker.py`, `workflow/store.py` | Repo client/worker, local receipts, registered tasks and Gateway native state |
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

## Тесты

Из корня репозитория:

```sh
python3 -m pip install -r fortis_approvals/requirements-owner.txt
bash scripts/test-source.sh
python3 -B -m compileall -q fortis_approvals
```

`scripts/test-source.sh` запускает поддерживаемый offline suite: GitHub contracts/transport/adapter/Repo client/default-deny wiring, native Git/worktree TLS flows, SonarCloud package compatibility, Core, Gateway, Owner Portal, Repo ingress/client, Sonar READ/ASK workflow, TLS 1.3 R6/R7 end-to-end candidate и изолированный import нового modularized Gateway image context. Исторические R4/R5/R7 Windows image audit tests остаются отдельными provenance checks; некоторые используют owner-held архивы вне этого standalone source repository и не являются deployment/build шагами.

## Старые артефакты

`deploy/` содержит preserved deployment-artifact references и исторические G2/G4/R5/A3/P1 scripts. **Не запускать** старые provisioning, preflight, cutover, build или rollback scripts как часть обычной работы. Одноразовые GO-1/GO-2/GO-3 операции завершены. Исторические документы сохранены в `archive/20261103-pre-live-doc-cleanup/`; краткий указатель deployment-файлов: [deploy README](deploy/README.md). Историческая матрица проектирования и acceptance gates от 2026-11-01: [FORTIS-UNIVERSAL-GATEWAY-ACCEPTANCE-MATRIX-20261101.md](deploy/FORTIS-UNIVERSAL-GATEWAY-ACCEPTANCE-MATRIX-20261101.md) — архивный указатель на неизменённый оригинал, не текущий release status.

Новые providers подключаются через [`extensions/`](extensions/README.md): общий
ALLOW/ASK runtime, именованные credentials, клиент и scaffold. Нормативный
порядок — [extension contract](../docs/INTEGRATION-EXTENSIONS.md).
