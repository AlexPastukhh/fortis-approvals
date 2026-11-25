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

<a id="api-onboarding-program"></a>

## API onboarding → управляемые providers и owner policy — целевая программа

**Source status (2026-11-22):** Owner Portal V2 editor and registered-method outer `DENY/ASK/ALLOW` authority (`OWNER_ALL_METHODS_V1`) accepted in [PR #216](https://github.com/AlexPastukhh/fortis-approvals/pull/216) with source/CI; later PR #218 is also merged. Owner-only WebAuthn begin/finish, persisted Core revisions, exact-target policy, original-UUID readback and native one-use READ ASK are present in source. **Installed owner-policy mode has not been independently verified here**: prior owner-reported release was `UNIFIED_V2 + OWNER_LABELS_V1`; no new mode, grants or credentials are conferred by merge. [Current owner-policy contract](OWNER-POLICY-EDITOR-V2.md); [dated all-method handoff](OWNER-ALL-METHOD-POLICY-HANDOFF-2026-11-21.md) is historical. The P1 material below preserves earlier design/history and must not be read as the current live status.

**Историческое состояние до V2/V3: P1 этапы 1–5 MERGED SOURCE ONLY; действующий owner-редактор тогда не был активирован.** Внешний owner-managed `DENY/ASK/ALLOW` — первый слой для всех методов; дополнительный динамический policy применяется **только** к PowerShell Executor согласно [PowerShell plan](#powershell-plan). Канонический источник приоритетов и технических задач Gateway — этот backlog. Исходный Workfile-план `Workfiles/fortis-api-onboarding-priority-20261110/PLAN.md` от 2026-11-10 — историческая проработка, не текущий источник разрешений. Для Action Core действуют отдельные план/hand-off от 2026-11-17, отмеченные в том Workfile. Общее руководство владельца/ИИ принадлежит [Fortis Container backlog](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md#api-onboarding-workflow); технические маршруты остаются [UC-GW-002](use-cases/integrations.md#uc-gw-002), [003](use-cases/integrations.md#uc-gw-003), [004](use-cases/credential-lifecycle.md#uc-gw-004), [012](use-cases/own-api.md#uc-gw-012).

**Историческая база API onboarding (до owner-policy PR #216).** Trusted provider extensions имеют source scaffold, strict operation schemas, fixed transports, config policy и actor-scoped catalog; каталог НЕ является owner-инвентаризацией всех providers/методов. `ExtensionConfig`/policy устанавливаются из доверенной конфигурации при активации Gateway; Owner Portal WebAuthn подтверждает ASK-заявку, но не редактирует provider registry, target grants или policy. Стандартный own-API toolkit V1 ограничен GET/READ/ALLOW, хотя общие extensions допускают разные kinds. Windows Executor имеет отдельный ASK-only proof/receipt, **не** «универсальный WRITE installer». Новые providers или ASK/ALLOW из UI ещё не реализованы.

**Почему отдельная программа, а не переписывание UC.** Подключение Executor и Mirror выявило повторяемые проверяемые стадии (transport, trust, provider, credential, source PR, release, owner decision, exact result), но не доказало автоматическую установку произвольного API. Два направления не смешивать: Fortis → API — эта программа; внешний API → Fortis/new machine actor — отдельный UC-CONT-008, DEFERRED до реального клиента. Native GitHub/Sonar/workspace и extensions имеют разные контракты; один UI может их показывать, но не переписывать одним generic handler.

### P0 — безопасный профиль подключения и детерминированный plan/check

- [ ] **API intake в явной типизированной форме:** владелец/ИИ задаёт сервис, среду, версионированную OpenAPI/spec, разрешённые методы, фиксированный origin, trust/identity, scope, тип/read-vs-effect и test target. Спецификация считается **недоверенными данными**, не исполняемым кодом. Итог: `SUPPORTED_AS_IS / NEEDS_TRUSTED_TRANSPORT / INSUFFICIENT_SPEC / UNSAFE_WRITE`, причины STOP и проверяемый diff; без URL/auth из runtime AI payload.
- [ ] **One-shot source-only assistant/toolkit:** переиспользовать scaffold, manifest checker, Doctor, typed schemas, fixtures, CI и отдельный upstream owner. Генератор готовит **кандидат source и PR** в зарегистрированном task worktree, а не live provider из загруженного OpenAPI. В отдельном preview показывать, что меняется: provider/operations/policy/credentials/transport/source SHA/CI/Windows tasks/release/rollback. Выбирать trusted custom transport при несовместимых CA/mTLS/non-443/OAuth/JSON; НЕ ослаблять стандартный JSONAPI или GET/READ/ALLOW linter.
- [ ] **Раздельное принятие эффекта:** read-only пилот (Action Core HTTPS/443 остаётся OPEN до owner gates) → для разрешённого WRITE отдельный reviewed effect manifest с read-only immutable preview, preconditions, idempotency и bound receipt/upstream readback. Никакого автоматического replay при UNKNOWN, нет обещания exactly-once от generic connector. Испытать второго независимого API, прежде чем объявлять onboarding toolkit воспроизводимым.
- [ ] **Происхождение и этапы:** `DRAFT → SOURCE_READY → PR_MERGED → IMAGE_ACTIVATED → LIVE_API_VERIFIED`; для каждого API хранить точные evidence, scope, installed source/image, отдельный upstream live status, отрицательные auth/actor/target/redirect/timeout/replay проверки. Нет deployment/credential write из Repo в обход owner review, UC-GW-005 и protected state.

### P1 — Owner Portal: список providers, методы, политики и версии

**Датированная передача от 2026-11-21 (уже завершена source merge):** [план единого DENY/ASK/ALLOW](OWNER-ALL-METHOD-POLICY-PLAN-2026-11-21.md) и [historical handoff](OWNER-ALL-METHOD-POLICY-HANDOFF-2026-11-21.md) описывали работу до PR #216. Тот task больше не является незакоммиченной незавершённой реализацией. Следующий gate — независимо подтвердить owner-installed `OWNER_ALL_METHODS_V1` / image/config/revision, all-worker policy enforcement и protected Backup/Promote; не считать source merge production rollout. Старый handoff 2026-11-20 также исторический.


**История до V2:** [handoff 2026-11-20 — прежний READ ONLY, не текущий статус](OWNER-POLICY-HANDOFF-2026-11-20.md). Пять независимых этапов приняты в GitHub/Docker `main`: [#147](https://github.com/AlexPastukhh/fortis-approvals/pull/147), [#149](https://github.com/AlexPastukhh/fortis-approvals/pull/149), [#152](https://github.com/AlexPastukhh/fortis-approvals/pull/152), [#154](https://github.com/AlexPastukhh/fortis-approvals/pull/154), [#157](https://github.com/AlexPastukhh/fortis-approvals/pull/157). Это **не** означает Windows/image owner release и не подключает live policy editor. Канонический статус приёмки — owner current-state evidence и independent live readback.

**Пятый этап MERGED SOURCE ONLY (2026-11-19, task/owner-policy-browser-webauthn-phase5-20261119):** owner-only, opt-in `GET /v1/owner/policy/review/capabilities` + `POST /v1/owner/policy/review/begin|finish`, браузерная форма WebAuthn из Dashboard и повторный точный preview. Требует trusted, **вручную переданного** `PolicyDraftLedger`, никогда не создаёт его автоматически, по умолчанию отключён. Подтверждение **только просмотра** черновика, без записи/активации разрешений. Pinned `owner_auth.py`, `owner_portal.py`, Core не меняются. [Границы и тесты](OWNER-POLICY-REVIEW-UI-PHASE5.md). Активный `DENY/ASK/ALLOW` по-прежнему не редактируется.

**Четвёртый этап MERGED SOURCE ONLY (2026-11-19, task/owner-policy-strong-webauthn-phase4-20261119):** отдельная strong WebAuthn user-verification ceremony в wrapper-модуле без изменений pinned `owner_auth.py`, связанная с точным proposal (actor/provider/operation/target, old/new, baseline/source/credential-generation, ревизия и audit hash, срок действия и owner session). Одноразовая challenge, строгая смена origin/UV/credential/session запрещена; post-verification CAS readback. **Нет HTTP-маршрута, нет активации, нет выдачи reusable approval token.** Новая процедура возвращает только «проверено для просмотра», но **не** меняет policy или ledger. [Контракт и тесты](OWNER-POLICY-STRONG-WEBAUTHN-PHASE4.md). Все P1 чекбоксы ещё открыты.

**Третий этап MERGED SOURCE ONLY (2026-11-19, task/owner-policy-draft-ledger-phase3-20261119):** изолированный SQLite `PolicyDraftLedger` — только **неактивные** точные actor/provider/operation/target черновики, глобальный CAS revision, доверенная baseline/source/policyVersion/credential-generation привязка, журнал с хеш-цепочкой, идемпотентность request UUID, откат черновика к baseline и fail-closed readback. **Не подключён** к Core/Owner Portal/исполнению, не вводит WebAuthn apply и не изменяет текущие DENY/ASK/ALLOW. [Контракт и следующие блокеры](OWNER-POLICY-DRAFT-LEDGER-PHASE3.md). Ни один из P1 чекбоксов ещё не завершён.

**Второй этап MERGED SOURCE ONLY (2026-11-19, task/owner-policy-preview-phase2-20261119):** owner-only `POST /v1/owner/policy/preview` (только вычисление, без изменения Core/policy) и форма предварительного просмотра на вкладке «API и политики». Ограничен существующими точными actor/target правилами, stale version+rule проверяются, unresolved Core состояния подсчитываются отдельно. Нет пути `apply`, storage CAS или WebAuthn изменения прав. [Границы P1 preview](OWNER-POLICY-PREVIEW-PHASE2.md). P1 чекбоксы остаются открытыми.

**Частичный MERGED SOURCE ONLY (2026-11-19, task/owner-policy-inventory-phase1-20261119):** owner-only `GET /v1/owner/provider-inventory` и вкладка «API и политики» только на чтение. Покрытие ограничено loaded Gateway runtime, без editor, fresh WebAuthn mutation и утверждений о deployment. [Границы и недостающие пункты](OWNER-PROVIDER-INVENTORY-PHASE1.md). Все P1 чекбоксы остаются открыты.

- [ ] **Отдельный owner-authorized inventory READ:** полный список packaged/deployed native и extension providers, методов/версий, available-vs-configured-vs-active, kind/effect risk, actor/target grants, effective ALLOW/ASK/DENY, разрешённый readiness/credential alias status, last verified result. Текущий `/v1/integrations/catalog` остаётся **actor-scoped** и не расширяется до выдачи чужих grants/secrets ИИ. Разделить owner view от machine actor view, реализовать pagination/filters/redaction.
- [ ] **Policy editor только для owner:** выбрать точный provider+operation+actor+target/environment и желаемый `DENY / ASK / ALLOW`, увидеть old/new diff, влияние на незавершённые ASK и prereqs. Метод с внешним `ASK` требует подтверждения **сразу по принадлежности методу**; `ALLOW` для `powershell.execute` передаёт команду на внутренний Dynamic ASK/ALLOW/DENY, а не обходит его. **Не выводить ALLOW из GET** и не разрешать ALLOW для неограниченного shell без Windows command-policy enforcement/owner acceptance. Для native/extension методов учитывать разные trusted policy storage и совместимость. Отсутствующие/неизвестные операции DENY.
- [ ] **WebAuthn на каждое изменение полномочий:** отдельная **fresh strong owner authorization** на exact policy change (policyVersion/source digest/actor/target/ops/grant/credential generation/expiry). Защита CSRF/session/origin и stale races, fail-closed validation/re-read, audit/receipt и возврат к прежней политике. WebAuthn «одобрить заявку на действие» не равен WebAuthn «изменить настройки доступа».
- [ ] **Два уровня разрешений для ИИ:** ИИ через typed Gateway может READ **свои** capabilities, подготовить `proposal/preview` на provider/operation/policy и попросить owner review (ASK). Самостоятельно выставлять policy, менять credential, runtime/config, grant, назначать себя actor, обходить WebAuthn или снимать блокирующие условия ИИ **не может**. Owner-only UI выполняет и утверждает чувствительные изменения; некоторые действия (секрет, machine identity/grant, первичная активация) не имеют machine-write route даже после AI proposal.
- [ ] **Безопасное применение:** для удобного редактирования owner должен менять проверенные versioned policies через Dashboard, а не через изменение захардкоженного Python/ручной source release для каждой правки. Спроектировать persistent store и защищённую атомарную активацию только после свежего WebAuthn, audit/rollback и threat review: durability, cache invalidation, in-flight ASK/UNCERTAIN, provider revoke и proof/version invalidation. Первичное внедрение и новая реализация всё ещё доставляются через checked source PR/CI и owner-controlled release; hot-reload без принятого контракта не обещать.
**Phase 6A / 6B.1–6B.4 MERGED SOURCE ONLY (PR #160 / #161 / #162 / #165 / #166):** exact admission, inert PREPARED barrier, signed witness and HOLD recovery classifier. **Owner scope change 2026-11-20:** separate monotonic/journal service deferred for the MVP, with explicit backup rollback risk. **Phase 6C.0 MERGED SOURCE ONLY (PR #168):** separately selected `LocalDenyCore` subclass with same-Core-SQLite deny-only revision fence and pinned core.py untouched. **Phase 6C.1 MERGED SOURCE ONLY (PR #169):** owner-only exact DENY fresh WebAuthn UV + same SQLite CAS/local audit, still NOT deployed. **Phase 6C.2 MERGED SOURCE ONLY (PR #170):** opt-in owner-only WSGI bridge not mounted by default. **Phase 6C.3 MERGED SOURCE ONLY (PR #171):** one-process Core/client/owner bundle and truthful exact local DENY inventory. **Phase 6C.4 MERGED SOURCE ONLY (PR #173):** explicit R7 builder selector for LocalDenyCore, matching owner portal + same RepoIngress/Broker Core; default server still does NOT pass it. **Phase 6C.5 MERGED SOURCE ONLY (PR #175):** default-R7 startup refuses plain Core when local-policy SQLite tables exist, but cannot stop old workers or rollback. **Phase 6C.6 MERGED SOURCE ONLY (PR #176):** fresh owner-WebAuthn exact-target DENY derived from existing actor-scoped literal ASK/ALLOW (native R7 Sonar), preserving other targets and adding a truthful owner-inventory DENY row. **Phase 6C.7 MERGED SOURCE-ONLY TESTS (PR #178):** independent subprocess/SQLite revision and lock validation; split-volume and old-backup counterexamples remain release STOPs. **Phase 6C.8 MERGED SOURCE ONLY (PR #179):** strict offline owner-supplied worker census consistency check; no host collection or deploy authorization. **Phase 6E.1 MERGED SOURCE (PR #182):** opt-in Dashboard exact-target DENY preparation + separate strong WebAuthn confirmation and original-UUID readback, hidden unless the restricted owner portal and local policy inventory are explicitly configured; see [6E.1 browser contract](OWNER-POLICY-LOCAL-DENY-UI-PHASE6E1.md). No default runtime enablement or all-worker attestation. **Phase 6F SOURCE CANDIDATE:** explicit owner-release configuration opt-in for native Sonar accept_issue exact DENY in actual R7; guarded staged activation and local policy state preservation. See [6F release contract](OWNER-POLICY-R7-RELEASE-PHASE6F.md). See [6C.8 contract](OWNER-POLICY-WORKER-CENSUS-PHASE6C8.md), [6C.7 tests](OWNER-POLICY-CROSS-PROCESS-PHASE6C7.md) and [6C.6](OWNER-POLICY-ACTOR-SCOPED-TARGET-DENY-PHASE6C6.md). See [6C.5 restart fence](OWNER-POLICY-R7-LEGACY-RESTART-FENCE-PHASE6C5.md), [6C.4 R7 contract](OWNER-POLICY-R7-OPTIN-PHASE6C4.md) and [6C.3](OWNER-POLICY-LOCAL-BUNDLE-PHASE6C3.md). Actor-wide R7 grants remain unchanged; only an independently WebAuthn-confirmed exact target can be locally denied. **All-worker/host attestation remains unproven**; no owner-host release; see [6C.1](OWNER-POLICY-LOCAL-DENY-APPLY-PHASE6C1.md) and [local MVP contract](OWNER-POLICY-LOCAL-MVP-PHASE6C.md). Full owner-host trust attestation, all-worker fencing, Dashboard Save/Apply and controlled release remain OPEN. Previous 6B candidates are not automatically production-ready. [6A design](OWNER-POLICY-ACTIVATION-PHASE6-DESIGN.md), [6B.1](OWNER-POLICY-ACTIVE-STORE-PHASE6B-CANDIDATE.md), [6B.2](OWNER-POLICY-AUDIT-WITNESS-PHASE6B2.md), [6B.3](OWNER-POLICY-MONOTONIC-FENCE-PHASE6B3.md), [6B.4](OWNER-POLICY-RECOVERY-EVIDENCE-PHASE6B4.md). No owner-host release or production policy activation is implied.

- [ ] **После Phase 5 (отдельный будущий owner scope, теперь выполняется по явному заданию владельца):** сначала reviewed design authority и migration из существующей trusted policy в защищённый **active** store (native+extensions, exact actor/target, default DENY), при этом inactive `PolicyDraftLedger` не становится автоматически источником прав. Независимо anchored audit, durable multi-process CAS / rollback, in-flight `PENDING/APPROVED/DISPATCHED/UNCERTAIN/CLAIMED` semantics, expiration/revocation/credential-generation/source digest, fresh apply-specific strong WebAuthn и proof readback; негативные race/restart/restore/forgery tests. Только после этого — owner-only UI Save/Apply и отдельный owner-controlled release. Source-мердж #157 не выдаёт разрешения на разработку/активацию.

### P2 — мастер установки + provider lifecycle и AI-assisted workflow

- [ ] **UI wizard «Добавить API»**: import spec/выбор пакета → compatibility/security checks → список typed методов → credential alias с owner-only secret entry → actor/target/scopes → policy diff → source PR/CI → owner-reviewed activate/rollback → live test/readback. Проходить шаги по status, давать resumable read-only progress по исходным UUID и явное `MANUAL_REQUIRED` для Windows/Docker/CA/network/ACL; не скрывать эти gates кнопкой «Подключить».
- [ ] **Provider registry lifecycle:** install/version/upgrade/disable/revoke/rotate/retire, несовместимые схемы и client API versioning, зависимые consumer checks и reverse compatibility; native methods показывать отдельно от extension plugin code. Никакой remote URL-import исполняемого Python или unrestricted HTTP proxy.
- [ ] **Автоматизация для ИИ на тех же typed contracts:** discover permitted ops, propose changes, generate reviewed source/fixtures/negative tests, submit exact plan; по статусам ASK/CI/release/verification возобновлять исходную операцию, без retry неизвестного эффекта. Секреты вводит только владелец, изменения прав подтверждает WebAuthn. Если UI не может доказать разрешения upstream, статус остаётся `NOT_VERIFIED`.
- [ ] **Тестирование/приёмка:** owner-vs-machine inventory isolation; no privilege escalation; denied/ASK/ALLOW policy matrix; forged WebAuthn/CSRF/stale approval; concurrent policy changes/revocations; transport/SSRF/redirect/auth; credential scope/rotation; unknown effects, lost ACK, replay, rollback. Пилоты на изолированных ресурсах и отдельный owner GO для реального runtime.

**Порядок:** owner inventory/editor (P1) — самостоятельный приоритет, **не блокируется** P0 onboarding второго API; API P0 → P2 wizard/AI workflow развиваются отдельно. Для PowerShell Executor внутренний Dynamic ASK зависит от безопасного Gateway policy/Core integration и [Executor backlog](#powershell-plan), но не от общего API wizard. Для конкретных write/broker capabilities отдельный security design/owner review обязателен; не выдавать этот backlog за доступную функциональность.

### Снимок статусов 2026-11-18 и сохранение истории

**Дополнение 2026-11-19 (P3.4):** отдельный owner-invoked
Release Label Publisher прошёл live ASK/WebAuthn/receipt E2E для одного
добавления метки на PR #118. Исходный request `ed0dce76-8402-4230-941e-a89b5639460d`
`EXECUTED`, независимый readback PASS; [точные рамки acceptance](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).
Отдельный unattended publisher/таймер, live E2E удаления метки,
CD Queue и Deployment Publisher **не готовы**. Общий P4–P8 roadmap —
только в `fortis-container`; эти Gateway-specific разделы не создают
второго плана.

- Windows Machine ASK V1 **активирован**; один `Get-Date` прошёл `PENDING→APPROVED→DISPATCHED→EXECUTED` с exitCode=0 и одной bound machine receipt в исходной SQLite (с сохранением owner-only receipt). Отдельный Reject подтверждён Core `PENDING→REJECTED` и отсутствием новой machine receipt/binding в Windows SQLite. Gateway UC-GW-014/015/016 приняты в [PR #141](https://github.com/AlexPastukhh/fortis-approvals/pull/141); Windows Executor и Script Center UC приняты в исходных repo. **Full live fault injection (forged proof, replay, timeout/lost ACK/restart) OPEN**, не считать полную PS-AI-V1-10 закрытой.
- Release Labels typed READ и ASK доступны в Gateway. На 2026-11-19
  подтверждён **ручной** отдельный Publisher E2E; `update_pull_request`
  owner ASK ранее использована для PR #141. Unattended публикация
  **не принята**. GitHub Projects V2 исключён из текущего Release Planning
  roadmap в пользу собственной Release Board. Разделы от 11/17 ноября
  со словами `SOURCE CANDIDATE` и старым планом Projects —
  исторический контекст, а не live статус; датированные evidence
  не переписывать задним числом.
- Action Core READ: не обновлять на `LIVE_API_VERIFIED` без независимого upstream HTTPS/443 и Gateway acceptance; historical P0 Workfile утверждал, что пилот ещё не выбран, но Action Core уже выбран как source candidate. Его host/runtime gates остаются отдельными.
- Этот status snapshot не заменяет [current-state guide](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) и protected owner release records; при конфликте с live runtime STOP и независимый readback.

---

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

## Release Labels — исторический Gateway typed API snapshot (2026-11-11)

**Исторический статус на 2026-11-11: SOURCE CANDIDATE, тогда не установлено.** Сверить с актуальным снимком выше: typed Release Labels READ/ASK и owner-invoked Publisher уже прошли live E2E, но unattended режим и CD Queue ещё не приняты. По запросу владельца
расширяется native GitHub provider без generic HTTP/GraphQL proxy.
Предлагается READ `list_repository_labels`, `list_pr_labels`,
`get_pr_release_label_context` и owner ASK `create_release_label`,
`add_pr_release_labels`, `remove_pr_release_label`.
Контракт/Use Case: [UC-GW-011](use-cases/integrations.md#uc-gw-011).
Реализация/валидации живут в одном GitHub provider, политики — в
native `workflow/runtime.py`; описание не дублирует полный контракт.

**Незакрытые gates:** source tests/CI, Owner Merge, Primary image
UC-GW-005, live capabilities + реальный scope/readback и negative
actor/repository tests. Этот абзац — первоначальные условия допуска:
  owner-invoked Publisher уже прошёл изолированный live E2E добавления
  управляемой метки; unattended запуск и расширение прав всё ещё
  требуют отдельного security/owner review. GitHub Projects V2
  **не входит** в текущий Release Planning roadmap, где выбрана
  отдельная read-only Fortis Release Board.
Нормативный Release Planning контракт один —
`fortis-container/docs/RELEASE-PLANNING-CONTRACT.md`.

## P0 — Подключение собственных API через Gateway: ПЕРВОЕ В ОЧЕРЕДИ (2026-11-10)

- [ ] **Action Core READ — owner runtime gates (2026-11-17).** Source PR #16 в `feed_and_search_and_bank_and_brain` (merged main `cb22a03591e5c77739e192794d8f1d8323a68c4d`) и Gateway provider PR #105 (merged main `42c6ef7b94c4e72d8be0594b8034e782fca4636b`) прошли точный CI/Release Impact. Public [manifest](templates/own-api/action-core-read.json) — только source, сеть `fortis-actioncore-net` предлагается, не установлена. **Перед live READ:** owner-reviewed Docker HTTPS/443 ingress с SAN/CA, отдельный scoped verifier/vault alias, Guard/controller compatibility, блокировать оба подтверждённых Gateway→HTTP/8000 bypass (host.docker.internal и прямой IP), проверить отрицательные TLS/auth/ACL тесты, UC-GW-009 global state/quiescence, старый image, isolated restore, owner Check/Apply/Backup/Promote, затем one-shot Gateway READ для 3/4 с readback. Исходный provider есть в source, но установленный catalog его пока не показывает; **WRITE отдельно**. **Путь внедрения только прямой HTTPS-first:** первый Gateway-visible READ — сразу по финальному проверенному `DOCKER-HTTPS:443`, без промежуточного HTTP, dual-stack/compatibility режимов, adapter/proxy fallback или временного доступа по `:8000`. Существующий Windows-local API сохраняется независимо для текущих клиентов, но не используется Gateway. Если целевая TLS/network/ACL граница ещё не готова — STOP, без промежуточного подключения.

**Уточнение границы 2026-11-17 (source candidate):** после принятого
native TLS/443 и provider source создан upstream
[Compose/network PR #19](https://github.com/AlexPastukhh/feed_and_search_and_bank_and_brain/pull/19),
разделяющий local HTTP API, DB и HTTPS ingress. Зарегистрированный Gateway task
action-core-gateway-network-guard-20261117 готовит opt-in режим штатного
Manage-Integrations.ps1: отдельная user-defined egress bridge,
controller-owned secondary ingress attach, exact-ID Docker Guard,
Windows Defender Firewall rule preflight для com.docker.backend.exe TCP/8000,
положительный Windows localhost и отрицательные Gateway probes обоих bypass.
Новые rule/network не установлены; ни одного production release не проведено.
Нужны owner review/merge обеих source-веток, Windows backup/provisioning,
UC-GW-009 quiescence, Check/Apply/Backup/Promote и live UC-GW-012 acceptance.
[Точный контракт и STOP-гейты](ACTION-CORE-NETWORK-ISOLATION.md).

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

## PowerShell Executor — внешний policy Gate и внутренний Dynamic ASK (план 2026-11-19)

**Статус: DESIGN AGREED / IMPLEMENTATION OPEN.** Действующий machine route уже
**включён только через ASK**, `machineExecutionAutoApprove=false`, protocol V1.
Первый реальный `Get-Date` и Reject проверены 2026-11-18; полный fault-injection,
restart/lost-ACK/replay acceptance остаётся OPEN. Действующую настройку и
Windows installation этот план **не меняет**. Доказательства текущего
состояния — [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
и [Machine ASK UC-GW-014…016](use-cases/powershell-executor.md). Исходный ASK-only V1
описан в [контракте](POWERSHELL-MACHINE-ASK-CONTRACT-V1.md) и
[Executor Machine V1](https://github.com/AlexPastukhh/fortis-powershell-executor/blob/main/docs/MACHINE-ASK-V1.md).

### Два независимых слоя — согласованное поведение

1. **Внешний Gateway policy (общий для всех providers):** владелец в Owner
   Dashboard устанавливает `DENY / ASK / ALLOW` для конкретного
   provider + method + actor + target/environment. `DENY` прекращает запрос;
   `ASK` **обязательно** требует WebAuthn для вызова метода, независимо от
   внутреннего анализа; `ALLOW` пропускает во внутренний слой. Для остальных
   провайдеров dynamic policy в этой программе **не вводится**.
2. **Внутренний Executor evaluator (только `powershell.execute`):** проверяет
   точную команду против owner-managed versioned policy и выдаёт
   `DENY / ASK / ALLOW`. `DENY` блокирует даже одобренный внешний ASK;
   `ASK` требует один owner WebAuthn, `ALLOW` разрешает исполнение только
   при внешнем ALLOW и успешной повторной проверке на Windows. Неизвестный
   синтаксис **не** становится ALLOW только потому, что анализатор не нашёл риск.
3. **Итог:** `DENY > ASK > ALLOW`; при внешнем ASK и внутреннем ASK — **одна**
   Core PENDING/strong WebAuthn заявка, а не две. При внешнем ALLOW и внутреннем
   ASK — обычная PENDING/strong WebAuthn заявка. Никаких новых owner approval
   queues, обхода Core или машинного изменения разрешений.

| Gateway method policy | Executor policy | Итог |
| --- | --- | --- |
| DENY | не вызывается | DENY |
| ASK | DENY / ASK / ALLOW | DENY / ASK / ASK |
| ALLOW | DENY / ASK / ALLOW | DENY / ASK / ALLOW |

**Важно:** внешний `ALLOW` на `powershell.execute` **не** означает
разрешение произвольного PowerShell. До безопасной реализации обоих слоёв
остается live ASK-only V1; включать auto-ALLOW одной правкой конфигурации нельзя.

### Отложенный архитектурный review: внутренний policy gate (2026-11-26)

- [ ] **GW-POL-INNER-REVIEW — OPEN, решение владельца отложено.** Live
  `powershell.capabilities()` вернул `configured=true`, `policy=ASK`,
  `machineExecutionAutoApprove=false`, `version=1`; при отображаемом в Owner
  Portal базовом ALLOW для `powershell.execute / windows-owner` заявка
  `63555cb2-def3-405e-aa4e-32b86aad6282` осталась PENDING. Это наблюдение
  допуска, не доказательство исполнения или OS isolation. В исходнике
  `MachinePowerShellAdapter.inner_policy` фиксирует ASK, а общий
  `OwnerPolicyCore._inner_guard` применяет наиболее строгое решение.
  Инвентаризировать все inner guards (PowerShell, publisher, подписанные
  extensions, Registry и callable baseline), разделить правила автономии,
  обязательную proof/подпись, scope и OS isolation. Оценить, какие повторные
  policy-решения необходимы, какие дублируют внешнюю owner authority и
  какие можно заменить единым явным контрактом без потери гарантий.
  Сравнить сохранение двух слоёв, упрощение и перенос командной политики
  в Windows Executor; согласовать с владельцем до реализации V2. Отдельно
  оценить owner-managed изменение допустимых правил без выпуска image,
  но не обходить текущий V1 owner proof. В UI показывать outer, inner и
  effective policy, причину/владельца ограничения и возможность изменения
  каждого слоя; для command-dependent verdict явно показывать conditional.
  Acceptance: матрица решений, отказ при отсутствующем/устаревшем proof,
  отсутствие расширения grants и обхода WebAuthn/изоляции, совместимость
  receipts и обратимый rollout. До отдельного решения и release GO ничего
  не менять в действующем ASK-only V1 или Windows Executor. Связанные задачи:
  GW-PS-01..03 и [Executor backlog](https://github.com/AlexPastukhh/fortis-powershell-executor/blob/main/docs/BACKLOG-IMPROVEMENTS.md#executor-dynamic-ask).

### Gateway — задачи и готовность (внешний policy + Core)

- [ ] **GW-POL-01 Owner Dashboard:** полный owner-only inventory native +
  extension providers/methods, versions, installed/active readiness, actors,
  targets, effective `DENY/ASK/ALLOW`; поиск и фильтры, безопасная индикация
  недоступных providers. Переиспользовать план [P1 выше](#api-onboarding-program),
  **не делать второй policy editor** специально для PowerShell.
- [ ] **GW-POL-02 Owner policy writes:** versioned persisted owner-only setting
  provider+method+actor+target, exact diff/preview, fresh strong WebAuthn,
  origin/session/CSRF, audit и atomic activation/rollback/revocation.
  AI видит безопасный каталог и свои effective policies, но **не может менять**
  policy/grants/config/secrets или вызывать owner-write путь. Не путать
  owner-change authorization и approval конкретной команды.
- [ ] **GW-PS-01 Dynamic policy integration:** отдельный evaluator hook только
  в PowerShell adapter, в согласованной точке до `Core.submit`/dispatch.
  Пересмотреть текущие `Core._policy`, `submit`, `owner_decide`, `execute`:
  воспроизводимый итог и policy digest в snapshot/receipt, повторная проверка
  на approval и перед эффектом; смена политики, analyzer version или параметров
  переводит запрос в STALE/STOP, никогда не даёт молчаливый ALLOW.
- [ ] **GW-PS-02 Trusted preflight и proof V2:** read-only authenticated Windows
  evaluate без запуска команды; ответы с командным SHA256, evaluator/profile
  version и policy digest не доверяются без криптографической/transport-привязки.
  Exact-command signed proof различает `owner-approved ASK` и `policy-ALLOW`,
  связывает Core fingerprint, actor/target/UUID, source identity, итоговый
  disposition и policy digest. Windows повторяет verdict перед dispatch.
  Существующий ASK-only proof V1 остаётся совместим до отдельного cutover.
- [ ] **GW-PS-03 Acceptance:** матрица всех 3x3 внешних/внутренних решений,
  один ASK при двух ASK, no owner proof on ALLOW but valid bound policy proof,
  no dispatch on DENY/reject/expired/revoked/stale, cross-actor/target и
  replay/concurrency/lost-ACK/UNKNOWN/restart; без повторного эффекта на UUID.

### Windows Executor — отдельный технический владелец

**Единственный backlog реализации внутреннего evaluator, формата правил,
owner settings, AST/typed operations, Windows enforcement и Windows tests** —
[Executor backlog](https://github.com/AlexPastukhh/fortis-powershell-executor/blob/main/docs/BACKLOG-IMPROVEMENTS.md#executor-dynamic-ask).
Не копировать туда Gateway Dashboard, а сюда — AST/Windows rule schema.
`script-control-center` — только owner setup/launch integration; не второй
policy-store или authorization engine. `fortis-container` ведёт отдельно
Windows identity/OS isolation и будущий container-control broker.

### Порядок, релиз и сохранённая история

1. Зафиксировать machine ASK-only V1 contract и завершить недостающие
   security/recovery negatives без изменения режима работы.
2. Внедрить owner inventory/editor внешних policy и версионирование с
   отдельным owner-only правом изменения (общий Gateway P1).
3. Реализовать Executor owner policies + безопасный evaluator и V2 preflight,
   затем Gateway dynamic hook + 2 вида signed proof и protocol compatibility.
4. Провести offline/CI/adversarial matrix, source PRs/owner merge;
   **отдельно**, после owner review, Windows Executor и Gateway rollout
   согласно [UC-CONT-002](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-002)
   и [UC-GW-005](use-cases/releases.md#uc-gw-005). Никакой source merge не
   активирует ALLOW на Windows сам по себе.

**Исторические PS-V1-01…10, PS-AI-V1-00…10, MOVE-01…08 и решения
2026-11-10/17/18** фиксировали отдельные стадии исходного owner-only и
ASK-only V1. Их завершённые результаты и открытые отрицательные проверки
сохраняются в dated evidence, [Owner PowerShell](OWNER-POWERSHELL.md),
[Machine V1 contract](POWERSHELL-MACHINE-ASK-CONTRACT-V1.md) и
[Windows Executor source](https://github.com/AlexPastukhh/fortis-powershell-executor).
Старые указания «machine API source-only/not installed», «каждая команда
всегда ASK навсегда» и «dynamic ALLOW только когда-нибудь после V2» относятся
к датированным снимкам, а **не** к текущему статусу или согласованной цели.
Не повторять исторические publish UUID, не перезапускать Windows listener,
не создавать новую receipt DB и не подменять Owner WebAuthn решением ИИ.

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
