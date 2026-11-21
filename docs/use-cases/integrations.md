# Providers и typed операции

Собственные Windows/Docker API и проверяемый owner handoff:
[UC-GW-012](own-api.md#uc-gw-012). Этот UC дополняет, но не заменяет
общую процедуру UC-GW-002.

## UC-GW-002

**Когда:** требуется подключить новый внешний API/service к Gateway.

**Цель:** typed provider с минимальным scope, проверками и owner approval.

**Как:** направление этого UC — **Fortis → свой/внешний API**. Обратное
«новое приложение → Gateway» учтено, но **отложено** до реального спроса
([UC-CONT-008](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/authorization.md#uc-cont-008)).

1. Получить документацию/версию API, test endpoint и **точную** цель владельца:
   необходимые READ/WRITE, среда, исходный контракт, ownership, модель auth,
   запрашиваемые upstream scopes и возможность readback без секрета в Repo.
2. По [extension contract](../INTEGRATION-EXTENSIONS.md) проверить, подходит ли
   фиксированный HTTPS/443 JSON transport. Локальная сеть, произвольный порт,
   свой CA/mTLS, OAuth refresh или non-JSON требуют reviewed transport и
   специальных отказных тестов; не проксировать через Owner PowerShell.
3. По [provider package](../../fortis_approvals/integrations/README.md)
   создать scaffold в отдельном task worktree, описать **закрытые** операции,
   params/results/targets, trusted actor policy и отказ при лишних полях.
   Source scaffold и доступность API по сети **не** означают готовность provider.
4. Для write определить read-only preview/preconditions, идемпотентность
   upstream и проверяемый receipt/lookup с исходным requestId; при неизвестном
   эффекте **не** повторять под новым UUID. Утвердить минимальную policy
   (`ALLOW/ASK/DENY`) и безопасный test target; READ не выдаёт WRITE прав.
5. Провести source/negative tests, точный PR/CI через UC-CONT-002/003,
   credential отдельно по [UC-GW-004](credential-lifecycle.md#uc-gw-004),
   owner-managed image activation по [UC-GW-005](releases.md#uc-gw-005).
   Подтвердить в live каталоге разрешённые actor/target, реальные upstream
   permissions, read result, отказ лишнему scope и, **если разрешён write**,
   точный effect/receipt через ASK и owner decision.

**STOP / UNKNOWN:** неизвестный транспорт, лишние права, отсутствие безопасного
scope или доказуемого исхода значимой write-операции. Тогда ограничить пилот
READ или остановить; не выдавать `scaffold`, CI или `Check -Build` за live API.

**Готово:** только конкретная принятая операция имеет проверяемую границу
`SOURCE_READY` → `PR_MERGED` → `IMAGE_ACTIVATED` → `LIVE_API_VERIFIED`;
неподтверждённые upstream эффекты обозначены отдельно, не как PASS.
Подробная последовательность P0 и этап выбора пилота — в
[backlog](../BACKLOG-IMPROVEMENTS.md); методические детали остаются у
extension owner, а не дублируются в UC.

**Будущая автоматизация (PLANNED, не шаг этого UC):** intake/OpenAPI и выбор
методов должны порождать **draft** typed provider/публичный config diff, plan
с безопасными STOP-гейтами и source PR/CI, а не автоматически исполнять
недоверенную спецификацию или ставить provider из URL. Мастер в Owner Portal
позже использует те же стадии и отдельные owner approvals/release; никакой
общей machine записи для grants/credentials/policy не следует из успешного
scaffold. Точные требования owner UI/AI proposal — в
[Gateway roadmap](../BACKLOG-IMPROVEMENTS.md#api-onboarding-program).

## UC-GW-003

**Когда:** нужно расширить существующий provider новой операцией.

**Цель:** принять одну безопасную typed операцию с policy и тестами отказов.

**Как:** в [extension owner](../INTEGRATION-EXTENSIONS.md) и
[provider code](../../fortis_approvals/integrations/README.md)
найти соответствующий schema/handler/client. Добавить required preconditions,
replay reconciliation и preview для эффекта. Не обходить зарезервированные
provider ID, не выбирать policy/URL из AI payload. Запустить профильные тесты,
доставить source через UC-CONT-002 и при изменении server image — UC-GW-005.

**Граница типов изменений — сначала выбрать нужный путь:**

**Для будущего Owner Portal:** изменение provider method ≠ изменение доступа.
Первое требует source schema/handler/version/CI/при необходимости release;
второе — отдельного owner-authorized policy diff для точных
provider+operation+actor+target, свежего WebAuthn, precondition/digest и
проверки in-flight ASK/UNCERTAIN. Нынешний actor-scoped catalog не является
полной owner-инвентаризацией. ИИ вправе предложить изменение, но не может
назначить себе ALLOW/credential/grant. Пока editor не реализован, использовать
только проверенную конфигурацию и существующий owner release путь.


1. **Новая операция готового `extensions/` provider:** оставить существующий
   `/v1/integrations/*` клиент и transport, расширить только его закрытую schema,
   handler, policy/target и тесты. Добавить *новый* HTTP endpoint лишь если
   существующий транспорт принципиально не покрывает нужный протокол.
2. **Новое действие в native `workspace` или GitHub/Sonar:** изменение закрытого
   контракта — не generic extension. Проверить полный путь
   [`workflow/common.py`](../../fortis_approvals/workflow/common.py) (допущенные
   операции) → [`workflow/adapters.py`](../../fortis_approvals/workflow/adapters.py)
   (request fields, trusted GitHub evidence и preview) → [`workflow/ingress.py`](../../fortis_approvals/workflow/ingress.py)
   (machine-route allowlist, строгая типизация) → [`workflow/worker.py`](../../fortis_approvals/workflow/worker.py)
   (preconditions, canonical Git и эффект) →
   [`workflow/client.py`](../../fortis_approvals/workflow/client.py) (typed wrapper).
   При изменении remote GitHub effect дополнительно проверить
   [`workflow/git_backend.py`](../../fortis_approvals/workflow/git_backend.py).
   Для нового GitHub READ/evidence endpoint также проверить закрытый каталог
   [`gateway/transport.py`](../../fortis_approvals/integrations/github/gateway/transport.py):
   adapter fixture не заменяет проверку фактического route/verb. Тестировать
   разрешённый exact route и отказ для других URL, refs, методов и suffix.
   Определить источник истины: Repo-side Git state или Gateway-only API/token.
3. **Новый API route/новый клиентский метод:** обновлять client и server **в одном
   исходном PR**, но сохранять поддержку старых вызовов; не удалять существующие
   параметры/маршруты без отдельного миграционного контракта. Проверить TLS/machine
   identity, content-type/size, reject unknown fields, fail-closed ALLOW/ASK/DENY,
   actor/target scope, response projection, receipt/reconcile/timeout и точный
   `requestId`. Для условного ALLOW/ASK policy должна получать доказательство
   из trusted state/API, повторно сверять его с подписанным preview и сохранять
   worker preconditions при обоих решениях; флаг из payload не авторизация.
   Клиентское имя не даёт новых прав само по себе; сервер без
   deployment не умеет вызывать новый метод.
   **Для глобального read-only machine API:** отделить инвентаризацию
   и `details(UUID)` для любого аутентифицированного actor от owner
   API и от actor-scoped `status/result/reconcile/claim/finish`.
   Тестировать вторую machine identity: видит чужую карточку и audit,
   но не получает чужую возможность исполнения или claim token.
   Проверить live capability `globalRequestInventory` и отрицательные
   сценарии HTTP route/payload; source-тест не равен живому межакторному
   E2E. Нормативная семантика состояний — [UC-GW-009](incidents.md#uc-gw-009).
4. **Для local `workspace` операций** разграничить `create_task` и
   `update_main`: первая создаёт/регистрирует *изолированный* worktree только
   при **чистом** canonical `main`, иначе незакоммиченные файлы primary
   незаметно не попадут в новую задачу; отказ не исправлять автоматическим
   `stash/reset/clean`. Второе реально меняет `main`, требует clean tree,
   exact GitHub main/PR evidence и только `--ff-only`. Внешний merge
   владельца через GitHub UI не авторизуется фиктивным Gateway mergeRequestId.
   Доступность `update_main_from_pr` проверять по live capabilities и
   [native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md), а не по наличию
   нового client method в исходниках.
5. **Проверки перед PR:** негативные тесты wrong actor/repo/branch, missing proof,
   owner mismatch, SHA race, dirty index/working tree, повтор с тем же UUID,
   read-only или timeout/unconfirmed effect; позитивный end-to-end через
   TLS/Gateway/worker на фикстуре настоящего Git и гарантированная сохранность
   старого native `update_main`. Проверить `scripts/update-source-manifests.py
   --check`, `scripts/test-source.sh`, PR Source CI точного SHA.
6. **После owner merge в GitHub UI:** readback PR+CI+merge SHA, затем принять
   source в чистый Docker main по *поддерживаемому* typed пути. Изменённый сервер
   или image-baked client требует отдельного owner-managed выпуска **по UC-GW-005**
   с checked-image Check/Apply, Backup/Promote, rollback и
   live capability/contract acceptance; изменение
   только внешнего Repo-клиента иногда требует обновления source, но не image —
   выяснить по Dockerfile COPY/runtime импорту, не делать rebuild вслепую.

**Готово:** request/response и runtime policy совместимы, старые операции
продолжают работать, отказ/гонка доказаны тестами, точный PR SHA имеет CI success,
а новый метод подтверждён live после отдельного релиза. Разделять `SOURCE_READY`,
`PR_MERGED`, `IMAGE_ACTIVATED` и `LIVE_API_VERIFIED`.


**Visual iteration scoped ALLOW (live on 2026-11-19):** the closed
`github.append_visual_revision` action adds a PNG revision comment only to
the *same* verified Fortis-created Issue in `visual-workspace`. Its independent Core policy
remains DENY outside visual-workspace and requires an exact DISPATCHED request,
preview/actor/policy checks and one-shot durable run/revision reservation.
The current Gateway advertises ALLOW, but its installed preflight still requires
`private=true` and therefore blocks today's public repository. The public/private
visibility fix requires a separate owner-managed Gateway image release; no per-draft
PR, source PR only after owner acceptance.
Technical contract, limitations and negative tests:
[integrations/github/README.md](../../fortis_approvals/integrations/github/README.md#append-visual-revision-to-an-existing-issue--scoped-allow-source-candidate-not-live).
The older `publish_visual_review` contract remains unchanged.

**Publisher и Release Labels:** отдельные grants, trusted runner,
source/runtime boundary и owner acceptance принадлежат
[UC-GW-011](#uc-gw-011) и
[проекту P3](../RELEASE-LABEL-PUBLISHER-P3-REVIEW.md).
Текущее состояние этапов — в
[едином roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md);
source merge сам по себе не выдаёт grants и не активирует runtime.

<a id="uc-gw-011"></a>

## UC-GW-011 — Typed Release Labels через Fortis Gateway

**Когда:** после принятого read-only Release Impact CI требуется
создать определения управляемых меток или безопасно добавить/удалить их
на открытом PR. Нормативная классификация и правила `build:` /
`release:` принадлежат только
[Fortis Release Planning Contract](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/RELEASE-PLANNING-CONTRACT.md).
Единственный исполняемый источник расчёта `suggestedLabels` —
`fortis-release-impact-action`; Gateway **не вычисляет Release Impact
второй раз и не объявляет развёртывание выполненным**.

**Цель:** один типизированный, проверяемый и owner-controlled путь
для изменения PR-меток, без прямого AI GitHub write, универсального REST proxy,
массовой замены всех labels или второго approval-механизма.

**Роли/границы:** Repo agent через existing TLS machine ingress может
делать только разрешённые READ и отправлять typed intent. Текущие
`create_release_label`, `add_pr_release_labels`,
`remove_pr_release_label` имеют **ASK** и требуют подтверждения владельца
в действующем Owner Portal. Наличие источников в `main` и зелёного CI
не делает их активными до owner release Primary; GitHub токен никогда
не попадает в Repo actor. Политика `ASK` не заменяет semantic
revalidation перед будущим полностью автоматическим publisher.

**Следующий source-кандидат — постоянная политика владельца:**
редактор V2 после отдельного согласованного перехода authority может
разрешить `DENY / ASK / ALLOW` для трёх методов управляемых меток,
но **не изменяет** установленный ASK автоматически. `ALLOW` — постоянное
решение владельца для уже допущенного Repo actor, подтверждаемое WebAuthn
при изменении правила, а не доказательство согласования каждой заявки.
При выполнении остаются обязательными registered task PR, точные SHA/body/
labels preconditions, семантические ограничения и readback; профиль
`release-label-publisher-v1` сохраняет независимый ASK. Переход требует
явного owner-reviewed `ownerPolicyAuthorityUpgrade: OWNER_LABELS_V1`
и специального upgrade только над V2 без событий изменений; см.
[раздел редактора V2](../OWNER-POLICY-EDITOR-V2.md).
Принятый UC-GW-011 и текущий Primary остаются ASK, пока не выполнен
полный owner release и live acceptance, включая обновление текста UC.

**Trusted publisher (отдельная активация):**
[проект P3](../RELEASE-LABEL-PUBLISHER-P3-REVIEW.md) фиксирует
principal/trigger/scope;
[trusted one-shot runner](../../fortis_approvals/integrations/github/PUBLISHER-RUNNER.md)
и [owner-sealed startup](../P3-4-PUBLISHER-OWNER-STARTUP.md)
имеют независимые source/owner gates. Их source не выдаёт credentials/grants
и не запускает unattended publisher. Этапы и статусы — в
[едином roadmap](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/BACKLOG-IMPROVEMENTS.md);
здесь только повторяемые ASK/READ правила.

**Методы (см. закрытый Python-контракт
`fortis_approvals/integrations/github/contract.py`):**

| Тип | Метод | Результат / ограничение |
| --- | --- | --- |
| READ | `list_repository_labels(repo, page, per_page)` | Постранично, только `name,color,description`; max 50/page |
| READ | `list_pr_labels(repo, number, page, per_page)` | Только PR, не произвольный Issue |
| READ | `get_pr_release_label_context(repo, number)` | Открытый same-repo task PR → head/base SHA, SHA-256 body и полного набора labels; тело PR и token не раскрываются |
| READ (capability-gated) | `get_pr_release_impact_evidence(repo, number, expected_head_sha)` | Отдельный bounded READ: тело PR (до 20 000 символов), head/base SHA, same-repo/head/base provenance и SHA-256 body; требует точный HEAD, open/non-draft/unmerged `task/` PR в `main`. **Не предоставляет право записи или CI PASS** |
| ASK | `create_release_label(repo, name, request_id, reason)` | Только `build:<target>` и перечисленные `release:<action>`; цвет/описание задаёт сервер, дубликат STOP |
| ASK | `add_pr_release_labels(..., labels, request_id, reason)` | До 5 существующих управляемых labels; **POST добавляет**, не заменяет чужие |
| ASK | `remove_pr_release_label(..., name, request_id, reason)` | DELETE ровно одного управляемого label; `release:review-required` и чужие labels запрещено удалять |

**Как:** выполнять только закрытые typed операции по текущему exact-head PR,
trusted policy, owner ASK и независимому readback.

**Порядок работы:**

1. Проверить текущий owner-managed `main`, полный
   `release/targets.yaml`, точный HEAD и успешный Release Impact
   из **доверенного** API/checkout. После установки нового READ использовать
   `get_pr_release_impact_evidence` для ограниченного полного PR body и
   same-repo provenance; independently повторно вычислить Release Impact
   по exact-HEAD Git-объектам, а не PR-controlled CI artifact. Полученное
   тело — недоверенные данные, исполнять PR-код запрещено. Выполнив
   пересчёт, снова сверить `bodySha256` с label context; разница = STOP.
   Вычислять план меток только единым `fortis-release-impact-action`
   (pure label projection/admission).
2. Прочитать `get_pr_release_label_context` и все нужные определения
   `list_repository_labels`. При отсутствии определения — отдельный ASK
   `create_release_label`, owner approval и независимый readback;
   только после этого повторно читать контекст PR.
3. Отправить запрос `add_pr_release_labels` или
   `remove_pr_release_label` с **точными** `expectedHeadSha`,
   `expectedBaseSha`, `expectedBodySha256`,
   `expectedLabelsSha256`, `number` и immutable
   `requestId`. Любой stale PR, fork, draft, чужой repo,
   non-`main` base, незарегистрированная task branch, неизвестное
   имя label либо несоответствие digest → STOP до мутации.
4. Владелец просматривает ASK preview и подтверждает через WebAuthn.
   Native adapter снова проверяет scope, актуальный PR и набор labels
   **перед** одним ограниченным GitHub REST-эффектом; проверяет PR
   HEAD/body и **весь** набор меток после эффекта, сохраняет receipt.
   Повтор с тем же UUID возвращает установленную квитанцию.
5. `UNCERTAIN`, HTTP timeout/403, SHA race или неполный readback →
   [UC-GW-009](incidents.md#uc-gw-009), без слепого retry,
   смены requestId или попытки GitHub connector как обхода.

**Важный предел:** GitHub REST не поддерживает атомарный compare-and-swap
по PR SHA вместе с изменением labels. Даже при свежих preflight/readback
возможна гонка; в этом случае это **UNKNOWN/STOP**, а не `Deployed`.
Не использовать `PUT /issues/{n}/labels`, который заменяет все метки,
и не удалять ручной `release:review-required`. Действия здесь
не запускают build, Windows install, GitHub Deployment или GitHub Projects.

**Релиз и критерий готовности:**

- Для source: отрицательные контрактные/HTTP route/forged input
  тесты + existing tests, `scripts/update-source-manifests.py --check`
  и `scripts/test-source.sh`; exact-head Source CI на PR.
- После owner Review/Merge: `update_main_from_pr` с точным merge SHA;
  обновление image-baked Gateway — **только** через
  [UC-GW-005](releases.md#uc-gw-005) и
  [Primary operator runbook](../PRIMARY-GATEWAY-OPERATIONS.md),
  с сохранением PENDING/APPROVED/CLAIMED/UNCERTAIN, backup и
  rollback. Установка требует отдельного owner approval.
- `LIVE_API_VERIFIED` только после проверки
  `/v1/workspace/capabilities`, реального READ token scope,
  отказа wrong actor/repo, controlled ASK на тестовом PR,
  точного GitHub readback и Core receipt. Без live evidence
  конкретная операция остаётся **NOT_VERIFIED**, даже при принятом source.
- Для автоматического publisher нужны отдельные принятые trusted
  workflow/worker, независимая source metadata revalidation и
  policy acceptance; текущие ASK-методы **не являются**
  unattended автоматическим назначением.

**Готово:** Source/CI и owner merge отдельно от live acceptance.
Только deployed Gateway + owner ASK, GitHub readback без потери чужих
меток и сохранённый Core receipt позволяют LIVE_API_VERIFIED; иначе STOP.

**GitHub Projects V2** здесь не активируется: он требует конкретного
owner-approved project ID, доступов GraphQL и собственного typed
UC-GW-003 с pagination, item-idempotency/receipt и live readback.
GitHub Project — только проекция планирования; Deployment evidence
всегда отдельно. Состояние этой следующей задачи — в
[едином Gateway backlog](../BACKLOG-IMPROVEMENTS.md).


### Owner-selectable outer policy (future reviewed release, source candidate)

The installed P3 publisher approval and the current policy map above stay
as-is until an explicit owner release. The next V3 owner-policy candidate
offers `DENY/ASK/ALLOW` for **each existing actor-granted method**, including
the ordinary Repo `update_pull_request`, without operation-name ASK_ONLY
ceilings. Owner consent to change that persistent policy uses fresh WebAuthn;
consent to an individual `ASK` action is a separate Core request.
Provider preflight, receipt, immutable PR/commit/labels and independent
executor/publisher proof stay in force. For signed/publisher methods an outer
ALLOW can still have an effective inner ASK. See
[Owner policy editor V2, subsequent all-methods section](../OWNER-POLICY-EDITOR-V2.md).
No other actor scope or provider credentials are activated by this source.
