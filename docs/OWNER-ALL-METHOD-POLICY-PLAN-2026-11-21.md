# P1: единая политика владельца для всех методов Gateway

**Владелец требования:** Owner Portal / «API и политики». **Статус на 2026-11-21:** план принятого владельцем поведения; НЕ свидетельство готового к production кода. [Текущий handoff и gate проверки](OWNER-ALL-METHOD-POLICY-HANDOFF-2026-11-21.md). Канонический backlog — [P1 API onboarding](BACKLOG-IMPROVEMENTS.md#api-onboarding-program), не создаём дублирующий реестр.

## 1. Необходимая семантика продукта

Для **каждой уже зарегистрированной, установленной, выданной данному actor и доступной в указанном target/environment операции** всех провайдеров владелец выбирает **DENY / ASK / ALLOW** через Owner Portal. Ни серверный список названий методов, ни HTTP verb, ни «READ/WRITE», ни старое значение ASK не ограничивают доступные три варианта в редакторе:

- **DENY** — запрещает ИИ отправлять операцию;
- **ASK** — инициируется отдельный Core PENDING и WebAuthn подтверждение владельцем *данного вызова*;
- **ALLOW** — операция проходит без отдельного подтверждения владельцем *данного вызова*, но лишь в уже выданном scope.

GitHub (`update_pull_request`, merge и release labels), Sonar, Workspace, installed extensions и PowerShell должны отображать все три варианта. **Это не разрешение добавлять actors, targets, credentials, providers, grants или методы:** отсутствующий registration/grant продолжает fail closed. При новой регистрации операция попадает в инвентарь только через доверенный source/конфигурацию и явную область доступа.

WebAuthn для **изменения постоянного правила** — отдельная свежая strong/UV ceremony с exact old/new, revision, scope, source и credential bindings. Она не заменяет WebAuthn на **конкретную ASK-заявку**. ИИ не получает owner-only mutation API. В Owner Portal показывать current configured rule отдельно от target-evaluated effective rule, иначе возникают ложные «ASK + ALLOW» из несовпадающих снимков.

## 2. Что ALLOW НЕ отключает

- Точная типизированная валидация provider inputs; допуск actor, grant, repo/project/target/environment и trusted executor binding.
- SHA/CAS, PR provenance, namespace, upstream permissions, receipt, pre-effect rechecks, version/fingerprint, no blind replay after UNCERTAIN.
- Дополнительные независимые проверки provider/executor. Для `powershell.execute` внешний owner-ALLOW **не является** разрешением произвольной команды: Windows Executor применяет внутреннюю командную Dynamic ASK/DENY/ALLOW модель и proof, приоритет DENY > ASK > ALLOW. Если внутренний ASK необходим, должно быть **одно** Core PENDING, не два.
- Условные политики и callbacks — независимые preconditions. Нельзя превращать их veto в безусловный ALLOW. При несоответствии семантики ASK в синхронном методе — реализовать одноразовый deferred-approval протокол, не превращать ASK в ALLOW и не показывать ложную поддержку.

## 3. Поэтапная реализация и объективные gates

1. **Admission вместо method allowlist.** От зарегистрированных literal/callable policies, реально подключённых adapters, доверенных grants, binding и готовности provider вывести общий редактируемый список; `_GITHUB_ASK_ONLY` и `_GITHUB_FLEXIBLE` не используются в новой модели. Старые ветки допуска сохранять лишь для совместимости предыдущих release records. Verify positive/negative matrix для GitHub, Sonar, Workspace, extension signed write/read, Mirror, PowerShell; не доверять одной UI-выдаче `editablePolicies`.
2. **Сохранение истории authority V2.** Для базы, где owner уже менял ALLOW→ASK, новая миграция должна точно доказать старый authority digest, старый effective projection, все старые events и UV-bound изменения; сохранить revision, rows, actor/target exclusions, отдельные authority epochs и все хэши. No row rewrite, no revision reset, no database surgery. Reject tampered epoch, reordered events, drift source/grant/credentials, old-image rollback and unreviewed widening. Reconcile `PENDING / APPROVED / DISPATCHED / UNCERTAIN / CLAIMED` separately; worker quiescence is independently proven by owner.
3. **Нативные синхронные READ + ASK.** Core PENDING must precede upstream GET, owner decision is bound to exact requestId, actor, method, target, params and TTL; single-use consume under SQLite lock before request, fail-closed on changed policy/version. Correct 202/PENDING machine DTO and client contract. Test non-replay, reject, expiry, races and actual R7 installation, plus protected receipt/state-growth handling for any new tables.
4. **WRITE runtime matrix.** Проверить не только selector, но реальное исполнение под ALLOW и ASK: `update_pull_request`, GitHub CI/merge/release labels, Sonar mutation, extension signed write, Workspace and PowerShell. ALLOW must not bypass provider owner-only independent proof where still required; reconcile incompatible contracts rather than lying in UI. Unknown/partial effects never blind-replayed.
5. **Owner Portal UI.** Один V2 workbench, стабильная группировка/фильтры провайдера, постоянные три варианта для eligible rows, честные disabled/not-installed/grant-missing rows; atomic preview → WebAuthn → result/UUID readback → fresh inventory. Regression for stale browser inventory and provider filter (PR #214 already merged).
6. **Acceptance and publication.** Add tests to `scripts/test-source.sh`, regenerate both tracked source manifests, run focused/source/CI including FIDO2 and negative runtime tests, exact SHA PR with truthful releaseImpact. Owner reviews+merges via GitHub UI; no machine merge. Windows sync/build/Check → protected Apply → backup/promote under UC-GW-005 after independent quiescence and image/state compatibility checks. Source merge alone never activates policy.

## 4. Release safety and scope

The owner-reported last Windows activation was image
`sha256:97c18ce70421a03a81dd2d333cbc938ae8e63119fe8cb188b8bdd3d78f45e9f7`
from source `0ca724b8caed3ab30a5fb5ea964e4ebf1ec74bfe`,
configuration `UNIFIED_V2 + OWNER_LABELS_V1`. Owner verified running/healthy
and V2 `0|0|0` **before** changing the release-label policy to ALLOW and
back to ASK (therefore the V2 history is no longer necessarily empty).
Subsequent Backup/Promote for that particular release were **not
confirmed in this conversation**. Re-read actual Windows protected release
records, latest V2 revision, source image and primary/backup pointers,
owner acceptance and worker state before any proposed release.

**STOP:** no permission change, Gateway activation, code merge, database
migration, cleanup or rollback follows merely from this plan.
