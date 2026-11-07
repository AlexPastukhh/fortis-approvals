# Providers и typed операции

## UC-GW-002

**Когда:** требуется подключить новый внешний API/service к Gateway.

**Цель:** typed provider с минимальным scope, проверками и owner approval.

**Как:** по [extension contract](../INTEGRATION-EXTENSIONS.md) и
[пакету integrations](../../fortis_approvals/integrations/README.md)
проверить совместимость и использовать provider scaffold в task worktree.
Определить закрытые request/result schemas, preview/effect/receipts,
trusted actor/target policy и READ/ASK/Reject acceptance. Новые permissions
не возникают от каталогизации provider. Credential отдельно по [UC-GW-004](credential-lifecycle.md#uc-gw-004),
image activation по [UC-GW-005](releases.md#uc-gw-005), GitHub публикация —
через глобальные UC-CONT-002/003.

**Готово:** поддержка подтверждена в live каталоге и авторизованном readback;
набор операций/ошибок сверяется с кодом, а не продублирован здесь.

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
   или image-baked client требует ровно одного owner-managed `Apply/Build` и
   `Backup/Promote` с rollback и live capability/contract acceptance; изменение
   только внешнего Repo-клиента иногда требует обновления source, но не image —
   выяснить по Dockerfile COPY/runtime импорту, не делать rebuild вслепую.

**Готово:** request/response и runtime policy совместимы, старые операции
продолжают работать, отказ/гонка доказаны тестами, точный PR SHA имеет CI success,
а новый метод подтверждён live после отдельного релиза. Разделять `SOURCE_READY`,
`PR_MERGED`, `IMAGE_ACTIVATED` и `LIVE_API_VERIFIED`.
