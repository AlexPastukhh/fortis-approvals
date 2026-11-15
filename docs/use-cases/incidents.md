<a id="uc-gw-009"></a>

# UC-GW-009 — ИИ видит все заявки и расследует исход; решение остаётся у владельца

**Когда:** нужно проверить **все** заявки из «Требуют разбора», включая заявки
других AI-инициаторов, обнаружить ожидающее решение, найти неизвестный
результат GitHub/worker или безопасно завершить старый инцидент.

**Цель:** любой AI с действующей machine TLS/grant-аутентификацией может
прочитать полный глобальный реестр и карточку **любого** инициатора,
но не получает права принимать решения или повторять эффекты.
Владелец отдельно отменяет/закрывает заявки в Owner Portal.

**Как:**

1. **ИИ сначала получает глобальный read-only список** через
   `WorkflowClient.list_requests()` (рецепт и семантика ниже), а не просит
   владельца переписать UUID из Portal. Сопоставляет actor, state,
   service/operation/target, время и контекст исходного действия; при
   необходимости использует прошлые ответы и журнал инструментов для
   дополнительных доказательств. Для известного UUID штатный клиент
   `default_client().incidents.inspect(uuid)` сам собирает ограниченные страницы
   Core audit, worker/receipt и разрешённые GitHub READ, возвращая безопасную
   evidence-проекцию, границы полноты и `retryAuthorization=NONE`.
   Он использует существующий `details()` (доступный для любого actor с PR #62)
   и требует live `globalRequestInventory.crossActorDetails=true`.
   Для углублённой ручной проверки первоисточника остаётся read-only
   `details(uuid, event_offset=..., event_limit=...)`; его сырые params,
   preview и worker result не публиковать в отчётах. Ни один вариант не
   возвращает claim token или owner credentials. Точный контракт inspector —
   [техническая спецификация](../INCIDENT-INSPECTOR.md).
2. **Не делать вывод только из `UNCERTAIN` или отсутствующего receipt.**
   Сопоставить operation/target/task, ожидаемые и новые SHA с независимыми
   read-only данными: GitHub branch/PR/CI/commit, локальными Git refs,
   worktree и worker journal. Отдельно различать эффект исходной заявки,
   последующие успешные операции и текущее состояние GitHub. Выдать вывод:
   «выполнение подтверждено», «невыполнение подтверждено» или «недостаточно
   доказательств», с указанием доказательств и границ уверенности.
   `inspect()` и `details()` не запускают effect, worker claim, reconcile или
   retry; обнаруженная ветка/PR без привязки к исходному UUID означает только
   достигнутое состояние. `reconcile` — отдельная потенциально изменяющая Core
   операция, не часть read-only расследования.
3. Владелец открывает [Owner Portal](http://localhost:19203),
   входит обычным passkey/WebAuthn, выбирает «Требуют разбора», читает
   карточку и при необходимости нажимает **«Закрыть заявку»**.
   Для `UNCERTAIN` это один owner-local action через существующую
   сессию и CSRF: **нет** второго WebAuthn, формы backup, объяснения
   или требования `worker=FAILED`. ИИ **не** вызывает owner routes
   и не закрывает заявку самостоятельно.
4. Закрытие записывает `CLOSED_UNCONFIRMED` с owner audit, сохраняет
   исходный payload, result/failure и всю историю. Это **не** доказательство
   `EXECUTED`/`NOT_EXECUTED`, не отменяет GitHub effect и **не** меняет
   `CLAIMED` worker job. Не создавать фальшивый receipt, не запускать
   повторный commit/push/create_task и не исправлять SQLite вручную.
   При сохранённом `CLAIMED` соблюдать отдельную quiescence и точный
   preservation scope при будущих backup/release.

### Действующий глобальный read-only API и смысл состояний

**Установлено 2026-11-10 (PR #62, owner Promote).** Любой
аутентифицированный AI-инициатор может вызвать
`POST /v1/workspace/list_requests` через `client.list_requests()`:
глобальные метаданные всех actor с пагинацией, без фильтра по инициатору.
`client.details(UUID)` возвращает полную карточку любого UUID
(request, preview, decision/fingerprint, audit, worker, доступный receipt).
Для полной истории событий использовать `event_offset/event_limit`.
Это **чтение**, не owner role, не claim/reconcile/replay/approve/cancel;
чужой `result()`/обычный `status` остаётся ограничен исходным actor.
Machine credentials, owner session/WebAuthn и worker claim token не выдаются.

**Точное соответствие разделу Owner Portal:**

| Core state | Смысл | Раздел / действие |
| --- | --- | --- |
| `PENDING` | ASK ещё ожидает решения | «На согласовании», **не** «Требуют разбора» |
| `APPROVED` | Решение принято, `DISPATCHED` ещё не отмечен | «Требуют разбора»; владелец может **отменить до dispatch** при всех проверках |
| `DISPATCHED` | Gateway отметил начало эффекта; результата может не быть | «Требуют разбора»; **не** считать неисполненным |
| `UNCERTAIN` | Исход эффекта неизвестен | «Требуют разбора»; разбор по evidence, возможна owner-closure без выдуманного результата |
| `CANCELLED_BEFORE_DISPATCH` | Owner подтвердил защищённую отмену до dispatch | История; не исполнять старый UUID |
| `CLOSED_UNCONFIRMED` | Административно закрыто, исход **не** доказан | История; возможный `CLAIMED` остаётся отдельным фактом |

`list_requests(unresolved_only=True)` возвращает **четыре** состояния:
`PENDING`, `APPROVED`, `DISPATCHED`, `UNCERTAIN`.
Чтобы получить **точно «Требуют разбора»**, ИИ выбирает из результата
только три последние состояния (без `PENDING`).
`unresolved_only=False` включает также завершённую/закрытую историю;
это не команда на очистку базы. `CLAIMED` — **worker state**, а не
Core state и не дополнительная категория в списке Portal.

## APPROVED в «Требуют разбора»: безопасная отмена и быстрая автопроверка

`APPROVED` — разрешение записано, но `DISPATCHED` ещё не зафиксирован.
Owner Portal по-прежнему показывает `APPROVED`, `DISPATCHED` и `UNCERTAIN`
в «Требуют разбора». Для зависшего `APPROVED` владелец может нажать
**«Отменить до выполнения»**: authenticated owner session + Origin + CSRF,
точный UUID и fingerprint, без второй WebAuthn ceremony. Gateway берёт
write-lock своей SQLite-транзакции, проверяет именно `APPROVED`, отсутствие
исторического `DISPATCHED`, результата и native worker job и только тогда
переводит в `CANCELLED_BEFORE_DISPATCH`. Audit сохраняет owner и исходный
fingerprint; `PENDING`, `DISPATCHED`, `UNCERTAIN` и прочие состояния
**не допускаются**. Параллельный Core.execute либо фиксирует `DISPATCHED`
первым (тогда отмена отклоняется), либо видит отмену и не исполняет старый UUID.
Отмена убирает заявку из «Требуют разбора», но не стирает историю и не
изменяет остальные jobs или receipts.

Отдельная кнопка **«Автопроверка результата»** вызывает owner-only
`POST /v1/owner/incidents/assess` без dispatch/reconcile/retry. Это только
записи Core audit/state и локальных durable worker/GitHub/Sonar receipts:
`CANCELLABLE_IF_STILL_APPROVED` (моментальный read, **не** гарантия без
транзакционной отмены), `VERIFIED_NOT_DISPATCHED` (успешная защищённая
отмена), `CORE_EXECUTION_CONFIRMED` (Core зафиксировал `EXECUTED`),
`RECEIPT_PRESENT_RECONCILE_REQUIRED` (дальше отдельная проверка существующей
квитанции) или `OUTCOME_UNCONFIRMED`. Отсутствие receipt никогда не становится
автоматическим `NOT_EXECUTED`. Недоступность evidence должна давать
неопределённость/STOP, а не ложный PASS.

**Возобновление работы:** после `VERIFIED_NOT_DISPATCHED` ИИ может
подготовить новый requestId и заново проверить текущие SHA/preconditions,
policy и разрешения. Это **новая операция**, не retry/cancel/replay старого
worker claim. После `DISPATCHED` или `UNCERTAIN` автоматический повтор
запрещён, если независимое доказательство исхода не получено. Безопасная
проверка результата допустима как отдельный read; запись `EXECUTED` по
полученному receipt делается штатной reconciliation, не скрытым эффектом
вызова «Автопроверка».

**Не путать** отсутствие `APPROVED` в списке с доказательством отсутствия
внешнего эффекта: только `CANCELLED_BEFORE_DISPATCH` с соответствующим
защищённым audit и без `DISPATCHED` даёт это подтверждение для данного
Gateway request. Подробный общий алгоритм расследования — ниже.

**Установленный переход:** 2026-11-10 владелец выполнил
`Check → Apply → Backup → Promote` для PR #62 с точным сохранением
двух `APPROVED` и исторического `CLAIMED`. Глобальный машинный API
и обе исходные карточки проверены read-only после активации; сами
`APPROVED` **не отменены** этим выпуском. Нажатие отмены/автопроверки
в браузере владельца требует отдельного live-подтверждения.
[Primary runbook](../PRIMARY-GATEWAY-OPERATIONS.md) содержит границы
переноса и восстановления. Никакой ручной правки SQLite.

## Самостоятельная инвентаризация и расследование: AI-first

**По умолчанию ИИ выполняет весь доступный технический разбор сам.**
Owner Portal — интерфейс решений владельца, а не обязательный источник UUID,
логов или Git-диагностики. Не просить владельца поочерёдно открывать карточки
и переписывать `ID`, если их можно восстановить из уже доступных инструментов.

1. **Найти все заявки без ручного перечисления UUID.** Проверить live
   `globalRequestInventory.readOnly/crossActorDetails`, затем пройти все
   страницы `list_requests(unresolved_only=True)`. Для раздела «Требуют
   разбора» фильтровать `APPROVED/DISPATCHED/UNCERTAIN`, а `PENDING`
   учитывать отдельно как ожидающие согласования. При расследовании
   использовать исторический `unresolved_only=False` и исходные
   tool-call/evidence записи для сопоставления task, SHA и эффектов.
   Если версия Gateway не поддерживает глобальный API — явно указать
   ограничение, не выдавать actor-scoped `list_uncertain` за полный список.
2. **Проверить каждый UUID, а не угадывать статус.** В разрешённом Repo
   окружении выполнить, например:

   ```python
   from fortis_approvals.workflow.client import default_client

   request_id = 'UUID-из-исходного-ответа-Gateway'  # заменить точным UUID
   client = default_client()
   report = client.incidents.inspect(request_id)
   print(report['requestId'], report['coreState'], report['outcomeAssessment'])
   print(report['missingEvidence'], report['retryAuthorization'])
   ```

   `inspect()` возвращает безопасную доказательную проекцию без raw payload
   и выполняет автоматический ограниченный обход audit-страниц. Неуспешный
   GitHub READ или неполный снимок явно отмечается `missingEvidence`.
   Для исходных params/preview и отдельных audit-событий используйте
   `details()` только при необходимости. Оба метода — read-only;
   право исполнять чужие заявки от этого не возникает.
3. **Независимо исследовать эффект.** Для GitHub использовать разрешённые
   Gateway READ (ветки, commits, PR, CI, точные SHA); для локальных действий —
   Git refs, worktree и worker journal в разрешённой Repo-среде, только read-only.
   Отдельно фиксировать: исходная заявка, поздняя успешная заявка, текущее
   состояние GitHub/Repo. Поздний аналогичный успех не является receipt
   исходного UUID; отсутствие receipt/ветки не доказывает отсутствия эффекта.
4. **Вернуть доказательный итог.** Для каждого UUID указать `state`,
   `worker`, `receipt`, найденные независимые свидетельства и один из выводов:
   «исходное исполнение доказано», «неисполнение доказано» или «результат
   исходного исполнения неизвестен». Никакого повторного исполнения,
   `claim`, `resume`, `finish`, `reconcile`, ручного изменения SQLite или
   фиктивного receipt при обычном расследовании. `reconcile` может изменить
   Core state, поэтому не является read-only эквивалентом `details()`.

### После проверки: продолжение задачи без слепого повтора

**Приоритет — проверенная возможность завершить цель, а не доказательство
исторической причины ошибки.** Оценить текущий целевой результат и гарантии
конкретной операции; недостигнутая цель + свежие предусловия + отсутствие
активного конкурирующего worker + разрешённый ограниченный новый intent
означают **продолжать работу**, даже если старый UUID остался `UNCERTAIN`/
`CLOSED_UNCONFIRMED` или `NOT_FOUND`. `retryAuthorization=NONE` у инспектора
не запрещает новый допустимый intent. Точный порядок для GitHub и локального
`cleanup_task` принадлежит [UC-CONT-003](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-003)
и [контракту очистки](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md#task-worktree-cleanup).
Сначала решать, безопасен ли новый WRITE, затем отдельно фиксировать,
что известно и неизвестно о прошлом исполнении. Повторять старый worker claim
или подменять receipt запрещено.

- **Доказано выполнение конкретного исходного UUID:** не повторять эффект;
  фиксировать receipt и достаточные независимые подтверждения.
- **Целевое состояние не достигнуто:** отличать исход старого UUID от
  необходимости продолжить задачу. Fortis не переисполняет завершённый
  UUID: Core защищает fingerprint, worker — durable journal, GitHub adapter —
  receipt. Для завершившегося local worker (`FAILED`, не `CLAIMED`),
  чистого Git и неизменных SHA не требовать абстрактного доказательства
  «невозможности любого отложенного эффекта»: сделать точный readback,
  затем **новую штатную попытку** с новым requestId, новыми preconditions
  и политикой ALLOW/ASK/DENY. При `ASK` требуется новое решение owner.
  Для GitHub branch/ref/push защищённые identity/SHA операции можно
  продолжить только по общему правилу [UC-CONT-003](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-003)
  (HTTP 500, budget попыток, новый requestId и независимый readback).
  Все исходные UUID и audit сохранить, без автоматического replay.
- **GitHub CREATE после UNCERTAIN / HTTP 500 / CLOSED_UNCONFIRMED:**
  неизвестный исход старого UUID не равен запрету продолжать задачу.
  Для PR проверить полные `head/base/HEAD`, включая закрытые PR; если
  нужного PR нет, branch SHA и права совпадают, а исходный job не активен —
  создать **новый** авторизованный запрос. При конфликте уже созданного
  PR снова читать GitHub и использовать его, не делать blind retry.
  Для visual-review Issue допустима новая публикация с **новым `runId`
  и новым requestId**: Gateway резервирует старый `(repo,runId)`,
  но дубли Issue возможны и принимаются в этом сценарии. После публикации
  искать все open/closed Issue по title/body и общему идентификатору
  задачи, **не только новому `runId`**, сообщить оба URL при дубле;
  не удалять автоматически. Детальный алгоритм и лимит попыток
  принадлежат [UC-CONT-003](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-003).
  `retryAuthorization=NONE` запрещает replay исходной заявки инспектором,
  **не** новую корректно авторизованную операцию. Риск дубля не отменяет
  STOP при активном `CLAIMED`, неполном READ или реальном DENY.
- **Результат неоднозначен:** если `CLAIMED` ещё существует, READ неполон,
  точные SHA изменились, повтор может создать нежелательный эффект или
  Gateway возвращает реальный `DENY` — STOP с конкретным объяснением,
  а не новый WRITE через обход. `CANCELLED_BEFORE_DISPATCH` — отдельное
  прямое доказательство отсутствия dispatch. `CLOSED_UNCONFIRMED` только
  убирает запись из списка, но не устанавливает исход.

**Штатный вызов с обновлённым Repo-клиентом:** использовать обычный
`default_client()` и проверять **живые** capabilities, а не наличие
метода в Docker source. Дополнительные поля `claimedAt`/`lastHeartbeatAt`
появятся только после отдельного owner-managed Gateway release;
их отсутствие не является ошибкой и не доказывает quiescence. Для просмотра списка раздела «Требуют разбора»:

```python
from fortis_approvals.workflow.client import default_client

client = default_client()
cap = client.gateway.post('/v1/workspace/capabilities', {})
global_read = cap.get('globalRequestInventory') or {}
assert global_read.get('readOnly') is True
assert global_read.get('crossActorDetails') is True

offset = 0
while True:
    page = client.list_requests(offset=offset, limit=100,
                                unresolved_only=True)
    for item in page['items']:
        if item['state'] in ('APPROVED', 'DISPATCHED', 'UNCERTAIN'):
            print(item['requestId'], item['actor'], item['state'],
                  item['service'], item['operation'], item['target'])
            report = client.incidents.inspect(item['requestId'])
            print(report['outcomeAssessment'], report['missingEvidence'])
            # Не публиковать сырые request/preview/worker result.
    if page['nextOffset'] is None:
        break
    offset = page['nextOffset']
```

Для `PENDING` не использовать фильтр «Требуют разбора»; эти записи
у владельца ждут решения. Для всей истории — тот же метод с
`unresolved_only=False` и проверкой всех страниц.
Каждая страница — отдельный согласованный снимок SQLite, **но
все страницы вместе не атомарны**; при параллельной работе
список нужно перепроверять, а release admission независимо сверяет
точный текущий набор. `list_uncertain()` остаётся прежним
**actor-scoped** диагностическим API и не заменяет глобальную
инвентаризацию. `activity()` тоже actor-scoped; `quiescenceProven=false`
не доказывает остановку worker. Owner-only `GET /v1/owner/unresolved`
машинным ИИ не вызывается.

**Граница live evidence:** на PR #62 выполнены CI и negative tests
для разных machine actors; на работающем Gateway подтверждены
`globalRequestInventory.crossActorDetails=true`, глобальный список и
полные карточки двух `APPROVED`. В текущем сохранённом наборе все
записи принадлежат одному actor; отдельный live-запрос под **вторым
machine grant** пока не подтверждён. Не подменять этим утверждение
о полноценной multi-identity live acceptance.

Новое поле details()['diagnostic'] различает только наблюдаемые
стадии: worker job отсутствует, FAILED, CLAIMED, DONE или отсутствует
GitHub receipt. rootCause=UNDETERMINED всегда означает, что точную
причину/результат исходного эффекта не доказали. Core в старых
инцидентах сохраняет общий REMOTE_OUTCOME_UNCONFIRMED, а worker часто
только UNCERTAIN: потерянный traceback восстановить нельзя.
Датированный read-only разбор см. в
[исследовании](../../fortis_approvals/evidence/UNCERTAIN-DIAGNOSTIC-INVESTIGATION-20261110.md).

Если глобальный API отсутствует или неполон, ИИ сообщает точный
scope и gap; не выдаёт ограниченный результат за «все заявки» и
не запрашивает у владельца данные, которые способен прочитать сам.
Ни список, ни diagnosis не запускают reconcile, replay или finish.
Закрытие, WebAuthn и Primary deployment остаются owner-only.

**Готово:** ИИ проверил глобальный список «Требуют разбора» без actor
blind spot, прочитал нужные карточки и отделил фактические доказательства
от `UNKNOWN`. Если владелец отменил `APPROVED` или закрыл
`UNCERTAIN`, подтверждено соответствующее Core state и сохранность
audit/job; автоматическое исполнение или повтор не запускались.

Технический источник: [инцидентный Core и Owner API](../../fortis_approvals/incidents.py),
[typed client](../../fortis_approvals/workflow/client.py) и
[операционные правила](../PRIMARY-GATEWAY-OPERATIONS.md).

<a id="uc-gw-010"></a>

## UC-GW-010 — Read-only worker activity and safe typed error evidence

**Когда:** нужно понять, есть ли наблюдаемые признаки исполнения `CLAIMED`
при расследовании или перед owner-managed release. Не выполнять `claim`,
`resume`, `finish`, `reconcile` или повтор исходного эффекта ради диагностики.

**Цель:** безопасный actor-scoped read-only worker сигнал без claim token,
без replay и без объявления heartbeat доказательством quiescence.

**Как:** читать штатный activity() и details(UUID), сопоставляя с Core
audit, не инициируя claim, reconcile или выполнение effect.

**Доступ:** новый machine POST `/v1/workspace/activity` (параметры строго
`offset`,`limit`) и `WorkflowClient.activity()`. Возвращает только задания
авторизованного actor в состояниях `QUEUED` или `CLAIMED`, с ограниченной
пагинацией. `lastHeartbeatAt` — время **доставленного Gateway** сигнала от
оригинального claim-token-bound worker, а не доказательство активного
процесса. В ответе никогда нет claim token, payload или секретов.

`RECENT_HEARTBEAT_UNCONFIRMED` (30 с),
`STALE_HEARTBEAT_UNCONFIRMED`, `NO_HEARTBEAT_UNCONFIRMED`, `NOT_CLAIMED`
не превращаются в «worker точно завершил» либо «эффекта не было».
`quiescenceProven` всегда `false`. Старые `CLAIMED` без telemetry сохраняют
NULL timestamps и сигнал `NO_HEARTBEAT_UNCONFIRMED`.

**Не смешивать:** новый глобальный `list_requests()` и `details(UUID)`
из [UC-GW-009](#uc-gw-009) читают заявки всех инициаторов,
но `activity()` остаётся **actor-scoped** и никогда не означает
«все активные workers». В `details()` чужого UUID виден worker
state/evidence, но не claim token и не право завершить job.
При запуске нового worker best-effort POST `/v1/workspace/heartbeat`
принимает только `{requestId,claim}` исходного владельца `CLAIMED`, без
перевыдачи claims, renew leases или возможности повторить эффект.

Для **новых** `UNCERTAIN` сохраняются только `{stage,code}` из закрытого
списка исключений, без сообщений, traceback, URL и credentials: адаптерные audit events
`ERROR_OBSERVED` (`WORKSPACE_ADAPTER`/`GITHUB_ADAPTER`), worker journal после
DISPATCHED и Gateway worker job после `finish`. `details(UUID).diagnostic`
показывает эту информацию при наличии соответствующих событий, но
`rootCause` и `originalEffect` остаются неопределёнными. Исторические
ошибки задним числом не восстанавливаются.

**Граница принятия (2026-11-10):** source принят в `main` через PR #54;
authenticated Repo увидел `workerActivity.readOnly=true` и успешный read-only
`activity()` живого Gateway. Это **не** доказывает точный post-PR образ в
Windows, end-to-end новых heartbeat/errors или quiescence. До отдельного
owner release/provenance evidence и негативных тестов не объявлять полную
live acceptance. Для самостоятельного поиска неопределённых UUID действует
[UC-GW-009](#uc-gw-009). Эта возможность не меняет
`-ConfirmWorkerQuiescent`, exact preservation или Backup/Promote policy.


**Готово:** actor-scoped readback и пределы его достоверности установлены;
подтверждение отсутствия активного worker и release quiescence отдельно
принадлежат владельцу.
