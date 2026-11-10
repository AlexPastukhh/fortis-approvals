<a id="uc-gw-009"></a>

# UC-GW-009 — AI расследует заявку, владелец закрывает без повтора операции

**Когда:** операция вернула `UNCERTAIN`/`REMOTE_OUTCOME_UNCONFIRMED`,
пропало подтверждение GitHub/worker или владелец хочет просмотреть/закрыть
неопределённую заявку в Owner Portal.

**Цель:** дать ИИ всю доступную информацию о **своей** заявке, отличить
проверенный фактический эффект от неизвестного и позволить владельцу
административно убрать заявку из списка разбора без выдуманного результата.

**Как:**

1. **ИИ сначала самостоятельно устанавливает UUID** по уже имеющемуся
   контексту запроса, сохранённым результатам инструментов и журналу вызовов
   Fortis Repo; не отправляет владельца в Portal за ID, пока доступные
   источники не проверены. Для каждого кандидата через авторизованный machine TLS
   `fortis_approvals.workflow.client.default_client().details(uuid)`
   (серверный `POST /v1/workspace/details`) прочитать полный Core request
   с исходными params/reason, preview, actor/decision, timestamps,
   fingerprint, result/failure, постраничный audit, состояние/result/error
   worker и имеющийся durable receipt. Дополнительные страницы событий —
   `event_offset`/`event_limit`. Чтение разрешено **только actor,
   инициировавшему запрос**. Claim token, owner cookie и секреты не выдаются.
2. **Не делать вывод только из `UNCERTAIN` или отсутствующего receipt.**
   Сопоставить operation/target/task, ожидаемые и новые SHA с независимыми
   read-only данными: GitHub branch/PR/CI/commit, локальными Git refs,
   worktree и worker journal. Отдельно различать эффект исходной заявки,
   последующие успешные операции и текущее состояние GitHub. Выдать вывод:
   «выполнение подтверждено», «невыполнение подтверждено» или «недостаточно
   доказательств», с указанием доказательств и границ уверенности.
   `details()` не запускает effect, worker claim, reconcile или retry.
   `reconcile` допускается лишь отдельно по контракту и не заменяет
   расследование.
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

## Самостоятельная инвентаризация и расследование: AI-first

**По умолчанию ИИ выполняет весь доступный технический разбор сам.**
Owner Portal — интерфейс решений владельца, а не обязательный источник UUID,
логов или Git-диагностики. Не просить владельца поочерёдно открывать карточки
и переписывать `ID`, если их можно восстановить из уже доступных инструментов.

1. **Найти кандидатов на UUID.** Использовать ID из исходного ответа Gateway,
   предыдущих ходов/логов задачи и, при наличии подключения Fortis Repo,
   `get_recent_tool_calls` (по узкому временному интервалу и связанным
   `workspace.*` / `github.*` вызовам). Сопоставить `repository`, `operation`,
   `task`, параметры, SHA и время. Журнал инструментов ограничен глубиной и
   может не содержать все запросы; не объявлять найденный набор исчерпывающим.
   Не публиковать в отчёте сырые журналы с возможными секретами.
2. **Проверить каждый UUID, а не угадывать статус.** В разрешённом Repo
   окружении выполнить, например:

   ```python
   from fortis_approvals.workflow.client import default_client

   request_id = 'UUID-из-исходного-ответа-Gateway'  # заменить точным UUID
   client = default_client()
   row = client.details(request_id)  # только чтение; без claim/replay/reconcile
   request = row['request']
   print(request['requestId'], request['state'], request['request'])
   print(row['worker'], row['receipt'], row['eventTotal'])
   # Остальные события: details(request_id, event_offset=100, event_limit=100)
   ```

   `details()` возвращает полную actor-owned карточку: исходные `params`,
   причину, решение, историю событий, состояние worker, result/error и receipt.
   Авторизация ограничена **инициировавшим machine actor**; чужие UUID
   недоступны. Режим только для чтения, owner cookie/WebAuthn не нужны.
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

- **Доказано выполнение конкретного исходного UUID:** не повторять эффект;
  фиксировать receipt и достаточные независимые подтверждения.
- **Доказано невыполнение:** если также доказано, что прежний исполнитель
  больше не может выполнить старую операцию позднее (нет активного
  `CLAIMED` с неизвестным состоянием), и задача ещё актуальна, выполнить
  её как **новый штатный запрос с новым requestId**, новой проверкой SHA,
  preconditions, actor scope и ALLOW/ASK/DENY. Owner ASK подтверждается
  отдельно. Старый Core audit не редактировать и не использовать старый UUID.
  `CANCELLED_BEFORE_DISPATCH` — машинное доказательство отсутствия
  dispatch исходной заявки. Для остальных операций требуются дополнительные
  независимые доказательства, а не простое отсутствие результата сейчас.
- **Не удалось доказать ни исполнение, ни невыполнение:** STOP, а не
  автоматический повтор. Отсутствие branch/PR/receipt/heartbeat не даёт
  положительного доказательства отсутствия исходного эффекта. `CLOSED_UNCONFIRMED`
  только убирает запись из операционного списка, но не устанавливает исход.

**Версия API важна.** `POST /v1/workspace/list_uncertain` принят и
установлен в Primary 2026-11-10 (`9481699faaa297d8ec1fb45b4f14be50ae17406f`).
Это список текущих UNCERTAIN только инициировавшего machine actor через TLS;
Owner Portal, WebAuthn и machine claim здесь не используются.
Перед вызовом всегда проверять live `incidentInventory.readOnly == true`:
исходник Docker Repo может отличаться от установленного image.
Owner endpoint GET /v1/owner/unresolved не разрешён machine client.

Использование после установки новой версии:

    from fortis_approvals.workflow.client import default_client
    client = default_client()
    cap = client.gateway.post('/v1/workspace/capabilities', {})
    assert cap.get('incidentInventory', {}).get('readOnly') is True
    offset, ids = 0, []
    while True:
        page = client.list_uncertain(offset=offset, limit=100)
        ids.extend(item['requestId'] for item in page['items'])
        if page['nextOffset'] is None:
            break
        offset = page['nextOffset']
    for request_id in ids:
        details = client.details(request_id)
        print(request_id, details['diagnostic'])

Ответ включает actor-owned UUID, service/operation/target, state,
createdAt, failure, а также total, truncated и nextOffset. Он не
содержит полные params, owner session или worker claim token.
Каждая страница читается согласованно в одной SQLite-транзакции, но
**все страницы вместе не являются одним атомарным snapshot**. При
выпуске нужна независимая worker quiescence и повторная сверка
полноты на отсутствие параллельных переходов state.

Новое поле details()['diagnostic'] различает только наблюдаемые
стадии: worker job отсутствует, FAILED, CLAIMED, DONE или отсутствует
GitHub receipt. rootCause=UNDETERMINED всегда означает, что точную
причину/результат исходного эффекта не доказали. Core в старых
инцидентах сохраняет общий REMOTE_OUTCOME_UNCONFIRMED, а worker часто
только UNCERTAIN: потерянный traceback восстановить нельзя.
Датированный read-only разбор см. в
[исследовании](../../fortis_approvals/evidence/UNCERTAIN-DIAGNOSTIC-INVESTIGATION-20261110.md).

Если установленный API не умеет list_uncertain либо полнота по
нескольким страницам не доказана, ИИ сообщает точный scope и gap;
у владельца запрашивает только объективно недоступную инвентаризацию.
Ни список, ни diagnosis не запускают reconcile, replay или finish.
Закрытие, WebAuthn и Primary deployment остаются owner-only.

**Готово:** ИИ собрал read-only карточку и внешние доказательства (или явно
`UNKNOWN`); владелец при желании закрыл заявку, Owner Portal показывает
`CLOSED_UNCONFIRMED`, оригинальный worker/job/audit не подменены.
Отдельный worker claim может оставаться неразрешённым после закрытия.

Технический источник: [инцидентный Core и Owner API](../../fortis_approvals/incidents.py),
[typed client](../../fortis_approvals/workflow/client.py) и
[операционные правила](../PRIMARY-GATEWAY-OPERATIONS.md).

<a id="uc-gw-010"></a>

## UC-GW-010 — Read-only worker activity and safe typed error evidence

**Когда:** нужно понять, есть ли наблюдаемые признаки исполнения `CLAIMED`
при расследовании или перед owner-managed release. Не выполнять `claim`,
`resume`, `finish`, `reconcile` или повтор исходного эффекта ради диагностики.

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
