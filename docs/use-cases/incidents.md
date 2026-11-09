<a id="uc-gw-009"></a>

# UC-GW-009 — AI расследует заявку, владелец закрывает без повтора операции

**Когда:** операция вернула `UNCERTAIN`/`REMOTE_OUTCOME_UNCONFIRMED`,
пропало подтверждение GitHub/worker или владелец хочет просмотреть/закрыть
неопределённую заявку в Owner Portal.

**Цель:** дать ИИ всю доступную информацию о **своей** заявке, отличить
проверенный фактический эффект от неизвестного и позволить владельцу
административно убрать заявку из списка разбора без выдуманного результата.

**Как:**

1. Сохранить исходный UUID. Через авторизованный machine TLS
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

**Готово:** ИИ собрал read-only карточку и внешние доказательства (или явно
`UNKNOWN`); владелец при желании закрыл заявку, Owner Portal показывает
`CLOSED_UNCONFIRMED`, оригинальный worker/job/audit не подменены.
Отдельный worker claim может оставаться неразрешённым после закрытия.

Технический источник: [инцидентный Core и Owner API](../../fortis_approvals/incidents.py),
[typed client](../../fortis_approvals/workflow/client.py) и
[операционные правила](../PRIMARY-GATEWAY-OPERATIONS.md).
