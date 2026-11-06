# Подключение операций через Gateway

Нормативный контракт общего механизма для **новых providers**. Он не заменяет
native Git или существующие Sonar/GitHub контракты. Статус внедрения — в
[current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md), результаты проверок —
в [evidence](../fortis_approvals/evidence/EXTENSIONS-OFFLINE-20261106.md).

## Порядок работы

1. В зарегистрированном task worktree создать пакет командой:
   `python3 -m fortis_approvals.extensions.cli scaffold --source-root . --name tickets`.
   При добавлении операции существующему provider использовать его пакет.
2. В `integrations/tickets/extension.py` задать `PROVIDER`: фиксированный API,
   именованные маршруты, закрытые схемы входа/выхода, обработчики и описание эффекта.
   Дополнить provider README реальными scopes и примерами параметров; написать
   тесты в его `tests/`. Снять `ready=False` только после реализации.
3. В публичной конфигурации выбрать операции, точные targets, ALLOW/ASK и
   логическое имя credential. Проверить её через `cli check`; токен туда не писать.
4. Пройти `scripts/test-source.sh`, обновить source manifests, провести обычный
   Gateway PR/CI/merge. Новый пакет автоматически включается в suite и image:
   Core, ingress, client, список COPY и CI workflow не редактируются.
5. Owner запускает постоянный `Manage-Integrations.ps1`. Скрипт сам выполняет
   pull/build, проверяет конфигурацию, запрашивает недостающие токены, проверяет
   image и клиента, переносит state и проверяет каталог до активации.
6. Подтвердить реальные permissions и результат операций через Gateway:
   ALLOW read, ASK Reject без эффекта, ASK Approve с readback, replay и ошибки —
   применительно к добавленным операциям. Записать evidence и затем current state.
   Успешный build или каталог не означают успешную работу внешнего API.

Для нового чата точки входа: этот контракт → README нужного provider →
current state → последнее evidence. Будущие задачи остаются в follow-up plan.

## Определение операции

`Operation` задаёт `name`, `description`, `kind` (`read`/`write`), валидаторы
`params`/`result`, `execute(ctx)`, при необходимости `credential` и `routes`.
Для write обязательны `preview(ctx)` и его валидатор `preview_result`;
`lookup(ctx)` необязателен и только читает подтверждение неизвестного результата.
Схемы обязаны отвергать лишние поля. Обработчик возвращает ограниченную проекцию
ответа, а не сырые headers/response или исключения SDK.

`ctx` содержит target, проверенные params, request_id и `call(route, path=…,
query=…, body=…)`. `JSONAPI` внедряет credential только внутри Gateway. Origin,
метод, auth header/prefix, route и допустимые query keys задаются trusted source;
клиент не может их передать. Поддерживаются Bearer и API-key headers. OAuth refresh,
подписанные запросы, mTLS и non-JSON API требуют отдельного trusted transport и
своих тестов; шаблон не обещает их автоматическую поддержку.

Preview write и lookup могут пользоваться только read-only routes. Для ASK read
preview не делает upstream запросов. Если подготовке write нужны отдельные права
на чтение, это фиксируется в provider README и scopes токена.
Provider code — доверенный Python из проверенного image, не sandbox для чужих
плагинов; произвольный импорт из volume/URL не поддерживается.

## Политика и конфигурация

`FORTIS_EXTENSIONS_CONFIG` содержит JSON без секретов, например:

```json
{
  "schemaVersion": 1,
  "providers": {
    "tickets": {
      "credentials": {"api": "tickets-prod"},
      "operations": {
        "read_item": {"policy": "ALLOW", "targets": ["record-123"]},
        "set_item": {"policy": "ASK", "targets": ["record-123"]}
      }
    }
  }
}
```

Отсутствующая операция запрещена. Неизвестные provider/operation/actor, пустой
scope и незавершённый handler отвергаются. `actors` необязателен: по умолчанию
существующий R7 machine actor; owner CLI обслуживает этот профиль. Без credential
операция тоже допустима. `{"schemaVersion":1,"providers":{}}` включает только
инфраструктуру; такой starter сохранён в `deploy/extensions.review.example.json`.
Имена github/sonarcloud/workspace/synthetic зарезервированы.

ALLOW и ASK независимы от read/write. Оба проходят через существующий Core,
его actor grant, очередь и durable requestId. ASK требует существующего owner
WebAuthn; при изменении preview, поколения токена или config/code approval
становится устаревшим. DENY действует по умолчанию. Клиент не выбирает политику.

`UNCERTAIN` не повторяет внешний эффект. Reconcile вызывает только lookup;
без доказанного receipt состояние остаётся неизвестным. Для мутации provider
должен проверить concurrency/preconditions и связать receipt с точным requestId
и эффектом. Один generic wrapper не даёт exactly-once гарантии внешнего API.

## Токены и Windows entrypoint

Один дополнительный named volume `fortis-review-secrets` монтируется в Gateway
read-only на `/run/fortis-secrets`. Каждый токен имеет alias и случайное поколение;
файлы 0600 и каталог 0700 принадлежат uid/gid 10001. Существующие legacy volumes
остаются отдельными. Новый токен не требует нового mount на каждое подключение.

После принятия source первая и последующие установки используют один entrypoint
из Windows репозитория (SHA — точный одобренный merged commit):

```powershell
.\fortis_approvals\deploy\Manage-Integrations.ps1 -Action Apply -Build -Pull -SourceSha <merged-SHA> -Config <public-config.json> -Probes <read-probes.json>
```

Перед первым запуском самого entrypoint Windows main должен уже содержать его;
дальше `-Pull` обновляет его и при необходимости продолжает в новой версии сам.
Можно передать уже построенный immutable `-Image sha256:…` вместо build.
`-Action Check` проверяет конфигурацию без замены работающего контейнера.
`-Action Credential -CredentialName tickets-prod` добавляет токен;
`-Rotate` явно заменяет существующий с проверкой поколения. Токен вводится через
защищённый prompt и confidential stdin; его нет в argv/env/репозитории/выводе.
Ротация уже смонтированного alias не требует rebuild или restart. Права на стороне
provider владелец выдаёт отдельно; каталог не может доказать их по наличию файла.

`read-probes.json` — список `{service, operation, target, params}`. Контроллер
разрешает здесь только ALLOW read, не выполняет мутаций для проверки установки.
Без probes подтверждается готовность wiring/credential, не upstream permissions.

Контроллер поддерживает текущий native-v1 review record и собственные следующие
records. Он сохраняет owner identity, native state и прежний контейнер, а Production
проверяет неизменным. Config/image/Repo-client preflight выполняются **до stop**.
После clone новый контейнер staged: мутации и owner POST закрыты до проверки
каталога/probes и owner-only активации. После активации автоматический возврат
запрещён: новый state уже может содержать эффекты. До неё при ошибке сохраняются
артефакты и возвращается прежний контейнер. `-AttemptRecord <path>` продолжает
Created/Staged; `-Action Return` использует последний незавершённый record.
Не запускать второй контроллер параллельно. Точные records закрыты Windows ACL;
контроллер не удаляет старые контейнеры/volumes и не запускает Production cutover.

## Клиент

Из Repo используется один `fortis_approvals.extensions.client.default_client()`
(review endpoint по умолчанию): `catalog()`, `call(service, operation, target,
params, reason=…, request_id=…)`, `result(request_id, reconcile=False)`.
Закрытые machine routes — `/v1/integrations/catalog`, `/call`, `/result` под тем же
префиксом. Pending HTTP 202 поддерживается. UUID сохраняется для точного retry;
изменённый запрос с прежним UUID конфликтует. Новое чтение требует нового UUID,
так как replay возвращает сохранённый результат, а не свежие данные.
Каталог показывает effective policy, scope и readiness без значения токена.
