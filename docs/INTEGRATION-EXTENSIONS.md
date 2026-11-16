# Подключение операций через Gateway

Нормативный контракт общего механизма для **новых providers**. Он не заменяет
native Git или существующие Sonar/GitHub контракты. Статус внедрения — в
[current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md), результаты проверок —
в [evidence](../fortis_approvals/evidence/EXTENSIONS-OFFLINE-20261106.md).

Для **собственных** Windows/Docker API обязательная специализация —
[UC-GW-012](use-cases/own-api.md#uc-gw-012): выбор WIN-HTTPS/DOCKER-HTTPS,
границы upstream owner/TLS/credential, независимое восстановление,
[offline manifest и handoff](templates/own-api/README.md). Не заменяет
следующий общий порядок и не означает live activation.

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

Для нового чата сначала `/workspace/repo/README.md` → общий реестр (обзор ID,
обязательное чтение UC-CONT-002/003); затем этот контракт → README нужного
provider → current state → последнее evidence. Будущие задачи — в follow-up plan.

## Подходит ли мой API

Для **собственных** Windows/Docker API профиль и приёмка UC-GW-012 обязательны.
Описанная ниже возможность отдельного trusted transport не разрешает
активировать исторический HTTP/non-443 provider в обход этого профиля.
Штатные manifest/Doctor/one-shot READ инструменты перечислены в
[UC-GW-012](use-cases/own-api.md#что-переиспользовать-при-каждом-подключении)
и [TOOLS](templates/own-api/TOOLS.md). Они не устанавливают listener,
сертификаты или Docker network и не заменяют owner release.

Штатный `JSONAPI` покрывает HTTPS на порту 443 с системным доверием TLS,
фиксированные GET/POST/PUT/PATCH/DELETE маршруты, JSON body/ответ и Bearer либо
API-key header. Без токена тоже можно. AI реализует небольшой provider и закрытые
schemas; после подключения используется общий клиент, отдельный клиент на каждый
сервис писать не требуется. Это не подключение произвольного URL одним вызовом.

HTTP, нестандартный порт, собственный CA/mTLS, OAuth refresh, подпись запросов,
webhooks/streaming, файлы и пустой `204` response требуют отдельного trusted
transport/протокола и его проверок. До его реализации не объявлять API готовым.
Имена `Route.query_keys` сейчас соответствуют `[a-z][a-z0-9_]*`; API с другими
именами query-параметров требует адаптации transport. Пределы штатного transport:
request body 256 KiB, response по умолчанию 256 KiB
(настраивается trusted source до 1 MiB), JSON обязателен и для успешного ответа.
Наличие scaffold/token/catalog не заменяет первый live acceptance provider.

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
остаются отдельными; их [ротация GitHub/Sonar](CREDENTIAL-ROTATION.md) использует
тот же controller с `-Service`, а не credential alias. Новый токен не требует нового mount на каждое подключение.

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

Контроллер поддерживает исторический native-v1 review record и собственные
следующие records, включая защищённый Primary pointer после Promote. Он
сохраняет owner identity, native state и предыдущий контейнер; Legacy проверяет
по защищённой сохранённой идентичности, а не требует его повторного запуска.
Текущее состояние — в [Primary live evidence](../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md). Config/image/Repo-client preflight и round-trip публичного env-файла через Docker
выполняются **до stop**.
После clone новый контейнер staged: мутации и owner POST закрыты до проверки
каталога/probes и owner-only активации. После активации автоматический возврат
запрещён: новый state уже может содержать эффекты. До неё при ошибке сохраняются
артефакты и возвращается прежний контейнер. `-AttemptRecord <path>` продолжает
Created/Staged; `-Action Return` использует последний незавершённый record.
Не запускать второй контроллер параллельно. Точные records закрыты Windows ACL;
контроллер не удаляет старые контейнеры/volumes; `Apply` сам по себе не
назначает новое постоянное имя — после активации для этого служат отдельные
`Backup`/`Promote`. Это не инструкция повторить уже завершённый cutover.

## Клиент

Из Repo используется один `fortis_approvals.extensions.client.default_client()`
(Primary endpoint `19204` по умолчанию): `catalog()`, `call(service, operation, target,
params, reason=…, request_id=…)`, `result(request_id, reconcile=False)`.
Закрытые machine routes — `/v1/integrations/catalog`, `/call`, `/result` под тем же
префиксом. Pending HTTP 202 поддерживается. UUID сохраняется для точного retry;
изменённый запрос с прежним UUID конфликтует. Новое чтение требует нового UUID,
так как replay возвращает сохранённый результат, а не свежие данные.

Пример после реализации `tickets/read_item` и owner activation:

```python
import uuid
from fortis_approvals.extensions.client import default_client

client = default_client()
request_id = str(uuid.uuid4())  # Сохранить вместе с параметрами до отправки write.
result = client.call('tickets', 'read_item', 'record-123', {},
                     reason='Порученная проверка записи', request_id=request_id)
# При PENDING ждать Owner Portal; client.result(request_id) читает тот же intent.
```

ALLOW/ASK выбирает trusted config операции. Клиент не получает токен и не
назначает себе политику. Условный пример не означает, что tickets уже внедрён.

Каталог показывает effective policy, scope и readiness без значения токена.
