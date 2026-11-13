# Собственный API Fortis → типизированный Gateway READ

<a id="uc-gw-012"></a>

## UC-GW-012 — Подключить собственный Windows/Docker API к Gateway

**Когда:** сервис Fortis уже имеет или получает отдельный HTTP API, а ИИ
должен обращаться к нему исключительно через единый typed Gateway.
Это специализация [UC-GW-002](integrations.md#uc-gw-002), **не**
новый механизм Core approvals, не внешний generic proxy и не схема
«новый AI клиент → Gateway» из UC-CONT-008.

**Цель:** один повторяемый процесс для Windows и Docker upstream, с
закрытыми операциями, владельцами доверия, отдельным least-privileged
credential, отрицательными тестами и подтверждённым реальным READ.
Source/tests/CI, owner release и живой результат — разные уровни доказательств.

**Как:** последовательно выбрать проверенный upstream transport, описать
только публичные источники и READ scopes, проверить source негативными
тестами, затем отдельно принять owner release и живой typed API.

### Выбрать профиль и зафиксировать владельцев

| Обязательная граница | WIN-HTTPS | DOCKER-HTTPS |
| --- | --- | --- |
| Owner upstream | Windows listener, installed owner startup/cert/key и права | Отдельный owner Docker image, Compose/network/source/volume |
| Gateway → upstream | Точный https://host.docker.internal:443 с cert SAN DNS:host.docker.internal; владелец доказывает host bind/port | Точный https://<reviewed-service-dns>:443 на проверенной общей Docker network; не Docker loopback |
| Trust и identity | Public CA в фиксированном защищённом Gateway read-only mount; отдельный Bearer | То же, плюс независимые Docker network/volume/rollback доказательства |
| Negatives | HTTP, redirect, wrong CA/SAN/Host, отсутствующий/неверный bearer, POST, неразрешённый repo | Те же, плюс чужая Docker network, неправильная identity/permissions |
| Источник факта | Owner Windows listener + TLS readback от имени Gateway | Owner контейнера + HTTPS из настоящего Gateway namespace |

Пример WIN: [Mirror Gateway GET](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/GATEWAY-READ-ONLY.md),
[Gateway Mirror provider](../../fortis_approvals/integrations/mirror/extension.py),
[Mirror TLS](../../fortis_approvals/integrations/mirror/tls.py).
Пример будущего DOCKER API: [Observatory](../../fortis_approvals/integrations/observatory/README.md);
его исторический HTTP/18756 **не является** допущенным HTTPS/443 транспортом.
Не выдавать неустановленный TLS и ненастроенный Docker network за проверенный.

### Обязательный порядок

1. **Owner upstream:** определить canonical repo, API source SHA, installed
   listener/image, разрешённые ресурсы, версию response и владельца rollback.
   Изолировать upstream owner release и Gateway release; изменение одного
   не означает принятие другого. Owner Shell/PowerShell Executor — отдельный
   привилегированный API; нельзя подключать его как обычный ALLOW provider.
2. **Public source-only manifest:** в registered task worktree заполнить
   [шаблоны](../templates/own-api/README.md). Выполнить
   `python3 -B scripts/check-own-api-manifest.py --manifest <absolute-file>`.
   Он проверяет WIN-HTTPS/DOCKER-HTTPS, фиксированный HTTPS/443 origin,
   совпадение cert name, private CA *path*, vault *alias*, точный GET,
   targets, отсутствие wildcard/WRITE, строгие JSON поля и size limits.
   Он **не** проверяет реальные сертификаты, права, Docker/Windows сеть,
   source/git/permissions или работающий Gateway.
3. **Closed provider:** выполнить [UC-GW-002](integrations.md#uc-gw-002)
   и [extension contract](../INTEGRATION-EXTENSIONS.md): фиксировать URL,
   GET route и URI template в trusted code, закрытые request/result schema,
   actor/targets в доверенной конфигурации, проекцию без внутренних полей.
   Клиент не передаёт произвольные URL, headers, bearer, путь файла, policy.
   Вызов из Repo — только `fortis_approvals.extensions.client.default_client()`.
4. **Transport/CA/credential отдельно:** owner устанавливает upstream
   HTTPS listener/service, подтверждает сертификат SAN/hostname и pinned CA
   с **самого Gateway network path**, запрещает redirect/proxy/HTTP fallback,
   проверяет Host и bearer. Отдельный scoped principal на конкретный API,
   только его alias в существующем credential vault. Применить
   [UC-GW-004](credential-lifecycle.md#uc-gw-004); проверить root/mount,
   consumer/Owner Shell и восстановимость vault, не создавать новый vault
   controller и не размещать токен в Git/chat/argv/env.
5. **Source/negatives:** unit provider/transport/gateway/credential
   regression на правильный READ, wrong actor/target, path/query/suffix,
   wrong/no bearer, wrong CA/SAN, redirect, non-GET/POST, большие/malformed
   JSON и timeout. READ не наследует WRITE. Для нового effect/ASK требуется
   отдельный [UC-GW-003](integrations.md#uc-gw-003), upstream lookup,
   owner preview/receipt и `UNCERTAIN` без повтора; лентер V1 READ-only
   умышленно блокирует POST/ASK/WRITE.
6. **Review/merge и owner release:** через
   [UC-CONT-002](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-002)
   / [UC-CONT-003](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-003)
   доставить task → PR → точные Source CI/Release Impact → owner merge →
   clean Docker main. Перед любым Gateway production выпуском сверить
   [UC-GW-009](incidents.md#uc-gw-009) (все `UNCERTAIN`,
   `APPROVED`, worker `CLAIMED`), owner quiescence, TLS grants,
   upstream, public config/probes, vault, exact старый image и
   [UC-CONT-022](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/docker.md#uc-cont-022)
   isolated restore. Если владелец сознательно принимает отсутствие
   isolated restore для конкретного Gateway с отсутствующим image, пользоваться
   только отдельным [UC-GW-013](recovery.md#uc-gw-013--аварийный-image-release-при-отсутствии-прежнего-image),
   а не ослаблять release guard или считать аварийную копию tested restore.
   Никаких concurrent build/release нескольких чатов:
   один владелец, один agreed window, один accepted merged SHA.
   Штатный [UC-GW-005](releases.md#uc-gw-005) и
   [Primary runbook](../PRIMARY-GATEWAY-OPERATIONS.md) владеют
   Check/Apply/Backup/Promote; в случае незавершённого эффекта
   [UC-GW-006](recovery.md#uc-gw-006), исходный attempt ID, STOP.
7. **Live acceptance:** независимо прочитать host running/healthy,
   protected current image/config, owner shell/native GitHub/Sonar;
   `client.catalog()` должен показывать exact service/operation,
   effective ALLOW/actor/targets. `client.call(..., request_id=UUID)`
   выполняет реальный fresh READ через Gateway TLS → проверенный upstream.
   Проверить тип результата и его смысл, wrong target/actor/verb, один
   UUID/result без повторной мутации, отсутствие утечек; затем отдельные
   штатные Backup/Promote и актуальные receipts. При отсутствии живого
   каталога `IMAGE_ACTIVATED` и `LIVE_API_VERIFIED` не заявлять.
8. **Handoff:** заполнить [evidence](../templates/own-api/evidence.template.md)
   и [handoff](../templates/own-api/handoff.template.md), отметить точный
   source/host/actor/credential-alias/probe, ошибки и STOP. Следующий чат
   начинает с этого UC, owner сервиса и actual Gateway status, не с прошлой
   положительной фикстуры.

Автоматизация source-only Doctor и явного typed READ acceptance: [тонкие инструменты](../templates/own-api/TOOLS.md). Это не новый release controller или host listener.

### Второй независимый контрольный пример

[Манифест Mirror WIN-HTTPS](../templates/own-api/mirror-read.example.json)
и [учебный metricsprobe DOCKER-HTTPS](../templates/own-api/second-api-docker.fixture.json)
проходят один и тот же **offline** лентер. Второй сервис вымышленный,
`sourceSha=null`, никакой Docker network, сертификат, токен или живой
backend **не созданы**. Он проверяет, что reusable процесс описывает
другой транспорт, отдельного owner и ограничения, не переиспользует
Mirror bearer и не предполагает live сервис. В
[тестах](../../fortis_approvals/tests/test_own_api_onboarding.py)
проверяются fail-closed ошибки схемы/транспорта/политики. Перенос реального
Observatory допускается только после его отдельной HTTPS/permissions/recovery
приёмки; HTTP/18756 нельзя молча принять за DOCKER-HTTPS.

### STOP и статус завершения

**Готово:** source-часть завершена после принятого UC/шаблонов/тестов и
независимого учебного переноса. Живое подключение конкретного API —
только после owner evidence о TLS, vault, protected release, реальном
Gateway READ и отрицательных проверках; до этого статус не LIVE.

STOP при недостающем старом Gateway image, непроверенном restore,
конкурирующем Apply, открытом Core/worker effect без сохранения, неверной
TLS цепочке, неизвестном upstream credential scope, wildcard target,
любом POST/Owner Shell proxy или неподтверждённом host→Gateway READ.

Граница стадий:
`SOURCE_MANIFEST_VALID` (только структура) →
`SOURCE_READY` (code/negatives) →
`PR_MERGED` (owner/CI) →
`IMAGE_ACTIVATED` (protected runtime) →
`LIVE_API_VERIFIED` (fresh typed READ и отрицательные проверки).
Для Mirror финальный marker — `MIRROR_LIVE_READ_VERIFIED`; для
универсальной процедуры — `OWN_API_ONBOARDING_REPRODUCIBLE_VERIFIED`
**только после** положительного независимого второго tabletop и owner
review полного шаблона. Не считать локальный lint или source CI
доказательством этих последних стадий.
