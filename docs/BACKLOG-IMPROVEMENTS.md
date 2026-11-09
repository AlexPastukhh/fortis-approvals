# Backlog улучшений — Fortis Approvals Gateway

План согласован 2026-11-06 после завершения native Git/worktree live цикла.
Текущее внедрение описано в [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).
Перечень ниже фиксирует будущие задачи; эта документационная работа их не реализует.
Общий Fortis backlog принадлежит `fortis-container`; вход — через
реестр юзкейсов в `/workspace/repo/README.md`. Наличие GitHub remote в этом repo
не означает допуск к нему действующего Gateway (UC-CONT-018).
Это **единственный backlog этого репозитория**. Пункты здесь не разрешают менять Production. Общее Docker, Tunnel, Windows/Mirror и multi-agent направление принадлежат своим репозиториям; здесь только Gateway-specific задачи. Принятый результат и техническая история остаются в датированных evidence и source runbooks.

## Осиротевший native worker claim — отдельная задача 2026-11-09

После PR #37 live Windows preflight обнаружил шесть `UNCERTAIN`
(четыре исторических плюс `workspace.create_task` и `workspace.commit`
для `feed_and_search_and_bank_and_brain`), один worker job
`CLAIMED` (`2df32a24-efb1-4dac-97f6-3b66147d8944`).
Docker Repo worker journal не содержит UUID этого `create_task`,
но отсутствие записи НЕ подтверждает отсутствие локального эффекта.
Вторая заявка `ee9c5e73-5d5a-4ea1-8133-d79d59511f32` —
worker journal `FAILED/UNCERTAIN`.

Owner-reviewed `-PreserveClaimedJobs` и `-ConfirmWorkerQuiescent`
в новом source-кандидате позволяют *побайтово сохранить*
единственную явно названную связанную запись `CLAIMED`
при image release — только с точным SHA и списком UNCERTAIN,
без исполнения, повторного запуска или подмены статуса.
`QUEUED`, другие операции, активные approvals и новые UUID
по-прежнему запрещены. Quiescence пока только owner-attested:
внешнего worker-процесса helper сам не контролирует.

Обязательный следующий этап: отдельный Owner Portal workflow
для разбора зависшего `CLAIMED` с точным локальным journal
и Git-worktree evidence, машинной проверкой отсутствия
исполнения и подтверждённой backup, WebAuthn и неизменным
аудитом. Сейчас `owner_close_uncertain` намеренно требует
worker `FAILED`: перенос не заменяет terminalization.
Не выполнять UPDATE SQLite или подделывать receipt для удобства.

## Новый цикл UNCERTAIN и Owner Portal UX — SOURCE CANDIDATE, 2026-11-09

Во время владельческого `Manage-Integrations.ps1 -Action Apply` для CI image
обнаружены четыре новые блокирующие `UNCERTAIN`:
`18af495b-f84c-4fd3-b613-ebd5fdfa0165` и
`35ac68df-8be5-4dae-bf20-11f75555eecc`
(оба `github.push_commits rd-graphs`),
`31e8f60b-f396-4e5f-8a46-7772faf95fa4`
(`workspace.commit meat-proxy-track`) и
`7b2ea090-4408-4d9c-b1b6-be5a97eb7b36` (`workspace.fetch rd-graphs`).
Все четыре возвращают `REMOTE_OUTCOME_UNCONFIRMED`, то есть отсутствие
достоверного подтверждения, а НЕ доказательство провала или успеха.
Работающий Primary не менялся.

Новый source-кандидат оформлен отдельным `fortis_approvals/incidents.py`,
переиспользует Core/OwnerWebAuthn/OwnerShellPortal через наследование;
immutable storage source hashes остаются неизменными
(`scripts/check-release-storage-source.py` → PASS).

Новый source-кандидат:
- Owner Portal: отдельный список `Требуют разбора` для `APPROVED`,
  `DISPATCHED` и `UNCERTAIN`; точный readback и отдельная безопасная
  `receipt`-сверка, не запускающая GitHub/worker effect заново.
- `UNCERTAIN → CLOSED_UNCONFIRMED` только по отдельному решению владельца
  с WebAuthn, после оператора проверенной холодной backup, ввода её точного
  имени и объяснения; без `EXECUTED`, без удаления UUID и аудита, без
  возможности повторно исполнить тот же ID. Если durable receipt есть —
  только `reconcile`; если worker job не `FAILED` — отказ от закрытия.
  Owner Portal принимает имя backup как **заявление владельца**, но
  **не проверяет backup volume автоматически**.
- Approve/Reject до длинного preview, sticky на маленьком экране;
  мгновенная блокировка кнопок при клике, понятный прогресс, отдельные
  состояния owner decision / worker completion и readback после ошибок.
- Точный владельческий параметр `-PreserveUncertainRequests` в Windows
  release controller: при первой миграции UUID должны совпасть с
  множеством реально незавершённых UNCERTAIN в источнике; сохраняется
  неизменная копия всей базы, audit и receipts. Дальнейшие `Backup` и
  `Promote` допускают только **подмножество** ранее зафиксированных
  UUID после закрытий, но не новые `UNCERTAIN` без нового явного
  разрешения владельца. При новом инциденте нужен новый точный список
  с `-Build -SourceSha` и повторная проверка текущих UNCERTAIN.
  Все `PENDING`, `APPROVED` и `DISPATCHED` по-прежнему запрещены.

**Ещё не LIVE:** принятие PR, зелёный CI для точного SHA, Windows guarded
pull, owner-approved image release, Backup/Promote и живые браузерные
WebAuthn/UX проверки необходимы отдельно. Старый установленный
контроллер не знает `-PreserveUncertainRequests`.

Backlog далее: по каждому из 4 UUID проверить upstream/worker receipt,
фактический SHA/коммит и audit attribution; локализовать причины worker
timeout/failed acknowledgement, сделать полноформатный incident evidence
чеклист по `push_commits`/`commit`/`fetch`, добавить **независимую**
проверку backup provenance перед owner-close (в source сейчас лишь
owner-attested name), live browser validation длинных заявок и offline
recovery/rollback. Исходящие эффекты неизвестны и после перехода
`CLOSED_UNCONFIRMED`, их нельзя считать исполненными.

## Owner Portal PowerShell — source candidate (2026-11-08)

- Вкладка PowerShell с однократным исполнением вставленного скрипта через отдельный
  mTLS Windows Executor реализована в исходниках, но ещё **не развёрнута**.
  Ручная активация Windows worker, сертификаты, отдельный low-privilege Windows
  identity, сетевые правила, Gateway release/CI и Windows acceptance — отдельно.
- Кнопки Analyzer и «Мнение ИИ» пока отключены. Универсальный Analyzer для
  скриптов и других заявок должен быть отдельным этапом, не путать с существующим
  Sonar/GitHub `analysis_review`. Нет обещания безопасного выполнения произвольного
  PowerShell: команды от владельца сейчас не сканируются.
- Источник/API границы и эксплуатация: [OWNER-POWERSHELL](OWNER-POWERSHELL.md).

## Новый приоритет: UNCERTAIN / отказавшаяся локальная операция (2026-11-07)

- Разобрать заявку `5f8db475-c503-4a32-8d5f-118f32370f1c` (`workspace.stage` в `fortis-approvals`, task `local-use-case-registry-20261107`). Core стал `UNCERTAIN`, Gateway job `FAILED / UNCERTAIN`, worker receipt был `NULL`; однократный read-only `reconcile` не смог подтвердить результат. Позднее worktree имел чистый Git HEAD, но это **не доказывает** исходный stage effect.
- Повторное наблюдение 2026-11-07 при аудите документации: `workspace.create_task`
  для `tunnel`, task `docs-dry-audit-20261107`, request
  `b32222b5-4a84-4816-bd39-625ab6c9995d` вернул
  `UNCERTAIN / REMOTE_OUTCOME_UNCONFIRMED`. Read-only reconcile не изменил статус;
  соответствующие worktree и ветка не найдены. 2026-11-08 этот UUID вместе со
  старыми Tab Notifier `inspect`/`commit` и Mirror `sync_task` разово retired
  после отдельного owner approval, verified cold copy и проверки отсутствия
  активного исполнения. Native tombstones сохранены; подробности завершения и
  protected record — в [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).
  Первопричина не установлена: сохранить этот случай для расследования, а не
  повторять исходный запрос или считать его успешно исполненным.
- Исследовать точную первопричину с безопасными снимками ошибок: worker journaling между `DISPATCHED` / `git add` / receipt, исключения после частичного эффекта, timeout, stale precondition, отсутствие error detail. Не полагаться на `job.result IS NOT NULL`: это может быть JSON-строка `null`, не receipt.
- Сделать `UNCERTAIN` и `DISPATCHED` видимыми в Owner Portal **отдельно от очереди на подтверждение**: список «Требуют разбора», request ID, service/operation, worker/receipt status и ограничения. `History` и пустой `Pending` не должны маскировать блокирующее состояние.
- Разработать **штатное owner-authorized завершение без подтверждённого эффекта**, с привязкой к точному UUID, проверкой нет повторного исполнения, проверенным backup/evidence, терминальным статусом вроде `CLOSED_UNCONFIRMED`, неизменяемым событием и защитой от повторного replay. Не использовать фиктивное `EXECUTED` и не превращать исторический `UNCERTAIN` в `REJECTED/REVOKED` без определения семантики. Реализовать позитивные/отрицательные/конкурентные тесты и UI acceptance.
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

- Подготовить единый Windows PowerShell 5.1 operator entrypoint: `SelfTest → Check/Build exact SHA → Apply → live READ/Owner Portal → Backup → Promote → readback`, с учётом фазы protected release, кратких PASS-маркеров и остановки без повторного Apply при ambiguity.
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


## GitHub Actions в обычном профиле — ожидает релиза и live-приёмки

Source-кандидат 2026-11-09 переносит семь GitHub READ и четыре CI-control
операции из optional analysis-review в native профиль, без SonarCloud binding.
CI-control выключен по умолчанию и при opt-in остаётся ASK.
До нового образа и owner-managed релиза — SOURCE CANDIDATE, не LIVE VERIFIED.
После merge проверить PowerShell 5.1 parser, SelfTest, точный image/record,
Backup/Promote. На настоящем `rd-graphs` run `42542630753` проверить
jobs/logs и SHA, а также запрет чужого репозитория. Успешный Actions READ
не доказывает доступ GitHub Checks текущим токеном.

## Следующие задачи

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

- Довести подготовленное исправление `WorkflowClient.result` для HTTP 202 и
  его регрессионный тест из `task/native-client-pending-status-20261106` до
  проверенного source commit/PR. При сверке документации это локальные изменения,
  не часть `main`; новый Gateway image для изменения только Repo client не требуется.
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
