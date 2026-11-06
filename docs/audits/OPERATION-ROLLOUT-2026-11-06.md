# Разбор длительности добавления операций — 2026-11-06

Этот документ владеет разбором конкретного выпуска и оценкой времени.
[Общий процесс](../OPERATION-ONBOARDING-WORKFLOW.md) владеет дальнейшим workflow.
[Текущее состояние](../guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) и operation
contracts не заменяются этим разбором.

## Метод и границы измерения

Источники: commit timestamps из фактического Git, CI metadata через Gateway,
предоставленный владельцем build log и сообщения трёх запусков updater.
Время в таблице — Asia/Bangkok (UTC+7), 2026-11-06.

Это elapsed между наблюдаемыми событиями, а не учёт активных человеко-минут.
В интервалах присутствуют ожидание владельца, работа AI, IPC/network round trips,
прерывания связи и подготовка/публикация evidence. Начало исходного запроса,
длительность каждого локального теста и суммарное время ожидания не измерены.
Checkpoint PR12 не объявляется точным началом работы. Owner PASS случился после
последнего исправления и до коммита evidence; его точный timestamp отсутствует.

| Наблюдаемые границы | Время | Elapsed | Что известно |
| --- | --- | --- | --- |
| Checkpoint PR12 `7d50f5e` → feature commit `9ff4bc5` | 08:31:23 → 09:40:26 | 69 мин 03 с | Окно подготовки/реализации операций и проверок; чистое время кода отдельно неизвестно |
| Feature commit → PR13 merge `2f88d92` | 09:40:26 → 09:46:27 | 6 мин 01 с | Публикация, PR/approval, CI, merge вместе |
| PR13 merge → первый updater `0373038` | 09:46:27 → 10:44:56 | 58 мин 29 с | Build/handoff, smoke/inspect troubleshooting, создание нового updater; надёжного разбиения нет |
| Первый updater → native-state fix `0b72155` | 10:44:56 → 11:06:11 | 21 мин 15 с | Включает первый owner run/возврат, диагностику, исправление, тесты, docs и публикацию |
| Native-state fix → Repo-interpreter fix `143f944` | 11:06:11 → 11:25:27 | 19 мин 16 с | Включает второй owner run/возврат и следующий цикл исправления |
| Последний fix → success evidence `8349bb8` | 11:25:27 → 11:38:13 | 12 мин 46 с | Внутри этого окна успешный третий запуск и фиксация результата |

Итого от checkpoint до evidence — 3 ч 06 мин 50 с. После merge — 1 ч 51 мин
46 с, около 60% этого наблюдаемого окна. Два цикла исправления updater вместе —
40 мин 31 с. Эти величины перекрывают ожидания и не равны доказанному времени,
которое можно целиком сэкономить. До самого owner PASS после merge прошло
от 1 ч 39 мин до 1 ч 51 мин 46 с; evidence задаёт верхнюю границу.

Отдельные измерения, уже находящиеся внутри этих интервалов:

- OWNER-REPORTED build log: `[+] Building 4.6s (19/19) FINISHED`.
  Большинство базовых слоёв CACHED. Это Docker build, без всего Windows handoff,
  pull/archive/inspection. Для нового dependency/cold build эта цифра не SLA.
- LIVE-VERIFIED через Gateway: [Source CI run 42152076117](https://github.com/AlexPastukhh/fortis-approvals/actions/runs/42152076117),
  createdAt `02:43:00Z`, updatedAt `02:45:26Z`, completed/success, attempt 1,
  head `9ff4bc59f3bb8f963e9e379e054a4023e270896d`. Наблюдаемый lifecycle —
  2 мин 26 с, включая возможную очередь; это не отдельное CPU-время тестов.
- Вызовы Fortis Repo в доступной переписке обычно занимали порядка 8–12 с,
  иногда завершались init/network errors. Суммарного полного счётчика нет.
  Иллюстрация накладных расходов: 100 последовательных round trips такой
  длительности дали бы 13–20 мин. Это сценарная оценка, не измеренный итог;
  добавлять её к таблице нельзя — она находится внутри elapsed.

## Ошибки и последствия

| Ошибка | Конкретное наблюдение | Последствие | Изменение процесса |
| --- | --- | --- | --- |
| Граница релиза не была собрана заранее | Image установлен с `analysisProfileConfigured=false`, `newOperationsLiveVerified=false` | Пользовательский результат ещё не достигнут после сборки/обновления | До owner run готовы code, config/bindings, scopes, probes и activation plan; blockers показываются заранее |
| Смешали bootstrap и обычный release | Для добавления операций понадобились новый Windows updater, retained-state admission и упаковщик | Разовая платформенная работа оказалась в критическом пути feature | Общий release runner поддерживается отдельно; provider change передаёт ему проверенные данные |
| Неверная image smoke команда | `python -I` без `/opt/fortis` в sys.path | ModuleNotFoundError и ручной повтор | Один поддерживаемый image smoke из точного build context |
| Ошибка PowerShell JSON projection | Root array остался вложенным, summary смешал несколько containers | Лишний owner inspect и неоднозначные данные | Нормализация JSON на границе, проверка singleton/array, exact target admission |
| Устаревшая модель state | Legacy helper принимал marker и 4 DB, native runtime добавил `native-git` | Первый cutover остановлен, старый review возвращён | Версионированный state inventory включает Native Store/tasks/jobs/bundles; тест реальной структуры до owner run |
| Непроверенная команда Repo | В финальном probe использован `python`, в Repo есть `/usr/bin/python3` | Второй cutover откачен после запуска | Тот же client probe и проверка argv выполняются до stop; image и Repo interpreters разделены |
| Ошибки без этапа | Вывод `PILOT_PRIVATE_PROCESS_FAILED:127:` | Пришлось восстанавливать место отказа по коду | Step markers, persisted failureStep/failureMessage, времена этапов |
| Полноту тестов оценивали по числу | 30 checks не покрыли native state, затем 37 не покрыли Repo executable | Offline PASS создал избыточную уверенность в release readiness | Проверять точный путь эксплуатации и интерфейсы среды; число тестов не критерий готовности |
| Неоднозначный порядок в template | Checklist требовал live acceptance «before deployment» | Дефект инструкции; его отдельная цена по истории не измерена | Offline checks → ограниченный candidate deploy → live acceptance; не требовать нового API на старом runtime |
| Раздробленная оркестрация | Много отдельных reads/checks/публикаций и повторного контекста | Дополнительные RPC и owner handoffs | Пакетировать независимые reads/checks; один release bundle и один owner entrypoint |

Это ошибки подготовки AI и процесса выпуска. Windows-specific live-проверки
нужны, но обе ошибки updater были видны из Repo source/environment до передачи
команд владельцу. Ожидания approvals не объявляются главным источником задержки:
от feature commit до merge всего 6 минут. Причина UI latency после Approve не
установлена; отдельный HTTP 202 client fix не считается её доказательством.

## Объём задачи и результат

Feature diff `7d50f5e..9ff4bc5`: 33 файла, +2431/-42 строки. Каталоги содержат
31 новую Gateway operation: Sonar 14 reads + 6 actions, GitHub 7 reads + 4
CI controls. Дополнительно появились report composition, manifest helper,
shared validation, config и response/approval guards. Это существенный объём,
его следует явно ограничивать первым работающим вертикальным срезом.
Строки и число файлов не являются единицами времени или качества.

Updater diff `2f88d92..143f944`: 13 файлов, +992/-20 строк вместе с tests/docs/
manifest changes. Время ушло на создание части release-платформы и её исправление
в ходе пользовательской задачи. Переносить всю эту стоимость на каждое новое
подключение нельзя.

[Evidence v3](https://github.com/AlexPastukhh/fortis-approvals/blob/8349bb8d7937381c6de2206798d72732b821075e/fortis_approvals/evidence/FORTIS-REVIEW-UPDATER-OFFLINE-20261106.md)
фиксирует image update PASS и сохранение прежнего review/Production baseline.
Новые операции остались выключены; полный end-to-end срок их активации ещё
не измерен. Поэтому этот разбор не называет 3 часа сроком завершённой интеграции.

## Что окупается первым

1. Подготовленный code + public config + scopes + probes до owner run; один
   понятный список реальных blockers вместо отложенной конфигурации.
2. Один постоянный release runner: preflight перед stop, state inventory,
   безопасный startup return, durable record/resume и feature-specific probes.
3. Указатель для новых чатов и короткая change card; классификация client-only /
   config-only / code / credentials / state migration до начала изменений.
4. Проверка согласованности contract/adapter/grant/policy/client/image packaging
   и безопасный runtime capability report. Это планируемая автоматизация,
   а не уже доступные новые команды.
5. Замеры stage durations: активное исполнение, ожидание owner, provider/CI и
   повторные попытки отдельно. Без них точный процент потерь установить нельзя.

## Повторная проверка вывода и workflow

Арифметика повторно проверена по тем же Git objects: elapsed 11210 s,
post-merge 6706 s (59.82%), два fix cycles 2431 s. Build log повторно связан с
тегом `analysis-review-2f88d920` и image `515ad033...`; cached build 4.6 s относится
к этому образу. Оценку «40 минут можно целиком убрать» эти данные не доказывают:
необходимая разработка/проверки и ожидания внутри интервалов не разделены.

Проверка текущего кода выявила дополнительные ограничения:

| Наблюдение | Подтверждение | Вывод |
| --- | --- | --- |
| Общий profile связывает независимые возможности | `AnalysisReviewConfig` требует непустые GitHub workflow bindings, `install` создаёт GitHub adapter и вместе включает Sonar/GitHub reads | Соответствует нынешнему контракту, но мешает Sonar-only activation. Нужна независимая capability config; одних поправок updater недостаточно |
| Policy/grant не всегда config-only | Policies/grants задаются Python composition; supported config имеет закрытые поля | No-image путь применим только к уже поддержанным config knobs. Новые настройки/смена hardcoded policy требуют source/image changes |
| Новый provider не подключается одной папкой | Shared `OPERATIONS/READ_OPERATIONS`, validators, submit/result projection явно знают Sonar/GitHub; registration GitHub отдельная | Обязателен полный wiring check; adapter и copied template сами не дают новый API |
| ASK read требует result delivery | `RepoIntentBroker._public_result` отдаёт ID/state; native result разрешён только workspace/github | Approval reuse возможно, но новый service нуждается в actor-bound bounded result contract; raw Core результат не выдаётся |
| Provider tests не собираются автоматически из любой новой папки | `scripts/test-source.sh` явно discover GitHub и Sonar tests; Source CI вызывает этот script | Новый provider должен попасть в test collection и packaging, иначе зелёный CI неполон |
| Новые чаты main ещё не получают эти entrypoints | `git merge-base --is-ancestor` для `00d42b7` и runtime-doc commit `8349bb8` в main вернул false | Workflow/docs пока proposal в task-ветках; review/merge и согласованность current-state docs — часть внедрения |

Offline без provider calls: конструктор `AnalysisReviewConfig` отклонил как
пустой bindings, так и Sonar project с пустым workflows при отключённых CI
controls/mutations. `validate_intent` для незарегистрированного offline service
вернул `REPO_OPERATION_NOT_SUPPORTED`. Runtime/config/grants не менялись.

Workflow исправлен по контрпримерам: client-only и source-only не требуют
Gateway deployment, deny-only проверяет запреты, mutation-only не вынуждает
добавлять read permissions, ASK-read требует безопасного получения результата.
Accepted response и завершённый внешний эффект различаются. Карточка облегчена:
обязателен короткий delta/target/result, остальные поля условны и переиспользуют
принятые provider/owner records. Это проверка проекта процесса и кода отдельных
точек; новый сторонний provider end-to-end здесь не внедрялся.
