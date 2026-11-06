# Дальнейшие работы: Gateway и Mirror

План согласован 2026-11-06 после завершения native Git/worktree live цикла.
Текущее внедрение описано в [current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).
Перечень ниже фиксирует будущие задачи; эта документационная работа их не реализует.
Общий Fortis backlog находится в [Fortis Container](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/FUTURE-IMPROVEMENTS.md);
здесь ведутся детали этого этапа без второй копии общего backlog.

## Следующие задачи

| Порядок | Задача | Что должно получиться |
| --- | --- | --- |
| 1 | Sonar operations: source candidate реализован; live acceptance впереди | Сопоставить реальную работу с issues/analysis/quality gate с доступными API и текущими контрактами; решить, что оставить/изменить/добавить, определить ALLOW/ASK/DENY и scope. Отдельно разобрать branch/PR/analysis/SHA binding; нынешний default-branch `OK` этого не доказывает |
| 2 | Оценка получившегося GitHub workflow | Разобрать путь worktree → commit/push → PR/CI → ready/merge → main/cleanup: лишние шаги, число подтверждений, ожидание worker, resume/reconcile, ограничения bundles и нужные чтения. Сохранить согласованный обычный task push ALLOW; обосновать изменения остальных политик до реализации |
| 3 | Обратная связь Owner Portal после Approve/Reject | Сразу показать принятие решения и обработку, исключить повторное нажатие, затем показать результат или ошибку. Различать owner decision, ожидание worker и завершение эффекта; не убирать запрос как успешный до подтверждения исполнения. Проверить оба решения и медленные/ошибочные ответы |
| 4 | Проверка корректности кода, затем необходимый рефакторинг | Проверить контракт/политики/scope, гонки состояний, idempotency, SHA/CI/receipt binding, обработку сбоев и границы credential. Убрать найденное дублирование и лишнюю сложность; рефакторить по результатам, с проверками поведения |
| 5 | Доработка Mirror как API для AI из контейнера | В репозитории `docke-windows-mirror` выделить типизированный API состояния Windows зеркал и использовать его из GUI/AI. Определить аутентификацию, разрешённые repo, свежесть и unknown/error состояния. Сначала наблюдение; изменения Windows — отдельные операции с собственными разрешениями |
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
- Production release/rollback, перенос принятого review и общая миграция
  репозиториев с последующим закрытием legacy helper/PAT — отдельные задачи.
- Более широкие multi-agent identities, scheduler, RDG writer enforcement,
  supply-chain review и backup/rotation — в общем Fortis backlog.

Матрица текущих разрешений живёт только в [native contract](NATIVE-WORKTREE-GATEWAY-2026-11-06.md).
Mirror владеет общим [workflow](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/WORKFLOW.md);
здесь не создаётся новая система Windows-команд и не меняется его source.

## Повторяемое подключение операций

Общий source mechanism ALLOW/ASK + именованные Gateway credentials описан в
[extension contract](INTEGRATION-EXTENSIONS.md). Он подготовлен отдельно от
Sonar/CI activation. Осталось принять owner controller на реальном Windows/Docker,
затем подтвердить конкретный provider. Результаты проверок ведутся только в его
[evidence](../fortis_approvals/evidence/EXTENSIONS-OFFLINE-20261106.md).
