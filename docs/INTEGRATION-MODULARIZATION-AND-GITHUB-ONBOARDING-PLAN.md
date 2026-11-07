# GitHub onboarding — завершённые этапы

Исторический результат 2026-11-06: поэтапный план выполнен в изолированном
review, а переключение Primary тогда ещё было отдельной задачей. С 2026-11-07
оно [завершено владельцем](../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md),
Legacy остановлен. Текущие операции и политики
описаны только в [native contract](NATIVE-WORKTREE-GATEWAY-2026-11-06.md),
дальнейшая работа — в [follow-up plan](FOLLOW-UP-PLAN.md).

## Принятые результаты

| Этап | Результат | Evidence |
| --- | --- | --- |
| Modularization | Sonar/GitHub provider packages, общий Core/portal/ingress, сохранённые compatibility imports | [Review preflight](../fortis_approvals/evidence/FORTIS-REVIEW-PREFLIGHT-20261105.md) |
| M1 | Gateway READ → ASK/Reject без создания ветки → ASK/WebAuthn Approve → create_branch/readback/replay | [M1](../fortis_approvals/evidence/FORTIS-GITHUB-PILOT-M1-20261106.md) |
| M2 | Bounded `push_files` → draft PR №8, receipts/replay и Sonar GET | [M2](../fortis_approvals/evidence/FORTIS-GITHUB-PILOT-M2-20261106.md) |
| M3 | Source CI PR №8: exact head `a2cb4a59bf2251cc05301a9da17e3a9fd02a19ee`, run `42101319273`, completed/success прочитан через Gateway; marker `FORTIS_GITHUB_CI_READ_LIVE_PASS` | [Native live baseline](../fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md) |
| Native source | Настоящий push source commit, PR №10, CI, draft → ready, merge и Docker main | [Native live evidence](../fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md) |
| Native new task | create/edit/check/stage/commit, два push, PR №11/CI/merge, main fast-forward и cleanup | То же live evidence |

`push_files` создавал новый коммит из текста через GitHub API. В основном
native workflow его заменил `push_commits`, переносящий существующие Git-объекты
и SHA из worktree. `create_branch` через API больше не требуется для этого пути:
локальная ветка создаётся с worktree, удалённая — первым push. Старые методы не
удалены, но в native profile не допущены.

## Границы принятия

Native live проверка использовала исключительно запросы Repo → Gateway,
без GitHub-коннектора и старого credential helper. Отдельный GitHub provider
credential остаётся в Gateway. Это не означает удаления legacy Repo PAT,
разрешения всех репозиториев или обновления Windows main.

Не повторять M1–M3 provisioning/owner enrollment и принятые сценарии без изменения
существенного входа. Сохранить retained M3 и bootstrap source worktree до
отдельного изменения owner-run record. [Deployment references](../fortis_approvals/deploy/README.md).

Дальнейший глубокий разбор Sonar операций, оптимальности GitHub workflow, UI,
кода и Mirror выделен в [отдельный план](FOLLOW-UP-PLAN.md). Прежние next-step
предложения о расширении `push_files` и ожидании native acceptance заменены
фактически принятым native контрактом.
