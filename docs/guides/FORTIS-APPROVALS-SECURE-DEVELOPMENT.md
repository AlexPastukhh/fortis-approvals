# Fortis Approvals Gateway — текущее состояние

Актуализировано 2026-11-06 по исходникам, owner output запуска и результатам
запросов Repo → Gateway. Этот документ владеет текущим статусом;
[agent guide](../GATEWAY-AGENT-GUIDE.md) — правилами использования,
[native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md) — матрицей операций,
[отдельный план](../FOLLOW-UP-PLAN.md) — будущими задачами.

## Развёрнутые контуры

| Контур | Endpoints | Подтверждённое состояние |
| --- | --- | --- |
| Production `fortis-approvals-gateway` | Owner `http://localhost:19103`; machine `https://host.docker.internal:19104` | Sonar READ/ASK; image `sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402`. GitHub/native обновление сюда не переносилось |
| Изолированный native review | Owner `http://localhost:19203`; machine `https://host.docker.internal:19204` | Sonar + GitHub/native worktree; OWNER-REPORTED v3 image update PASS: source `2f88d92091e7d652ea0f33486fbeb38f2eaedd21`, image `sha256:515ad033db0a4af7e2d29a3138d53d6a3f6e8e7909bd884145828bcc6ea28a4d`; analysis profile выключен |
| Fortis Repo | `/workspace/repo/Repos/fortis-approvals`, task worktrees рядом в `Worktrees/fortis-approvals/` | Primary на `main`; после PR №13 — `2f88d92091e7d652ea0f33486fbeb38f2eaedd21`, чистый (LIVE-VERIFIED при подготовке updater) |

Это два отдельных Gateway runtime, каждый со своим состоянием и общей моделью
Core/Owner Portal. Native запуск сохранил M3 для возврата, owner credentials,
history и receipts; Production baseline не изменился по owner-run проверкам.
READY при запуске означал готовность, а не E2E PASS. Итоговый PASS подтверждён
последующим [живым циклом](../../fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md).
OWNER-REPORTED: Windows main обновлён до того же source SHA; собран image
`sha256:515ad033db0a4af7e2d29a3138d53d6a3f6e8e7909bd884145828bcc6ea28a4d`
с revision label этого commit. Offline smoke после явного добавления
`/opt/fortis` в `sys.path` прошёл, включая analysis-review imports.
OWNER-REPORTED: v3 [updater](WINDOWS-REVIEW-UPDATE.md) прошёл все шаги и выдал
`FORTIS_REVIEW_IMAGE_UPDATE_PASS`: прежний review/state сохранён, Production
baseline неизменён, native/GitHub/Sonar checks успешны. Две предыдущие попытки
завершились возвратом; их records и retained artifacts сохранены.
LIVE-VERIFIED после успешного update: точный client probe из Repo успешно прочитал
native capabilities, GitHub branches и Sonar quality gate. Новый Sonar read
`list_project_branches` получил HTTP 403 при `analysisProfileConfigured=false`.
Image/host lifecycle подтверждены owner output, не отдельным Docker inspect из
Repo. Новые grants/policies, workflow binding, permissions, CI manifest и live
acceptance новых операций остаются незавершёнными.
[Evidence обновления и предыдущих отказов](../../fortis_approvals/evidence/FORTIS-REVIEW-UPDATER-OFFLINE-20261106.md).

## Что завершено

- Sonar: `list_projects`, `list_issues`, `get_issue`, `get_quality_gate` — ALLOW;
  `accept_issue` — ASK + owner WebAuthn для закреплённого проекта
  `AlexPastukhh_obs-planning-docs`. [Reject/Approve evidence](../../fortis_approvals/evidence/FORTIS-SONAR-LIVE-E2E-20261104.md).
- GitHub M1/M2/M3: ветка, запись тестового файла через API, draft PR и чтение
  Source CI через Gateway приняты. [Milestones](../INTEGRATION-MODULARIZATION-AND-GITHUB-ONBOARDING-PLAN.md).
- Native: настоящие существующие Git-коммиты опубликованы без изменения SHA;
  source PR №10 прошёл CI, ready и merge. На отдельной задаче проверены
  create/edit/check/stage/commit, два push, PR №11, CI, merge, Docker main
  fast-forward и owner-approved удаление worktree/локальной ветки.
- Повторы commit/push с прежним UUID не повторили эффект; устаревший digest
  stage отклонён. Очистка подтверждена исполнением, не одним Approve.
- Весь native live цикл выполнен запросами Gateway без GitHub-коннектора и
  старого Git credential helper. Последний Sonar readback — `OK`.

Подробные SHA, request IDs и границы проверки находятся только в
[live evidence](../../fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md).
Матрица native-политик не дублируется здесь: обычный task push — ALLOW,
изменения CI, PR/ready/merge/cleanup — ASK; точные условия — в
[native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md).

## Граница доверия и исполнения

Repo использует `/run/fortis-client/grant` и публичный `server.crt` из RO mount.
Grant читается процессами того же UID; RO не обеспечивает изоляцию AI actors.
Provider tokens, TLS private key, owner WebAuthn и runtime DB остаются на стороне
Gateway. Production volumes `fortis-r7-state`, `fortis-r7-identity`,
`fortis-r7-grant`, `fortis-r7-sonar-token` не являются исходниками Git.
Изолированный GitHub credential подключён только в review Gateway, read-only
по `/run/github-token/token`; его точное имя volume хранится в owner record.

Локальные typed workspace-команды авторизует Gateway, выполняет Repo worker.
Он привязан к зарегистрированному worktree, ветке, HEAD и digest; provider
credential ему не передаётся. Core/owner decision и локальное исполнение —
разные стадии. `UNCERTAIN` требует сверки receipt; слепого повтора мутации нет.
Реализация не ограничивает все остальные возможности общего Repo process tool.

## Известные ограничения

- Код дополнительных операций Sonar/CI включён в новый review image, но [analysis profile](../ANALYSIS-REVIEW-CONTRACT.md) не активирован; новые grants/policies не включены. В действующем профиле Quality Gate относится
  к `CURRENT_DEFAULT_BRANCH`, `prShaBinding=NOT_VERIFIED_D2`; Sonar `OK` не
  подтверждает анализ конкретного GitHub SHA. `ACCEPTED` не означает исправление кода.
- Source CI для merge привязан к точному PR head; это проверка GitHub CI,
  не доказательство Sonar analysis/SHA binding.
- Native scope — один actor, `AlexPastukhh/fortis-approvals`, зарегистрированные
  `task/*`. Общая миграция остальных репозиториев и удаление legacy PAT/helper
  не проводились. Наличие helper остаётся отдельным обходным каналом доступа.
- Сам native live цикл не проверял Windows main; последующий pull подтверждён владельцем, как указано выше. Mirror остаётся
  отдельным получателем; его AI API и полноценная адресация worktree ещё впереди.
- При ожидании cleanup обнаружена несовместимость `WorkflowClient.result` с
  HTTP 202 (`PENDING`). Исправление и регрессионный тест подготовлены в отдельном
  `task/native-client-pending-status-20261106`, но на момент сверки не закоммичены
  и не входят в `main`. Успех cleanup подтверждён с тем же request ID.
- После Approve/Reject UI некоторое время не показывает обратную связь.
  Это наблюдение пользователя; причина задержки ещё не исследована.
- Production cutover, полный аудит/рефакторинг кода, редактор политик,
  multi-agent isolation, scheduler, RDG G3 и защищённая Windows import/RUN
  доставка не считаются завершёнными. [План дальнейших работ](../FOLLOW-UP-PLAN.md).

## Работа с исходниками и восстановление

Canonical source — отдельный GitHub repository `AlexPastukhh/fortis-approvals`;
извлечённый RDG subtree сохранён. Source PR/merge не меняет установленный image,
Windows clone или runtime volumes. Текущие client entry points и тесты —
в [source map](../../fortis_approvals/README.md); scripts/return paths —
в [deployment index](../../fortis_approvals/deploy/README.md).

Provisioning, owner enrollment и Repo client mount уже выполнены; не повторять
их из старых runbook. Не удалять retained M3, bootstrap source worktree или
volumes, от которых зависит owner deployment record. Git хранит код и manifests;
для image/state/секретов нужен отдельный owner-controlled backup/restore.
Историческая [acceptance matrix](../../fortis_approvals/deploy/FORTIS-UNIVERSAL-GATEWAY-ACCEPTANCE-MATRIX-20261101.md)
и архивы сохраняют provenance, а не текущие next steps.
