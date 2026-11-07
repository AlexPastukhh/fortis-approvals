# Fortis Approvals Gateway — текущее состояние

Актуализировано 2026-11-07 по owner Docker output и live Repo readback **после**
Backup/Promote, перезапуска Docker Desktop и остановки Legacy. Primary работает
под стабильным именем `fortis-gateway`; источник подтверждений —
[свидетельства переключения](../../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md).
Этот документ владеет текущим статусом;
[agent guide](../GATEWAY-AGENT-GUIDE.md) — правилами использования,
[native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md) — матрицей операций,
[отдельный план](../BACKLOG-IMPROVEMENTS.md) — будущими задачами.

## Развёрнутые контуры

| Контур | Endpoints | Подтверждённое состояние |
| --- | --- | --- |
| Legacy `fortis-approvals-gateway` | Бывшие Owner `http://localhost:19103`; machine `https://host.docker.internal:19104` | **Остановлен** (`exited`, `restart=no`), ID `0852c39c9e5d…`, image `sha256:e751f6ca0cfe6ce290cf580de2f243071ee1f3e681baa8827c6cea41a16fa402`. Контейнер, image, volumes и records сохранены для контролируемого отката; порт не используется штатным клиентом. |
| Primary `fortis-gateway` | Owner `http://localhost:19203`; machine `https://host.docker.internal:19204` | **Работает после Docker Desktop restart** (`running`, `healthy`, `unless-stopped`), ID `043d3497b2d1…`, image `sha256:238ea3a43225eec4b714a0cf23c70559434c56a8b03f44b865ede40c70ca8242`. Sonar/GitHub/Approvals READ после остановки Legacy: PASS. |
| Fortis Repo (`fortis-repo-test`) | `/workspace/repo/Repos/fortis-approvals`, task worktrees в `Worktrees/fortis-approvals/` | Автозапуск после Docker Desktop restart подтверждён; чистый Docker `main` во время live readback — `fab6f0101f849eb1343ad0b6365ee0bcb0034f24`. |

Это два отдельных Gateway runtime, каждый со своим состоянием и общей моделью
Core/Owner Portal. Native запуск сохранил M3 для возврата, owner credentials,
history и receipts; Production baseline не изменился по owner-run проверкам.
READY при запуске означал готовность, а не E2E PASS. Итоговый PASS подтверждён
последующим [живым циклом](../../fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md).
В рамках нового переключения факты Docker ID/image/health/restart подтверждены
выводом Windows-владельца, а защищённый machine API — живыми запросами Repo.
Внешние клиенты старого 19104 исчерпывающе не инвентаризированы.

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
Матрица native-политик и точные условия живут в
[native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md); live capabilities
после обновления review сверены с ним.

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

- Дополнительные операции Sonar/CI присутствуют в image как [source-кандидат](../ANALYSIS-REVIEW-CONTRACT.md), но их runtime profile выключен. В действующем профиле Quality Gate относится
  к `CURRENT_DEFAULT_BRANCH`, `prShaBinding=NOT_VERIFIED_D2`; Sonar `OK` не
  подтверждает анализ конкретного GitHub SHA. `ACCEPTED` не означает исправление кода.
- Source CI для merge привязан к точному PR head; это проверка GitHub CI,
  не доказательство Sonar analysis/SHA binding.
- Native scope — один actor, `AlexPastukhh/fortis-approvals`, зарегистрированные
  `task/*`. Общая миграция остальных репозиториев и удаление legacy PAT/helper
  не проводились. Наличие helper остаётся отдельным обходным каналом доступа.
- В историческом native live цикле Windows main не обновлялся; для Primary
  cutover Windows main уже получен через Mirror и проверен чистым на
  `fab6f0101f849eb1343ad0b6365ee0bcb0034f24`. Mirror AI API и полная
  адресация worktree всё ещё отдельные задачи.
- При ожидании cleanup обнаружена несовместимость `WorkflowClient.result` с
  HTTP 202 (`PENDING`). Исправление и регрессионный тест подготовлены в отдельном
  `task/native-client-pending-status-20261106`, но на момент сверки не закоммичены
  и не входят в `main`. Успех cleanup подтверждён с тем же request ID.
- После Approve/Reject UI некоторое время не показывает обратную связь.
  Это наблюдение пользователя; причина задержки ещё не исследована.
- Legacy Sonar-only runtime выведен из работы в рамках Primary cutover;
  новые host-independent disaster recovery и все свежие ALLOW/ASK/DENY проверки
  остаются незавершёнными. Полный аудит/рефакторинг кода, редактор политик,
  multi-agent isolation, scheduler, RDG G3 и защищённая Windows import/RUN
  доставка не считаются завершёнными. [План дальнейших работ](../BACKLOG-IMPROVEMENTS.md).

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

Общий [extension framework](../INTEGRATION-EXTENSIONS.md) активирован в review
с пустым списком новых providers. Последний owner-run обновил image до принятого
source с PR ALLOW. Repo подтвердил capabilities, GitHub main read, прежний Sonar
default-branch gate и неизменный пустой catalog. Текущие image/source/record,
configuration digest и проверка PR creation хранятся в
[live evidence](../../fortis_approvals/evidence/PR-CREATION-ALLOW-LIVE-20261106.md).
Предыдущее внедрение сохранено в
[extension evidence](../../fortis_approvals/evidence/EXTENSIONS-LIVE-ACTIVATION-20261106.md).

Optional Sonar/CI analysis profile остаётся выключенным: последнее отдельное
контрольное чтение `list_project_branches` вернуло 403. Для этих операций нужны
согласованные profile, CI binding/manifest, permissions и live acceptance.
Обновление image и общий framework их автоматически не включают;
default-branch OK не доказывает PR/SHA binding.

Source-only owner tooling now includes one-command legacy GitHub/Sonar token
rotation through the permanent controller. The [runbook](../CREDENTIAL-ROTATION.md)
owns its restart/shared-volume effects; [offline evidence](../../fortis_approvals/evidence/PROVIDER-CREDENTIAL-ROTATION-OFFLINE-20261106.md)
records validation. Windows/Docker execution and real token replacement are
MANUAL-PENDING; the currently deployed image does not need a rebuild for this tooling.
