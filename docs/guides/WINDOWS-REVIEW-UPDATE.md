# Owner-run обновление native review

[Update-NativeReview.ps1](../../fortis_approvals/deploy/Update-NativeReview.ps1)
сворачивает preflight, smoke, остановку исходного review, копирование state,
создание замены и read-only проверки в один owner-run entrypoint Windows
PowerShell 5.1. Это ограниченный переход от принятого native owner record к
уже собранному image; image/контуры и фактический статус принадлежат
[current state](FORTIS-APPROVALS-SECURE-DEVELOPMENT.md).

## Входы и границы

- Image и source revision закреплены в entrypoint; повторная сборка не нужна.
- Исходный protected record читается из `%LOCALAPPDATA%\Fortis\GitHubPilot`.
  Проверяются точные ID/name/image/state/token/native scope и ACL. Record не
  переписывается; bootstrap worktree и retained M3 сохраняются.
- Новый private record по умолчанию находится в
  `%LOCALAPPDATA%\Fortis\GitHubPilot\review-update-515ad033-native-v2\record.json`.
  Intent записывается до мутаций. State копируется в новый пустой named volume;
  исходный контейнер, state и image остаются. Автоматического удаления нет.
- State helper использует явный native profile: помимо прежних БД сохраняет
  `native-git/workflow.sqlite`, зарегистрированные tasks/jobs, content-addressed
  bundles и пустой изолированный Git runner. Проверяет целостность SQLite,
  отсутствие journals/незавершённых запросов и jobs, owner binding, hashes и
  права. Временные `git-auth-*`/`git-fetch-*` и другие неизвестные элементы,
  symlinks/hardlinks, непустой runner config и повреждённые bundles блокируют
  копирование. Legacy pilot profile остаётся строгим и отдельно тестируется.
  Копируется только state. Credential volumes подключаются к замене RO;
  их содержимое не выгружается в Repo, пакет или вывод.
- Скрипт может остановить только точно принятый исходный review и собственную
  admitted замену. Production только inspect/read baseline. Порты замены —
  loopback review; runtime profile, mounts и ограничения сверяются до start.
- Сеть: offline smoke/validation/clone helpers без сети; новый Gateway использует
  прежний bridge и provider transport. Read-only postchecks из `fortis-repo-test`
  идут через Gateway (capabilities, GitHub branches, Sonar quality gate).

Первый failed record `review-update-515ad033/record.json` сохраняется. Если он
существует, повторная попытка допускается только после проверки `Returned`,
отсутствия clone receipt/созданного контейнера и любых planned resources.
Его hash записывается в новый record; старый файл не перезаписывается.

## Один запуск

Для передачи создаётся один standalone `.ps1` через
[`scripts/package-review-update.py`](../../scripts/package-review-update.py)
из чистого source commit. В нём находятся нужные неизменённые pilot functions,
embedded state helper/offline smoke и тот же entrypoint. Внешние source assets
и распаковка ZIP на Windows не требуются. Builder отказывается перезаписывать
выходной файл и выводит source SHA / полный SHA256.

Владелец получает этот файл из `fortis-repo-test` через `docker cp`, проверяет
заранее выданный SHA256 и запускает его. Это разовая owner-reviewed передача
review release; production import/RUN процесс ею не заменяется.

При запуске непосредственно из Windows checkout, содержащего новый entrypoint:

```powershell
& .\fortis_approvals\deploy\Update-NativeReview.ps1
```

Внутри запуска до любых Docker-команд проверяются реальные PowerShell 5.1
JSON arrays, private stdin/subprocess transport, NTFS ACL и atomic record
replacement. Ошибка останавливает запуск. Отдельная ручная диагностика для
этого не требуется. `-Mode SelfTest` запускает только эти локальные проверки.

По умолчанию сохраняется прежний runtime profile. Новый код в image сам по
себе не включает новые grants/policies. Вывод
`ANALYSIS_OPERATIONS_DISABLED_CONFIGURATION_PENDING` означает именно это.

Для явного opt-in предусмотрен `-AnalysisConfig <path-to-public-json>`.
JSON проверяется самим image до остановки исходного review; допустимы только
закреплённые owner/project и схема
[analysis-review contract](../ANALYSIS-REVIEW-CONTRACT.md).
Фактические repo/workflow ID/path должны быть установлены отдельно через
Gateway и reviewed владельцем; нельзя подставлять Source CI другого проекта.
Наличие opt-in не подтверждает upstream permissions, CI manifest или live
работу новых операций. Токены/секреты в этот JSON не входят.

## Ожидаемый результат и сбой

Успех image update: `FORTIS_REVIEW_IMAGE_UPDATE_PASS`, protected record и
read-only checks в итоговом JSON. `newOperationsLiveVerified=false` остаётся
явным: этот запуск не выполняет Sonar/CI мутаций и не доказывает SHA binding.

STOP: несовпадение record/ACL/ID/image/revision/profile; занятой целевой ресурс;
неизвестный writer; неизвестный state/journal/незавершённый запрос; ошибка
smoke, clone, health или readback. При startup failure скрипт пытается остановить
только свою admitted замену, проверить неизменность исходного stopped state и
вернуть прежний review. Маркер: `FORTIS_REVIEW_UPDATE_RETURNED_PREVIOUS`.
При неоднозначности выводит `UPDATE_RETURN_INCOMPLETE`; сохраняет все артефакты.

После прерывания сначала читается записанный record. Повтор Start с тем же
record запрещён; `-Mode Rollback` продолжает только безопасный возврат по нему,
включая поиск созданной замены по имени и label при потере ответа Docker.
После `Complete` этот rollback запрещён: новая ветвь state уже может содержать
owner decisions/receipts, и её возврат требует отдельного review. Файлы/volumes
не удаляются и при неудачном обновлении.

Проверки source и границы evidence:
[offline evidence](../../fortis_approvals/evidence/FORTIS-REVIEW-UPDATER-OFFLINE-20261106.md).
