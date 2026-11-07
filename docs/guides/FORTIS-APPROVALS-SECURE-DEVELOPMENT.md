# Fortis Approvals Gateway — текущее состояние

Датированный срез 2026-11-07: последний owner-provided Windows release output
и последующие Repo machine readback. Это не свежий Docker inspect с Windows:
перед runtime-операцией сверить protected records и реальную identity.
Этот документ владеет deployment status; [agent guide](../GATEWAY-AGENT-GUIDE.md)
— применением, [native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md)
— операциями/policy, [backlog](../BACKLOG-IMPROVEMENTS.md) — будущими задачами.

## Развёрнутые контуры

| Контур | Endpoint / роль | Последнее подтверждение |
| --- | --- | --- |
| Primary `fortis-gateway` | Owner `http://localhost:19203`; machine `https://host.docker.internal:19204` | Owner post-promote: healthy, restart `unless-stopped`; Repo typed operations работают |
| Legacy `fortis-approvals-gateway` | Бывшие 19103/19104 | Owner остановил контейнер, `restart=no`, image/state сохранены; не штатный endpoint |
| Fortis Repo `fortis-repo-test` | Machine client и native workspace worker | Отдельный контейнер; canonical `Repos/<repo>` и linked `Worktrees/<repo>/<task>` |

Последний подтверждённый owner image release:

| Поле | Значение из owner output |
| --- | --- |
| Source SHA образа | `217dbcc05a735052e2531d6839c9d808e433792e` |
| Image ID | `sha256:5c5fc58ed80a4ea4fa2b39d78195395d08b8b9d4278c337fdd8fa2ba6339a109` |
| Complete release record | `%LOCALAPPDATA%\Fortis\GatewayReleases\fe0c906431e84f5287f764accb9f0df8\record.json` |
| Verified controller backup | `fortis-gateway-backup-eb084fe7ee9c4b078e80a19ca4050ade` |
| Host result | Apply activated, Backup PASS, Promote PASS, `FORTIS_GATEWAY_POST_PROMOTE_PASS` |

Последующие documentation/source merges меняют Git `main`, а не этот image.
Container ID нового Primary в предоставленном финальном выводе не записан:
не подставлять ID `043d3497…` от первоначального cutover. Факты reboot/autostart
initial runtime сохранены в [cutover evidence](../../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md);
они не являются новым reboot-тестом каждого последующего image.

<a id="что-завершено"></a>

## Что подтверждено через Repo

- Live capabilities: `dynamicRepositories=true`, присутствует
  `workspace.update_main_from_pr`, ordinary task push и PR creation — ALLOW.
- Реальные task commit/push/PR и owner UI merge с обновлением Docker main
  проверены для Gateway, Container, Mirror, Tunnel, Script Center и Tab Notifier.
  Это не обещание прав записи для всех обнаруженных GitHub repos.
- Provider credentials остаются в Gateway; native bundle сохраняет SHA локальных
  Git-коммитов. Точные policy/preconditions находятся только в native contract.
- Первоначальные Sonar READ и owner ASK Approve/Reject проверены в
  [Sonar evidence](../../fortis_approvals/evidence/FORTIS-SONAR-LIVE-E2E-20261104.md),
  native bootstrap — в [native evidence](../../fortis_approvals/evidence/FORTIS-NATIVE-GIT-LIVE-20261106.md).
  Не считать эти датированные циклы новой полной проверкой Owner Portal после
  каждого image. В этом аудите owner WebAuthn ceremony не запускалась.

## Граница доверия и исполнения

Machine grant/public trust в Repo, provider tokens/TLS private key/owner state
в Gateway имеют разные роли. RO mount и `0600` не изолируют процессы одного UID.
Local workspace effect исполняет Repo worker после Core authorization; approval,
dispatch и подтверждённый receipt — разные стадии. Общий process tool Repo не
становится автоматически ограниченным Gateway policy.

<a id="известные-ограничения"></a>

## Действующие ограничения

- Sonar default-branch Quality Gate не доказывает PR/SHA binding; доступные
  операции определяются live profile, не наличием source package.
- Legacy Repo PAT/helper removal не подтверждён. Это не разрешённый fallback:
  применять [UC-CONT-003](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/delivery.md#uc-cont-003).
- Для PENDING status у текущего клиента действует HTTP 202 caveat из
  [native contract](../NATIVE-WORKTREE-GATEWAY-2026-11-06.md); при UNCERTAIN
  сверять исходный UUID и receipt, не повторять эффект вслепую.

Незавершённая разработка и ожидающие acceptance ведутся только в
[единственном backlog](../BACKLOG-IMPROVEMENTS.md). Здесь — подтверждённые
факты, границы их проверки и ограничения выбора операции.

## Работа с исходниками и восстановление

Canonical source — standalone `AlexPastukhh/fortis-approvals`; старый RDG subtree
сохранён и не является местом разработки. [Package map](../../fortis_approvals/README.md)
и [deployment index](../../fortis_approvals/deploy/README.md) ведут к коду и контроллеру.
Provisioning/enrollment/client mount не повторять из старого runbook.
Использовать текущие controller records для Resume/Return/Backup/Promote по
[Primary operations](../PRIMARY-GATEWAY-OPERATIONS.md). Не очищать bootstrap,
retained states и credentials, пока от них зависят owner deployment records.
Git и image не заменяют backup persistent state и secrets.
