# Добавление и замена токенов Gateway

Вход для контейнера — UC-CONT-011. Этот документ владеет маршрутом выбора
controller; provider README владеет upstream permissions, current state — внедрением.
Токен вводит владелец на Windows, не AI и не чат.

## Выбор хранилища

| Подключение | Постоянный entrypoint |
| --- | --- |
| Действующий GitHub/native review | `Credential -Service github -Rotate` |
| Действующий Sonar в review и production | `Credential -Service sonarcloud -Rotate` |
| Named credentials новых providers | `Credential -CredentialName <alias>`; замена с `-Rotate` по [extension contract](INTEGRATION-EXTENSIONS.md#токены-и-windows-entrypoint) |

`-Service` и `-CredentialName` не смешиваются. Запись alias `github` в новый vault
не обновит старое подключение. Legacy Repo helper — другое хранилище;
этот путь его не читает, не меняет и не мигрирует.

## GitHub / Sonar: одна команда

Один раз получить принятый source в чистый Windows `fortis-approvals/main`
обычным [Git/Windows workflow](https://github.com/AlexPastukhh/docke-windows-mirror/blob/main/docs/WORKFLOW.md).
Далее из `%USERPROFILE%\Repos\fortis-approvals` запустить нужную команду:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\fortis_approvals\deploy\Manage-Integrations.ps1 -Action Credential -Service github -Rotate
```

Для Sonar та же команда с `-Service sonarcloud`. Значение вводится в защищённый
prompt. Нет значения токена в argv/env, Git, record или выводе; confidential stdin
передаёт его только временному owner helper с доступом к credential volume.

Новый image, build, mounts, контейнеры и конфигурация Gateway не создаются.
Оба старых transport читают токен при старте, поэтому controller останавливает
и запускает **те же** затрагиваемые контейнеры:

- GitHub: только активный review; production не меняется.
- Sonar: активные review **и production**, поскольку они используют один token
  volume. Будет короткая недоступность обоих контуров. Image и конфигурация прежние.

Controller выбирает текущий review по защищённому deployment record, проверяет
его admission, production baseline, RO token mounts и всех consumers volume.
Неизвестный активный consumer или writer блокирует действие. Retained containers
не запускаются и не удаляются; общий credential volume при этом получает новый токен.

Перед stop новый токен проверяется фиксированным authentication GET внутри
Gateway: GitHub `/user`, Sonar EU `/api/authentication/validate`. Затем обычный
клиент проверяет операции после рестарта. Sonar этого legacy controller ограничен
принятым EU profile; другая region требует отдельного согласованного пути.

До stop и повторно после stop проверяется Core. Неистёкшие PENDING/APPROVED,
DISPATCHED/UNCERTAIN и неизвестные состояния в затрагиваемых runtime блокируют
ротацию. Сначала завершить/отклонить либо reconcile эти заявки штатным клиентом/
Owner Portal; controller не переписывает approvals и не подтверждает их за владельца.
Старые approvals в retained остановленных state не получают новых гарантий:
их возврат требует отдельного review, не автоматического запуска после ротации.

Файл заменяется атомарно с проверкой прежнего поколения metadata, UID/GID 10001
и mode 0600. Прежнее значение не читается и не копируется в backup. После запуска
выполняются только чтения **Repo → Gateway → provider**: GitHub branches/PR/Actions
либо Sonar quality gate в обоих контурах. PASS: `FORTIS_PROVIDER_CREDENTIAL_ROTATED`.
Это подтверждает проверенные чтения; права внешних мутаций не доказываются readback.
Новый токен должен иметь нужные права по [GitHub](../fortis_approvals/integrations/github/README.md#credential-and-permission-boundary)
или [Sonar](../fortis_approvals/integrations/sonarcloud/README.md#credential-and-trust-boundary).

## Ошибка и повтор

Защищённый record хранится в `%LOCALAPPDATA%\Fortis\GatewayReleases\credential-<id>\record.json`.
При ошибке controller запускает те же остановленные контейнеры обратно, но
**не возвращает старое значение токена**. Ошибка после попытки записи может означать,
что значение уже заменено; PASS не выдаётся, старый token пока не отзывать.
Проверить record/код ошибки и повторить ту же команду с корректным токеном.

После прерывания процесса повтор той же команды сначала восстанавливает
зафиксированные контейнеры при неизменных ID/image/config, затем начинает новую
попытку с защищённым вводом. Изменившийся контейнер не запускается автоматически.
Records не удаляются. Не запускать параллельно другой controller или ручную
замену credentials. Старый токен отзывать у provider после успешного readback;
controller сам его не отзывает.

## Граница проверки

Исходники и локальные проверки — в
[offline evidence](../fortis_approvals/evidence/PROVIDER-CREDENTIAL-ROTATION-OFFLINE-20261106.md).
Фактическое внедрение и owner-run результаты ведутся в
[current state](guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md) и evidence.
Наличие source в main не означает замену токена.

Authentication API references: [GitHub](https://docs.github.com/en/rest/users/users#get-the-authenticated-user),
[Sonar Web API](https://docs.sonarsource.com/sonarqube-cloud/appendices/web-api)
и встроенная [V1 specification](https://sonarcloud.io/web_api/api/authentication/validate).
