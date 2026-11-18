# Gateway → Windows PowerShell Executor — Machine ASK V1

Этот документ — сценарии **Gateway/Repo actor**: подача, owner decision, readback, отказ и безопасная диагностика. Windows singleton/SQLite/ACL принадлежат [UC-PSE-001/002/003](https://github.com/AlexPastukhh/fortis-powershell-executor/blob/main/docs/use-cases/README.md); запуск через Script Center — [UC-SCC-003/004](https://github.com/AlexPastukhh/script-control-center/blob/main/docs/use-cases/README.md). Технический источник: [Machine ASK contract](../POWERSHELL-MACHINE-ASK-CONTRACT-V1.md) и [Gateway client](../../fortis_approvals/workflow/powershell_client.py). ASK не песочница: любая одобренная команда имеет обычные права Windows пользователя.

<a id="uc-gw-014"></a>

## UC-GW-014 — Создать ровно одну PowerShell-заявку с ASK

**Когда:** авторизованный Repo actor должен выполнить новую команду на доверенном Windows target.

**Как:**

1. Прочитать **живые** capabilities через `default_client().powershell.capabilities()`: `configured=True`, `policy=ASK`, `machineExecutionAutoApprove=False`, `version=1`. В отсутствие этого набора — STOP, никаких альтернативных HTTP/owner-only маршрутов.
2. Сформировать точный текст команды, один новый UUID и фиксированный `windows-owner`; через штатный клиент вызвать `powershell.submit(command, request_id=uuid, target="windows-owner")`. Actor, секреты, Windows identity, URL, proof, политику и SQLite не задаёт ИИ.
3. Проверить по **исходному UUID** `PENDING`; не считать accepted HTTP response разрешением на исполнение. Если ACK пропал или submit дал неопределённость, **не повторять submit**, не создавать новый UUID: читать `powershell.result(uuid)` и Core `details(uuid)`.
4. Owner открывает вкладку **«На согласовании»** в Fortis Owner Portal, сверяет полный текст команды, digest, actor, target и предупреждение о несандбоксированном исполнении. Approve требует отдельного owner WebAuthn; ИИ не вызывает owner approval APIs и не выбирает решающего.
5. Только после approval Gateway подписывает proof, связанный с UUID/точными байтами команды/Core fingerprint/actor/target/expiry. Windows проверяет mTLS, отдельный machine Bearer и proof **до** durable reserve и запуска; owner-only PowerShell tab не является machine proxy.

**Готово:** Core audit `PENDING → APPROVED → DISPATCHED → EXECUTED`, связанность UUID/command SHA/result с Windows SQLite и независимый typed result readback. Одна запись receipt сама по себе не даёт OS-подсчёт запусков.

<a id="uc-gw-015"></a>

## UC-GW-015 — Reject и чтение без нового исполнения

**Когда:** owner отклоняет заявку либо Repo должен проверить исход без повторной отправки команды.

**Как:**

1. Owner выбирает **ту же** Machine ASK заявку на вкладке «На согласовании» и нажимает Reject; не создавать отдельную команду или side-effect для проверки.
2. Repo читает `powershell.result(uuid)` и независимо Core `details(uuid)`. Для Reject ожидаются `REJECTED`, `result=None`, полная audit-история `PENDING → REJECTED`, **без** `DISPATCHED`.
3. Owner проверяет **существующую** Windows SQLite только `mode=ro` + `PRAGMA query_only=ON`. Записи rejected UUID отсутствуют в `shell_receipts` и `shell_machine_bindings`; более старые owner-only и machine receipts сохранены. Не передавать UUID/команды/SQLite-пути/секреты в чат.
4. Для Approve сопоставлять `requestId`, `commandSha256`, `state`, `exitCode`, ограниченные stdout/stderr из Core, typed result и Windows receipt. Не смешивать диагностический CLIXML progress с PowerShell ErrorRecord.

**Готово:** Reject не достиг dispatch/Windows receipt; Approve имеет проверенный bound result. Не считать пустой result доказательством отсутствия неизвестного эффекта.

**Live evidence — 2026-11-18:** новый `Get-Date` завершился `EXECUTED` (`exitCode=0`), команда/UUID/actor/target совпали; Windows SQLite: 2 receipts = 1 machine + 1 historical owner-only. Для отдельной отклонённой `Get-Date` Core `PENDING → REJECTED`, dispatch отсутствовал, Windows SQLite осталась 2/1; новой записи и binding нет. Положительный и Reject E2E — PASS; decoded stderr Get-Date содержит CLIXML progress с заменяющим символом, требует отдельного улучшения.

<a id="uc-gw-016"></a>

## UC-GW-016 — Неверный proof, ACK timeout и восстановление без повтора

**Когда:** появляется `DISPATCHED`/`UNCERTAIN`, lost ACK, timeout, mismatch proof, недоступность Windows или запрос на rollback/restart.

**Как:**

1. Для неоднозначного результата — **STOP** новым Windows effects. Сохранить оригинальный UUID/digest и read-only прочитать Core audit, typed result, Windows scoped GET, прежнюю SQLite и независимый процесс/child inventory. Не re-submit с тем же/новым UUID и не редактировать статусы.
2. `DISPATCHED` и `UNCERTAIN` в SQLite запрещают новое исполнение; отсутствие ACK, timeout, пустой ответ и nonzero exit не доказывают отсутствия side effect. `UNCERTAIN` Gateway Core и исторические `CLAIMED` относятся к другому журналу.
3. Missing/wrong client certificate, Bearer, Host, изменённый actor/target/command, expired/forged proof, неверный `Idempotency-Key` и дополнительное `approved` от ИИ должны блокироваться до PowerShell. Подмена payload под прежним UUID — конфликт. Никакой прямой machine или owner-only HTTP от Repo actor.
4. Для recovery/смены source владелец подтверждает quiescence, сохраняет **ту же текущую** защищённую SQLite/TLS/ACL/все receipts и единственный listener. Gateway release — [UC-GW-005](releases.md#uc-gw-005), incident review — [UC-GW-009](incidents.md#uc-gw-009); rollback Windows — UC-PSE/UC-SCC. Никаких автоматических restart, force-kill, старого DB snapshot или повтора исторических команд.
5. Сценарии intentional lost ACK, timeout, forged proof, replay и restart принимать **в изолированной тестовой среде** или отдельном owner-controlled maintenance window. Source/unit PASS не подменяет live PASS.

**Готово:** результат исходного UUID либо связан с подтверждённой квитанцией, либо остаётся явно `UNKNOWN/UNCERTAIN` с owner review без replay.

**Покрытие на 2026-11-18:** Gateway source 35/35 и Windows Executor 23/23 offline tests PASS; live Gateway DENY для чужого target, `approved=True`, неизвестного поля и пустой команды; TLS без client certificate отвергнут. **Live forged-proof, lost ACK, replay, timeout и restart не проверены**. Контур Repo не имеет Docker CLI для безопасного запуска дополнительных проверок от имени Gateway, никаких таких downstream запросов не было.
