# UC-GW-008 — дополнительный passkey владельца

**Когда:** владелец хочет зарегистрировать ещё один passkey для существующего Owner Portal без пересоздания Gateway.

**Цель:** новая активная WebAuthn credential и подтверждённый вход при сохранении существующих ключей.

**Как:**

1. Убедиться, что действующий `fortis-gateway` healthy, доступен [Owner Portal](http://localhost:19203), действующий passkey позволяет вход, сохранено защищённое состояние и известна доверенная Windows owner-сессия.
2. В доверенном **локальном Windows PowerShell 5.1** вызвать [`Invite-Primary-Owner.ps1`](../../fortis_approvals/deploy/Invite-Primary-Owner.ps1) сначала без флагов (только Preview), затем явно `-Issue`. Не выполнять эти команды через AI, Repo MCP, GitHub Actions или публичный HTTP endpoint; приглашение не передавать в чат, файл, Git или лог.
3. В пределах **5 минут** открыть `http://localhost:19203`, выбрать «Зарегистрировать ключ по приглашению», вставить одноразовое приглашение, завершить browser WebAuthn ceremony с другим допустимым passkey и проверить вход. Существующие credentials не отзывать автоматически.
4. Если приглашение истекло, выдать новое owner-only; не пытаться повторно использовать старое. При неизвестном состоянии, смене Origin/RP ID, отказе Guard/здоровья, отсутствии существующего owner-login или подозрении на доступ третьих лиц — **STOP** и отдельный recovery review.

**Готово:** новый passkey способен войти в текущий Portal, исходный при необходимости продолжает работать, учёт старых и новых credentials ограничен owner-private SQLite. Источники: [`owner_auth.py`](../../fortis_approvals/owner_auth.py) (`issue_invitation`, `begin_enrollment`, `finish_enrollment`) и [`owner_portal.py`](../../fortis_approvals/owner_portal.py); новый owner-only CLI не добавляет AI-права.
