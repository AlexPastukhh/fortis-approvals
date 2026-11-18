# Gateway credentials

## UC-GW-004

**Когда:** нужно добавить, заменить или отозвать provider credential.

**Цель:** выполнить owner-controlled rotation без утечки токена и без запуска
сохранённого Legacy по устаревшей инструкции.

**Как:** прочитать [credential rotation owner](../CREDENTIAL-ROTATION.md)
и [extension contract](../INTEGRATION-EXTENSIONS.md), проверить exact IDs,
protected records, token mounts и in-flight ASK, план affected consumers и
restart. Token вводится только в защищённый owner prompt, не в AI/Repo,
не из `.fortis-auth` Git credential helper.
После любой Primary promotion заново проверять фактический доступ
credential: предыдущее успешное обращение не является доказательством
ротации. Primary/Legacy ID, порты и состояние брать из live host и
защищённых records, не из исторического runbook. Legacy не запускать
без отдельного разрешения; при недоказанном readback — STOP.

**Готово:** защищённый receipt ротации, проверенный доступ нужного provider и
перечень непроверенных write permissions; при неопределённом restart plan — STOP.

**Будущий owner wizard (PLANNED):** показывать только alias/scopes/readiness
и границы затрагиваемых providers, никогда содержимое секрета. ИИ может
подготовить запрос/план, но не вводить, читать, сохранять или ротировать
credential через machine API; owner-only ввод и отдельный receipt остаются
обязательными. Policy WebAuthn не заменяет upstream credential authorization.
