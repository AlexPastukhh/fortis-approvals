# Gateway credentials

## UC-GW-004

**Когда:** нужно добавить, заменить или отозвать provider credential.

**Цель:** выполнить owner-controlled rotation без утечки токена и без запуска
сохранённого Legacy по устаревшей инструкции.

**Как:** прочитать [credential rotation owner](../CREDENTIAL-ROTATION.md)
и [extension contract](../INTEGRATION-EXTENSIONS.md), проверить exact IDs,
protected records, token mounts и in-flight ASK, план affected consumers и
restart. Token вводится только в защищённый owner prompt, не в AI/Repo,
не из `.fortis-auth` Git credential helper. После Primary promotion
re-rotation live отдельно не подтверждён: **не выводить её успех из старого
runbook**. Действующий Primary `19204`, legacy `19104` остановлен; не запускать
его без особого разрешения. Проверить readback и failure recovery.

**Готово:** защищённый receipt ротации, проверенный доступ нужного provider и
перечень непроверенных write permissions; при неопределённом restart plan — STOP.
