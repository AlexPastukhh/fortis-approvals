# Primary Gateway lifecycle

## UC-GW-007

**Когда:** требуется переключить Primary, подтвердить autostart или retire Legacy.

**Цель:** единый Gateway после Docker Desktop restart с контролируемым rollback.

**Как:** точный [Primary operations runbook](../PRIMARY-GATEWAY-OPERATIONS.md)
является владельцем действий. Перед Promote — [UC-CONT-021](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/docker.md#uc-cont-021)
и [UC-CONT-022](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/docker.md#uc-cont-022).
Проверить protected Primary pointer, identity, image/ports, restart policy,
WebAuthn, machine TLS, Sonar/GitHub/native readback, Repo worker.
Затем отдельный [UC-CONT-023](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/docker.md#uc-cont-023)
для сохранённого Legacy, без удаления volumes и образа.
`FORTIS_PRIMARY_PROMOTED` и post-promote `docker inspect` не
доказывают автозапуск после реального Docker Desktop restart либо
browser WebAuthn acceptance. Их проверяют отдельно в owner maintenance
window. Image, mounts, Primary pointer и retained rollback сверять
заново; результаты конкретного выпуска — в
[current state](../guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md)
и датированных evidence, а не в этом UC.

**Готово:** Primary healthy и autostart подтверждены владельцем, Repo TLS/API
доступен после restart, Legacy не используется по умолчанию, recovery retained.
