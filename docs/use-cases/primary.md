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
На релизе PR #62 (2026-11-10) владелец подтвердил
`FORTIS_PRIMARY_PROMOTED` и Windows `docker inspect`:
`/fortis-gateway | running | healthy | unless-stopped`,
loopback-порты `19203/19204`. Repo дополнительно проверил machine
`globalRequestInventory.crossActorDetails=true` и список заявок.
Это **подтверждение Promote**, но не самостоятельное испытание
autostart после реального Docker Desktop restart и не browser click
WebAuthn. Датированная
[cutover evidence](../../fortis_approvals/evidence/FORTIS-PRIMARY-CUTOVER-LIVE-20261107.md)
относится к более старому переходу; host/release identity всегда
проверять заново.

**Готово:** Primary healthy и autostart подтверждены владельцем, Repo TLS/API
доступен после restart, Legacy не используется по умолчанию, recovery retained.
