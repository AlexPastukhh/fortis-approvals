# Gateway image/config release

## UC-GW-005

**Когда:** новый принятый Gateway image/config нужно активировать в работающей среде.

**Цель:** установить только точную принятую версию с защищённым release record.

**Как:** выбрать [общий Docker preflight](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/docker.md#uc-cont-021),
[verified backup](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/docker.md#uc-cont-022)
и [операционный controller](../../fortis_approvals/deploy/README.md). Проверить
approved source/image digest, config, state writers, protected records, provider
READ и доступность Owner Portal. Apply/activation и последующий Backup/Promote
имеют отдельные фазы по [Primary runbook](../PRIMARY-GATEWAY-OPERATIONS.md).
Новый source commit сам не изменяет runtime; не запускать второй Gateway с тем
же RW state/ports. После установки повторить live tests.

**Готово:** exact source/image + protected Complete record, healthy runtime и
READ от реального Repo; staged smoke не назван развертыванием.
