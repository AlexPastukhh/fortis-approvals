# Providers и typed операции

## UC-GW-002

**Когда:** требуется подключить новый внешний API/service к Gateway.

**Цель:** typed provider с минимальным scope, проверками и owner approval.

**Как:** по [extension contract](../INTEGRATION-EXTENSIONS.md) и
[пакету integrations](../../fortis_approvals/integrations/README.md)
проверить совместимость и использовать provider scaffold в task worktree.
Определить закрытые request/result schemas, preview/effect/receipts,
trusted actor/target policy и READ/ASK/Reject acceptance. Новые permissions
не возникают от каталогизации provider. Credential отдельно по [UC-GW-004](credential-lifecycle.md#uc-gw-004),
image activation по [UC-GW-005](releases.md#uc-gw-005), GitHub публикация —
через глобальные UC-CONT-002/003.

**Готово:** поддержка подтверждена в live каталоге и авторизованном readback;
набор операций/ошибок сверяется с кодом, а не продублирован здесь.

## UC-GW-003

**Когда:** нужно расширить существующий provider новой операцией.

**Цель:** принять одну безопасную typed операцию с policy и тестами отказов.

**Как:** в [extension owner](../INTEGRATION-EXTENSIONS.md) и
[provider code](../../fortis_approvals/integrations/README.md)
найти соответствующий schema/handler/client. Добавить required preconditions,
replay reconciliation и preview для эффекта. Не обходить зарезервированные
provider ID, не выбирать policy/URL из AI payload. Запустить профильные тесты,
доставить source через UC-CONT-002 и при изменении server image — UC-GW-005.

**Готово:** typed operation соответствует каталогу, разрешениям, отказам и
readback; runtime activation подтверждена отдельно.
