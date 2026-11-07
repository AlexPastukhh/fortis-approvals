# SonarCloud

## UC-GW-001

**Когда:** требуется quality gate/issues, triage или связь анализа с PR/SHA.

**Цель:** получить обоснованный статус конкретного Sonar context и разрешённого provider effect.

**Как:** проверить [текущее состояние](../guides/FORTIS-APPROVALS-SECURE-DEVELOPMENT.md), scope, target и live typed catalogue. Через
[Sonar client](../../fortis_approvals/integrations/sonarcloud/README.md)
выполнять только доступный READ через Primary TLS. Для PR сопоставить Sonar
context с GitHub workflow/HEAD; default branch `OK` не равен анализу PR.
Analysis-review profile считается доступным только по live capabilities;
не запускать scanner при запросе отчёта. Triage effect — по
[ALLOW/ASK/DENY](https://github.com/AlexPastukhh/fortis-container/blob/main/docs/use-cases/authorization.md#uc-cont-007)
и [analysis contract](../ANALYSIS-REVIEW-CONTRACT.md). Поправки исходников —
через общий UC-CONT-002.

**Готово:** подтверждённый результат для выбранного context/SHA или явно
`UNKNOWN`; effect подтверждён receipt, отсутствие PR binding не замаскировано.
