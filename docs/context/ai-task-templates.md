# AI Task Templates

## Bug Investigation Template

Goal:
Investigate and propose a minimal fix for the bug below.

Before editing, read:
- `AGENTS.md`
- `docs/context/architecture.md`
- `docs/context/module-index.md`
- `docs/context/testing.md`
- Relevant source files and tests

Bug:
...

Constraints:
- Keep the fix minimal.
- Preserve public API behavior unless explicitly requested.
- Add a regression test when possible.

Return:
1. Root cause
2. Evidence
3. Proposed fix
4. Files to change
5. Tests to run
6. Risk assessment

## Refactor Plan Template

Goal:
Plan a behavior-preserving refactor for the area below.

Before editing, read:
- `AGENTS.md`
- `docs/context/architecture.md`
- `docs/context/module-index.md`
- `docs/context/risk-register.md`
- Current implementation and any related tests

Area:
...

Constraints:
- Do not change routes, DTOs, auth behavior, migrations, or external wire shapes unless explicitly requested.
- Prefer small, reviewable steps.

Return:
1. Current structure
2. Target structure
3. Step-by-step changes
4. Tests and checks
5. Rollback plan

## Test Generation Template

Goal:
Add focused tests for the behavior below.

Before editing, read:
- `AGENTS.md`
- `docs/context/testing.md`
- Relevant source files

Behavior:
...

Constraints:
- Mirror production package structure under `src/test/java`.
- Prefer focused unit tests before broad integration tests.
- Mock Exaflow and auth inputs where practical.

Return:
1. Test cases added
2. Fixtures/mocks used
3. Commands run
4. Remaining coverage gaps

## Code Review Template

Goal:
Review the current diff for correctness, security, architecture, and missing tests.

Before reviewing, read:
- `AGENTS.md`
- `docs/context/risk-register.md`
- `docs/context/code-review-checklist.md`

Constraints:
- Prioritize findings by severity.
- Cite file and line references.
- Do not rewrite code during review unless explicitly asked.

Return:
1. Findings
2. Open questions
3. Test gaps
4. Residual risk

## Dependency Update Template

Goal:
Update the dependency below with minimal risk.

Before editing, read:
- `pom.xml`
- `docs/context/commands.md`
- `docs/context/testing.md`
- `docs/context/risk-register.md`

Dependency:
...

Constraints:
- Explain why the update is needed.
- Avoid unrelated dependency churn.
- Run Maven checks and consider Docker build for runtime-impacting updates.

Return:
1. Version change
2. Compatibility notes
3. Files changed
4. Commands run
5. Risk and rollback notes

## Frontend Feature Template

Goal:
Coordinate a frontend-facing change that affects this backend.

Before editing, read:
- `AGENTS.md`
- `docs/context/architecture.md`
- Relevant API/controller/DTO code

Feature:
...

Constraints:
- This repo contains only the backend.
- Document request/response changes.
- Preserve backwards compatibility unless explicitly requested.

Return:
1. Backend API changes
2. Frontend contract notes
3. Validation plan
4. Risks

## Backend/API Feature Template

Goal:
Implement a backend/API feature.

Before editing, read:
- `AGENTS.md`
- `docs/context/architecture.md`
- `docs/context/module-index.md`
- `docs/context/testing.md`
- `docs/context/risk-register.md`

Feature:
...

Constraints:
- Put endpoints in `*API`, logic in `*Service`, persistence in repositories/DAOs, and API shapes in `*DTO`.
- Add Flyway migrations for schema changes.
- Preserve auth and access-control boundaries.

Return:
1. Summary
2. API/schema changes
3. Files changed
4. Tests run
5. Risk assessment

## Security-Sensitive Change Template

Goal:
Modify security-sensitive behavior.

Before editing, read:
- `AGENTS.md`
- `docs/context/risk-register.md`
- `SecurityConfiguration.java`
- `ClaimUtils.java`
- Affected service/API code

Change:
...

Constraints:
- Do not weaken authentication, authorization, CSRF, token handling, or logging protections.
- Add or update focused tests.
- Require human review.

Return:
1. Threat/behavior summary
2. Exact security boundary touched
3. Tests and manual checks
4. Human review notes
5. Rollback notes

## Documentation Update Template

Goal:
Update repository documentation/context for the change below.

Before editing, read:
- `AGENTS.md`
- `docs/context/README.md`
- Relevant context files

Change:
...

Constraints:
- Keep docs specific to repo evidence.
- Mark uncertain facts as `Unknown / TODO: verify`.
- Avoid duplicating large content across files.

Return:
1. Files updated
2. New facts documented
3. Unknowns left
4. Validation performed

## Architecture Review Template

Goal:
Review the architecture of the area below and identify practical improvements.

Before reviewing, read:
- `AGENTS.md`
- `docs/context/architecture.md`
- `docs/context/module-index.md`
- `docs/context/risk-register.md`
- Relevant source files

Area:
...

Constraints:
- Separate confirmed repo facts from recommendations.
- Prefer small, staged improvements over broad rewrites.

Return:
1. Current architecture
2. Risks or friction points
3. Recommended changes
4. Validation strategy
5. Decision-log entries to add
