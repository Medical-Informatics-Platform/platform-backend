# Code Review Checklist

## Correctness
- [ ] Does the change solve the stated problem?
- [ ] Are edge cases handled?
- [ ] Are null/empty/error responses handled consistently with existing code?
- [ ] Are public API, DTO, and database compatibility impacts documented?

## Tests
- [ ] Are relevant tests added or updated?
- [ ] Were the correct commands run?
- [ ] Are database migrations verified against PostgreSQL when applicable?
- [ ] Are Exaflow success and error paths covered when integration behavior changes?

## Architecture
- [ ] Does the change respect module boundaries?
- [ ] Is business logic in the service layer?
- [ ] Are controllers thin?
- [ ] Are persistence changes routed through repositories/DAOs and Flyway?
- [ ] Are shared utilities truly shared?

## Security
- [ ] No secrets are committed.
- [ ] Sensitive values are not logged.
- [ ] Auth/authz behavior is preserved or explicitly reviewed.
- [ ] Dataset and experiment access checks are preserved.
- [ ] Token exposure and CSRF behavior are reviewed if touched.

## Maintainability
- [ ] The change is small enough to review.
- [ ] Naming and structure match the repo.
- [ ] Dependencies are justified and minimal.
- [ ] Documentation/context files are updated if conventions or commands changed.

## Release Risk
- [ ] Migrations are reversible or rollback is documented.
- [ ] Runtime config/env changes are documented.
- [ ] Docker image impact is considered.
- [ ] CI/release workflow changes are reviewed for secret and publishing impact.
- [ ] Rollback considerations are included when relevant.
