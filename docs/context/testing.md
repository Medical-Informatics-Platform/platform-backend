# Testing

## Detected Test Setup
- No committed `src/test/java` tree was found.
- No `spring-boot-starter-test`, JUnit, Mockito, AssertJ, Surefire, Failsafe, or JaCoCo configuration was found in `pom.xml`.
- `mvn test` is still the baseline Maven test phase and should be run after changes.

## Test Directory Structure
Use package-mirroring under:

```text
src/test/java/hbp/mip
```

Recommended naming:

- `*Test` for unit tests.
- `*IT` for integration tests.

## Fast Tests
```bash
mvn test
```

Until test dependencies are added, this may only compile and run an empty test phase.

## Full Tests
Unknown / TODO: verify once integration tests exist. For database behavior, run relevant tests against PostgreSQL and verify Flyway migrations apply cleanly.

## Backend Test Guidance
Add focused tests when changing:

- `SecurityConfiguration`: auth modes, CSRF behavior, JWT authorities, permitted endpoints.
- `ClaimUtils`, `DataModelService`, `ExperimentService`: authorization and data access logic.
- `ExperimentRepository` and DAOs: persistence and schema-sensitive behavior.
- `HTTPUtil` or Exaflow integrations: external response handling and error mapping.
- `ControllerExceptionHandler`: HTTP status and error response mapping.

## Fixtures and Mocks
No committed test fixtures or mocks were found. For future tests, prefer:

- Mocking Exaflow HTTP responses for service-level tests.
- Using representative DTO payloads near the tests that need them.
- Using PostgreSQL-backed integration tests for migration/schema behavior.

## Under-Tested Critical Paths
- OAuth2/JWT authority mapping and authentication-disabled mode.
- Dataset and experiment authorization checks.
- Experiment creation, background execution, deletion, and immutable-field validation.
- Exaflow metadata aggregation and error handling.
- Flyway migrations and schema validation.
- Logging behavior around request bodies, tokens, and experiment results.

## Validation Matrix

| Change type | Required validation |
|---|---|
| Documentation-only change | `git diff --check`; optionally `pre-commit run --all-files` |
| Controller/API behavior change | Add or update controller/service tests; run `mvn test`; document request/response impact |
| Service/business logic change | Add focused unit tests; run `mvn test` |
| Database migration | Add new Flyway migration; verify against PostgreSQL; run `mvn test`; document rollback considerations |
| Auth/permission change | Add security/authorization tests; manually review `SecurityConfiguration`, `ClaimUtils`, and affected services |
| Exaflow integration change | Mock success/error responses; run `mvn test`; verify config keys and timeout/error behavior |
| Dependency update | Explain need; run `mvn test` and `mvn clean package`; check Docker build if runtime-related |
| Refactor without behavior change | Run `mvn test`; add characterization tests first if touching high-risk logic |
| Docker/runtime config change | Run `docker build -t hbpmip/platform-backend:testing .`; verify relevant env/template values |
