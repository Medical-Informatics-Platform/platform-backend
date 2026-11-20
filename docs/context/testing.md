# Testing

## Unit and HTTP contract tests

Use Java 21 and Maven:

```bash
mvn test
mvn clean package
```

`src/test/java/hbp/mip` contains JUnit, Mockito, AssertJ, MockMvc, and security tests. Spring Boot test support is already in the build. Unit tests cover Analysis request/result serialization, preview/run/save, draft expiry, sharing and dataset authorization, Study/group operations, data-model listing, Exaflow contracts, and authentication navigation.

## PostgreSQL integration tests

The `postgres-integration` profile uses Maven Failsafe to run `*IT` tests during `verify`. PostgreSQL is required; an unavailable database fails the run instead of skipping coverage. No additional Java test dependencies are needed: tests use the existing PostgreSQL JDBC driver, Flyway, Spring JDBC, and JPA.

Against a disposable local database:

```bash
mvn -B -ntp -Ppostgres-integration \
  -Dit.database.url=jdbc:postgresql://127.0.0.1:5432/platform_test \
  -Dit.database.username=postgres \
  -Dit.database.password=postgres \
  clean verify
```

These are also the profile defaults. The test user needs permission to create/drop schemas. Each test creates a random isolated schema, and cleanup drops that schema after the application context closes. Use a database reserved for tests.

`BackendPersistenceIT` verifies:

- Fresh Flyway migration through V6 and startup of the real persistence configuration, including package scanning, query parsing, and explicit Hibernate schema validation.
- Populated V5 upgrades preserving every saved-record, unsaved-run, Study, Analysis Group, and membership value, including malformed historical requests, results with explicit nulls/large integers, timestamps, permissions, and ordering.
- Dataset-authorization parity between the old V5 and new V6 SQL functions across selected/validation datasets, missing or malformed input, and mixed case.
- Saving migrated active runs without execution, repeated saves, expiry and owner checks, query filtering before totals, unchanged external claims, and Study/group/deletion operations.

The `backend-tests.yml` workflow runs `clean verify` with this profile, Java 21, a PostgreSQL service, and RabbitMQ 4.4.1 on pull requests and master pushes. Broker tests run when `RABBITMQ_TEST_URL` is set (`amqp://guest:guest@rabbitmq:5672` in that workflow).

## Review expectations

Keep focused HTTP tests for changes to routes, field names, totals, and status codes. Keep service authorization and raw-result tests. Migrations must be new files; do not rename or edit shipped migrations. Review the rename migration and claim handling together with the backend/UI deployment changes.
