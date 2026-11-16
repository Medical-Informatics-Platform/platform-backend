# Commands

## Package Manager
Detected: Maven from `pom.xml`.

No Maven wrapper (`mvnw`) was found, so commands assume Maven is installed on the host.

## Install
Prefetch Maven dependencies:

```bash
mvn -B -ntp dependency:go-offline
```

Unknown / TODO: verify a full local bootstrap command for PostgreSQL, Keycloak, and Exaflow dependencies.

## Run Locally
```bash
mvn spring-boot:run
```

The app uses `src/main/resources/application.yml` by default. Local defaults include port `8080`, servlet context `/services`, PostgreSQL at `127.0.0.1:5433/portal`, and Exaflow at `127.0.0.1:5000`.

## Build
```bash
mvn clean package
```

Expected artifact:

```text
target/platform-backend.jar
```

## Test
```bash
mvn test
```

Runs JUnit/Mockito and HTTP contract tests. PostgreSQL integration tests require `mvn -Ppostgres-integration verify`; see [testing.md](testing.md) for connection properties.

## Lint
```bash
pre-commit run --all-files
```

Configured hooks check whitespace, EOF newline, merge conflicts, large files, YAML, JSON, and JSON formatting.

Unknown / TODO: verify Java lint/static-analysis tooling; none is configured in `pom.xml`.

## Format
```bash
pre-commit run --all-files
```

The JSON hook can autoformat JSON. Unknown / TODO: verify Java formatting rules or formatter command.

## Typecheck
```bash
mvn test
mvn clean package
```

Java compilation is the available type/compile validation.

## Database / Migrations
Flyway migrations live in:

```text
src/main/resources/db/migration
```

The application configures Flyway startup migration through `PersistenceConfiguration`. Flyway owns schema changes; PostgreSQL integration tests explicitly validate Hibernate mappings.

The `postgres-integration` Maven profile applies migrations to isolated test schemas, tests fresh and populated upgrades, and removes those schemas afterwards.

## Docker
Build the container image:

```bash
docker build -t hbpmip/platform-backend:testing .
```

The Dockerfile performs a Maven build, copies `target/platform-backend.jar`, exposes port `8080`, and defines a healthcheck at `/services/actuator/health`. Configuration is read from classpath `application.yml`; set container environment variables to override defaults.

## CI
Detected workflows:

- `.github/workflows/publish_images.yml`: on published release, builds and pushes Docker images to Docker Hub and EBRAINS Harbor.
- `.github/workflows/ebrains.yml`: mirrors `master` and tags to EBRAINS GitLab on push.

`backend-tests.yml` runs the package build, unit/HTTP tests, and PostgreSQL migration/persistence tests on pull requests and master pushes.
