# Agent Instructions

## Project Overview
This repository contains the Spring Boot backend for the Medical Informatics Platform (MIP). It exposes API endpoints under the `/services` servlet context, integrates with PostgreSQL, Keycloak/OAuth2, and Exaflow services, and builds as a Java 21 Maven jar/container image.

## Repository Layout
- `src/main/java/hbp/mip`: application entrypoint and backend code.
- `src/main/java/hbp/mip/configurations`: security, OAuth2/JWT, persistence, OpenAPI, and redirect/filter configuration.
- `src/main/java/hbp/mip/algorithm`: algorithm metadata API/service and disabled algorithm filtering.
- `src/main/java/hbp/mip/datamodel`: data model API/service backed by Exaflow metadata endpoints.
- `src/main/java/hbp/mip/experiment`: experiment API, service, repository, JPA entity, specifications, and DTOs.
- `src/main/java/hbp/mip/user`: active user API/service, user repository, JPA entity, and DTO.
- `src/main/java/hbp/mip/utils`: shared logging, JSON/HTTP helpers, resource loading, claim validation, and exception handling.
- `src/main/resources`: local runtime config, Log4j2 config, and Flyway migrations under `db/migration`.
- `config/`: container config template and static runtime assets such as `disabledAlgorithms.json`.
- `.github/workflows`: release image publishing and EBRAINS mirror automation.
- `docs/context`: durable repository context for humans and AI coding agents.

## Stack
- Language/runtime: Java 21.
- Build/package manager: Maven (`pom.xml`); no Maven wrapper is committed.
- Frameworks/libraries: Spring Boot 4.0.6, Spring Security 7, OAuth2 client/resource server, Spring Data JPA, Hibernate, Flyway, Gson, Log4j2, springdoc OpenAPI.
- Database: PostgreSQL, configured through Spring datasource properties.
- Auth: Keycloak/OIDC when `authentication.enabled` is enabled; anonymous development mode exists when disabled.
- External services: Exaflow endpoints for algorithms, data models, metadata, dataset variables, and algorithm execution.
- Container: multi-stage Docker build using Maven and Amazon Corretto 21.

## Setup Commands
Use a local Java 21 JDK and Maven installation.

```bash
mvn -B -ntp dependency:go-offline
```

Local development also expects PostgreSQL and reachable Exaflow/Keycloak endpoints based on `src/main/resources/application.yml`. Unknown / TODO: verify the preferred local database bootstrap command; no Docker Compose or Makefile is committed.

## Development Commands
Run locally with the development config in `src/main/resources/application.yml`:

```bash
mvn spring-boot:run
```

The service listens on port `8080` with servlet context `/services` by default.

## Build Commands
```bash
mvn clean package
```

The Maven build produces `target/platform-backend.jar`.

## Test Commands
```bash
mvn test
```

There is currently no committed `src/test/java` tree. Treat `mvn test` as the baseline smoke check until focused tests are added.

## Lint / Format / Typecheck
```bash
pre-commit run --all-files
```

The pre-commit hooks check whitespace, merge conflicts, large files, YAML, JSON, and JSON formatting. Unknown / TODO: verify any Java formatter or static analysis command; none is configured in `pom.xml`.

Java compilation/type checking is covered by:

```bash
mvn test
mvn clean package
```

## Architecture Rules
- Put HTTP endpoints in `*API` classes under the owning feature package.
- Put business logic in `*Service` classes; controllers should delegate rather than implement workflows directly.
- Put persistence in Spring Data repositories and JPA `*DAO` entities. Current JPA packages are `hbp.mip.experiment` and `hbp.mip.user`.
- Put API/request/response shapes in `*DTO` records or DTO classes close to the feature package.
- Put cross-cutting helpers in `hbp.mip.utils` only when they are genuinely shared.
- Put security, persistence, OpenAPI, and web filter wiring in `hbp.mip.configurations`.
- Keep Flyway migrations in `src/main/resources/db/migration` using `V{number}__Description.sql`.
- Keep runtime/container configuration in `src/main/resources/application.yml` and `config/application.tmpl`; do not read environment variables ad hoc from feature code.

## Coding Conventions
- Use 4-space Java indentation and existing package style under lowercase `hbp.mip`.
- Prefer constructor injection for dependencies.
- Keep fields `final` where practical; Spring `@Value` fields in this repo are currently mutable.
- Preserve established suffixes: `*API`, `*Service`, `*Repository`, `*DAO`, `*DTO`.
- Use Java records for simple DTOs where the repo already does.
- Use repository/service methods for database work instead of direct persistence from controllers.
- Use `hbp.mip.utils.Logger` for user/action logs and existing Log4j2 configuration.
- Use custom exceptions plus `ControllerExceptionHandler` for HTTP error mapping.
- Preserve raw authority strings such as `research_dataset_*`; do not add a `ROLE_` prefix unless the auth model changes intentionally.

## Forbidden Patterns
- Do not make product-code changes when the task is documentation-only.
- Do not bypass service/domain layers from controllers.
- Do not silently swallow exceptions; either map them to existing exceptions or log and rethrow according to local patterns.
- Do not add global mutable state unless the existing module already owns that state intentionally.
- Do not read environment variables outside the Spring configuration layer.
- Do not change public API behavior, DTO fields, routes, auth semantics, or database schema without documenting compatibility and migration impact.
- Do not add dependencies or update versions without explaining why and updating validation notes.
- Do not log secrets, bearer tokens, client secrets, raw credentials, or sensitive request data.
- Do not change Flyway migrations that have already shipped; add a new migration instead.
- Do not make broad refactors while fixing a narrow behavior.

## Token Budget and High-Output Tool Rules
- Do not run broad, high-output commands on your own. Ask for explicit approval first if a command is likely to dump thousands of lines or large files.
- Forbidden without approval: `find .`, `ls -R`, `tree`, unbounded `cat`, unbounded `sed`, `rg` without focused globs, `git diff` without path/stat limits on large changes, full logs without `--tail`, `mvn -X`, recursive dumps of `target`, `.git`, dependency caches, generated files, jars, binaries, or minified assets.
- Prefer targeted commands: `rg --files` with path filters, `rg -n "pattern" src/main/java`, `sed -n 'start,endp' file`, `git diff --stat`, `git diff --name-status`, and log commands with explicit line limits.
- If large context is necessary, summarize it in chunks and state why the extra output is needed before requesting approval.

## Security and Privacy Rules
- Never commit secrets, tokens, keys, cookies, credentials, or private environment values.
- Never print secrets in logs or final reports.
- Treat auth, authorization claims, CSRF, token exposure, migrations, data deletion, and experiment execution as human-review areas.
- Preserve OAuth2 login and bearer-token behavior unless the task explicitly changes auth.
- Preserve dataset and experiment access checks in `ClaimUtils` and `ExperimentService`.
- Review logs carefully when touching experiment execution, active user token handling, or external service calls.

## PR Expectations
Every agent change should include:
- Summary of the change.
- Files changed.
- Tests and checks run, with results.
- Risk assessment.
- Rollback notes when relevant.
- Config/env/migration impact when relevant.
- Example request/response snippets if API behavior changes.

Recent history uses Conventional Commit style such as `fix(user): ...`, `chore(build): ...`, and `refactor(...): ...`.

## Definition of Done
- The diff is minimal and tied directly to the request.
- Relevant files and local patterns were read before editing.
- Documentation paths and commands are based on repo evidence, with uncertain items marked `Unknown / TODO: verify`.
- Relevant checks passed, or the exact reason they could not be run is reported.
- No secrets or unrelated generated artifacts are introduced.
- Risky areas have explicit validation and human-review notes.
