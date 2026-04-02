# Repository Guidelines

## Project Structure & Module Organization
This repository is a Spring Boot backend (`java.version=21`) built with Maven.

- `src/main/java/hbp/mip`: application code.
- `src/main/java/hbp/mip/configurations`: security, persistence, OpenAPI, and web filters.
- `src/main/java/hbp/mip/{algorithm,datamodel,experiment,user}`: feature modules (API, service, repository/DAO, DTOs).
- `src/main/java/hbp/mip/utils`: shared helpers and exception handling.
- `src/main/resources`: runtime config (`application.yml`, `log4j2.yml`) and Flyway migrations in `db/migration`.
- `config/`: container templated config (`application.tmpl`) and static runtime assets.
- `.github/workflows`: release image publishing and mirror automation.

## Build, Test, and Development Commands
- `mvn clean package`: compile and build `target/platform-backend.jar`.
- `mvn spring-boot:run`: run locally using `src/main/resources/application.yml`.
- `mvn test`: run test phase (also useful as a smoke check when no tests are present).
- `docker build -t hbpmip/platform-backend:testing .`: build container image.
- `pre-commit run --all-files`: run repository hooks (whitespace, YAML/JSON checks, JSON formatting).

Local development expects PostgreSQL (default `127.0.0.1:5433/portal`) and reachable external services configured in `application.yml`.

## Coding Style & Naming Conventions
- Follow existing Java style: 4-space indentation, clear constructor injection, and minimal field mutability (`final` where possible).
- Keep package names lowercase under `hbp.mip`.
- Use established type suffixes: `*API` (controllers), `*Service`, `*Repository`, `*DAO`, `*DTO`.
- Preserve current logging approach (`hbp.mip.utils.Logger` + Log4j2 config).
- Keep migration filenames in Flyway format: `V{number}__Description.sql`.

## Testing Guidelines
There is currently no committed `src/test/java` tree. For new functionality:

- Add unit/integration tests under `src/test/java`, mirroring production packages.
- Name tests `*Test` (unit) and `*IT` (integration).
- Run `mvn test` before opening a PR.
- For DB changes, verify migrations apply cleanly against a local PostgreSQL instance.

## Commit & Pull Request Guidelines
Recent history follows Conventional Commit style (for example: `fix(user): ...`, `chore(build): ...`, `refactor(...): ...`).

- Use `type(scope): short imperative summary`.
- Keep commits focused and atomic.
- In PRs, include: purpose, linked issue, config/env changes, migration impact, and validation steps run (`mvn test`, local run, or Docker build as relevant).
- If API behavior changes, include example request/response snippets.
