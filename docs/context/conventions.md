# Conventions

## Confirmed Conventions

### Naming and Structure
- Java packages live under `hbp.mip`.
- Controllers use the `*API` suffix.
- Services use the `*Service` suffix.
- Repositories use the `*Repository` suffix.
- JPA entities use the `*DAO` suffix.
- API/request/response shapes use the `*DTO` suffix, often as Java records.
- Feature modules are grouped by package: `algorithm`, `datamodel`, `experiment`, and `user`.

### Backend Layering
- Controllers accept HTTP input, create user/action logs, and delegate to services.
- Services own business logic, authorization decisions, Exaflow calls, and persistence workflows.
- Repositories own database access and persistence helpers.
- DAOs represent persisted PostgreSQL tables.
- Shared cross-cutting helpers live in `hbp.mip.utils`.

### Error Handling
- Feature code throws custom runtime exceptions from `hbp.mip.utils.Exceptions`.
- `ControllerExceptionHandler` maps exceptions to HTTP responses.
- Unexpected exceptions are logged and returned as HTTP 500.

### Logging
- User-facing actions use `hbp.mip.utils.Logger`.
- Logs include username, endpoint, and message.
- Existing code logs some request and experiment details; avoid expanding sensitive logging.

### Configuration
- Spring properties are defined in `src/main/resources/application.yml`.
- Container properties are rendered from `config/application.tmpl`.
- Feature code uses Spring `@Value` for configured URLs and flags.
- Environment variables should be routed through Spring config/templates, not read directly.

### API Patterns
- Routes are relative to servlet context `/services`.
- Controllers use Spring MVC annotations such as `@RestController`, `@RequestMapping`, `@GetMapping`, `@PostMapping`, and `@PatchMapping`.
- JSON serialization uses Spring/Jackson for API responses and Gson utilities in some internal conversion paths.

### Persistence
- Flyway owns migrations.
- Hibernate validates schema with `ddl-auto: validate`.
- Current JPA repositories/entities are in `experiment` and `user`.

### Agent Tool and Token Budget
- Agents should use focused repository inspection commands and avoid dumping broad context.
- Commands that are likely to consume excessive tokens require explicit human approval before use: `find .`, `ls -R`, `tree`, unbounded `cat`/`sed`, unfiltered `rg`, full build/debug logs, full container logs, large `git diff` output, and recursive inspection of `target`, `.git`, dependency caches, generated files, jars, binaries, or minified assets.
- Prefer bounded alternatives: path-filtered `rg --files`, targeted `rg -n`, small `sed -n` ranges, `git diff --stat`, `git diff --name-status`, and logs with `--tail` or equivalent limits.
- When large context is unavoidable, the agent should ask first, explain the expected size and reason, and summarize results instead of pasting raw output.

## Recommended Conventions to Verify
- Add a test dependency such as Spring Boot test support before creating substantive Java tests, if not already added by a future change.
- Prefer constructor-bound configuration properties for new configuration-heavy code, but match local `@Value` style for small scoped changes.
- Prefer managed Spring executors for new background work instead of raw `Thread`, unless intentionally preserving existing behavior.
- Prefer a Spring HTTP client abstraction for larger external integration changes; keep small fixes consistent with `HTTPUtil`.
- Add a Java formatter/static-analysis command before enforcing style mechanically.
