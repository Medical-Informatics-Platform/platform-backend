# Module Index

## `src/main/java/hbp/mip`

Purpose: Main Java application package.

Key files: `MIPApplication.java`.

Used by: Spring Boot component scanning.

Rules: Keep package names under lowercase `hbp.mip`.

Tests: Add tests under matching `src/test/java/hbp/mip` packages.

Notes: The application uses Spring Boot auto-configuration plus explicit security and persistence configuration.

## `src/main/java/hbp/mip/configurations`

Purpose: Framework and infrastructure configuration.

Key files: `SecurityConfiguration.java`, `PersistenceConfiguration.java`, `OpenApiConfig.java`, redirect/filter handlers.

Used by: Spring Boot startup and request security pipeline.

Rules: Treat auth, CSRF, JWT authority mapping, OAuth2 redirect behavior, Flyway, and entity manager configuration as high-risk changes.

Tests: Add focused Spring/security tests before changing behavior.

Notes: Raw authority strings are intentional and should not be automatically prefixed with `ROLE_`.

## `src/main/java/hbp/mip/algorithm`

Purpose: Algorithm metadata API and service.

Key files: `AlgorithmsAPI.java`, `AlgorithmService.java`, `AlgorithmsSpecs.java`, algorithm DTOs.

Used by: Clients requesting available algorithms and experiment execution validation paths.

Rules: Keep Exaflow metadata fetching and disabled algorithm filtering in the service layer.

Tests: Mock Exaflow responses and disabled algorithm resources for service tests.

Notes: A scheduled async refresh exists in `AlgorithmService.AlgorithmAggregator`.

## `src/main/java/hbp/mip/datamodel`

Purpose: Data model and dataset metadata API.

Key files: `DataModelAPI.java`, `DataModelService.java`, `DataModelDTO.java`.

Used by: Clients discovering available pathologies, variables, datasets, and metadata.

Rules: Preserve claim-based filtering when authentication is enabled.

Tests: Cover Exaflow response parsing, empty responses, and authorization filtering.

Notes: Data comes from multiple configured Exaflow endpoints and is aggregated in service code.

## `src/main/java/hbp/mip/experiment`

Purpose: Experiment lifecycle API, business logic, persistence entity, repository, and query specifications.

Key files: `ExperimentAPI.java`, `ExperimentService.java`, `ExperimentRepository.java`, `ExperimentDAO.java`, `ExperimentSpecifications.java`.

Used by: Clients creating, listing, updating, deleting, and running experiments.

Rules: Preserve ownership/shared access checks, max page size behavior, immutable field validation, and Flyway-backed schema compatibility.

Tests: Add service/repository tests for behavior changes and migration checks for schema changes.

Notes: Persisted experiment execution starts a background thread and then updates status/result.

## `src/main/java/hbp/mip/user`

Purpose: Active user resolution, persistence, and NDA state.

Key files: `ActiveUserAPI.java`, `ActiveUserService.java`, `UserRepository.java`, `UserDAO.java`, `UserDTO.java`.

Used by: Controllers needing user context and endpoints exposing active user/token behavior.

Rules: Treat token exposure and user identity mapping as security-sensitive.

Tests: Cover OIDC user, JWT user, authentication-disabled anonymous user, and missing-auth cases.

Notes: Authentication-disabled mode creates or updates an `anonymous` user with accepted NDA.

## `src/main/java/hbp/mip/utils`

Purpose: Shared helper classes and exception handling.

Key files: `Logger.java`, `HTTPUtil.java`, `JsonConverters.java`, `ClaimUtils.java`, `ControllerExceptionHandler.java`, `Exceptions/*`.

Used by: Feature APIs and services.

Rules: Do not put feature-specific business rules here unless they are truly shared. Avoid logging secrets or raw tokens.

Tests: Add unit tests for utility behavior before broad reuse or refactors.

Notes: `HTTPUtil` uses `HttpURLConnection`; no dedicated HTTP client abstraction is currently configured.

## `src/main/resources`

Purpose: Local runtime config, logging config, and database migrations.

Key files: `application.yml`, `log4j2.yml`, `db/migration/V1__InitialSchema.sql`.

Used by: Local app runtime and Maven resource packaging.

Rules: Add new migrations instead of editing shipped migrations. Keep secret values out of committed config.

Tests: Run migration validation against PostgreSQL for DB changes.

Notes: `application.yml` contains local defaults and placeholder Keycloak values.

## `config`

Purpose: Container runtime config template and static runtime assets.

Key files: `application.tmpl`, `disabledAlgorithms.json`.

Used by: Docker image entrypoint and production/container runtime.

Rules: Keep template variables aligned with documented environment configuration.

Tests: For config changes, build the Docker image or validate template rendering in the deployment environment.

Notes: `dockerize` renders `application.tmpl` to `/opt/config/application.yml`.

## `.github/workflows`

Purpose: Repository automation.

Key files: `publish_images.yml`, `ebrains.yml`.

Used by: GitHub Actions release publishing and EBRAINS mirror sync.

Rules: Treat registry credentials, mirror tokens, image tags, and release triggers as high-risk.

Tests: Validate workflow syntax and review secret usage before editing.

Notes: No test/build CI workflow was found beyond release image publishing.
