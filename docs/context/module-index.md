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

Purpose: Exaflow analysis execution (`AnalysisExecutionService`, called by `AnalysisService`) and Exaflow specification endpoints (`GET /specifications/{inputdata,preprocessing,algorithms}`).

Key files: `AnalysisExecutionService.java`, `AnalysisRequestDTO.java`, `SpecificationsAPI.java`, `SpecificationsService.java`, specification DTOs.

Used by: The UI and notebook client for specifications; `AnalysisService` for analysis previews and runs.

Rules: Keep Exaflow calls in the service layer. Dataset access checks must cover `inputdata.allDatasets()` (datasets plus validation datasets).

Tests: `AnalysisExecutionServiceRequestIdTest`, `AnalysisRequestDTODeserializationTest`, `AlgorithmSpecificationDTOTest`, `ExaflowKMeansAndSmdContractTest`, `ExaflowPcaCreatorContractTest`.


## `src/main/java/hbp/mip/datamodel`

Purpose: Data model and dataset metadata API.

Key files: `DataModelAPI.java`, `DataModelService.java`, `DataModelDTO.java`.

Used by: Clients discovering available data models, variables, datasets, and metadata.

Rules: Preserve claim-based filtering when authentication is enabled.

Tests: Cover Exaflow response parsing, empty responses, and authorization filtering.

Notes: Data comes from multiple configured Exaflow endpoints and is aggregated in service code.

## `src/main/java/hbp/mip/analysis`

Purpose: Platform Analysis management, synchronous preview/run/save, persistence, and query specifications.

Rules: Keep ownership/shared access checks, filtering before pagination/totals, max page size, immutable request fields, and raw result serialization. Complete execution requests use `analysisRequest` in Java/HTTP and `analysis_request` in both `analysis` and `analysis_run`; algorithm names remain in `algorithm_id`.

```text
GET  /analyses         -> { analyses, currentPage, totalPages, totalAnalyses }
POST /analyses/preview -> 200 Analysis   { name, analysisRequest } (no persistence)
POST /analyses/runs    -> 200 Analysis   { name, analysisRequest } (retain success; uuid is runId)
POST /analyses         -> 201 Analysis   { runId, name } (save without execution)
GET/PATCH/DELETE /analyses/{uuid}
```

All paths are under `/services`. PATCH permits name, shared, and viewed; the execution request is immutable. Successful runs remain owner-only in `analysis_run` for `analyses.run-draft-ttl` (`ANALYSIS_RUN_DRAFT_TTL`, default `PT24H`). Cleanup is opportunistic on successful runs. Save requires runId and name (400); missing, expired, or another user's draft is 404. Save copies the stored request, result, timestamps, and MIP version without rechecking dataset access, and does not consume the draft.

Others may read shared Analyses only when authorized for every selected dataset, including validation datasets. Owners and `research_experiment_all` retain their existing access. Only owners may update/delete. Lists enforce the same visibility before counting.

Tests: `AnalysisAPITest`, `AnalysisDTOResultTest`, `AnalysisServiceRunSaveTest`, `AnalysisServiceSharedAccessTest`, and `BackendPersistenceIT`.

## `src/main/java/hbp/mip/study`

Purpose: Owner-scoped Studies, Analysis Groups, and ordered Study Members.

```text
GET    /studies                                      -> 200 { studies: [study] }
POST   /studies                                      -> 201 study { name, analysisId? }
GET    /studies/{studyId}                             -> 200 study
PATCH  /studies/{studyId}                             -> 200 study { name }
DELETE /studies/{studyId}                             -> 204
POST   /studies/{studyId}/members                     -> 200 study { analysisId }
DELETE /studies/{studyId}/members/{analysisId}        -> 200 study
POST   /studies/{studyId}/groups                      -> 201 study { name, analysisId? }
PATCH  /studies/{studyId}/groups/{groupId}             -> 200 study { name }
DELETE /studies/{studyId}/groups/{groupId}             -> 200 study
PATCH  /studies/{studyId}/members/{analysisId}/group   -> 200 study { groupId: uuid | null }

study = { id, name, analysisIds, groups: [{ id, name, analysisIds }] }
```

One membership row per `(study_id, analysis_id)` gives at most one group per Study. An Analysis can belong to multiple Studies. Null/blank groupId ungroups without leaving the Study; deleting a group leaves its members ungrouped. Deleting a Study never deletes Analyses. Mutations return the updated Study, except Study deletion.

Preserve owner scoping (foreign Study/group is 404), Analysis read checks (403), normalization (collapse whitespace, trim, 60 characters), case-insensitive name uniqueness (409), transaction boundaries, write locks, and idempotent add/move/remove operations. Members use `study_position`, group members use `group_position`, and Studies/groups use `sort_order`.

Tests: `StudyAPITest`, `StudyServiceTest`, `StudyDTOTest`, and `BackendPersistenceIT`.

## `src/main/java/hbp/mip/user`

Purpose: Active user resolution, persistence, and NDA state.

Key files: `ActiveUserAPI.java`, `ActiveUserService.java`, `UserRepository.java`, `UserDAO.java`, `UserDTO.java`.

Used by: Controllers needing user context and the endpoints exposing the active user.

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

Key files: `application.yml`, `log4j2.yml`, `db/migration/V1__InitialSchema.sql`, `db/migration/V2__Studys.sql`.

Used by: Local app runtime and Maven resource packaging.

Rules: Add new migrations instead of editing shipped migrations. Keep secret values out of committed config.

Tests: Run migration validation against PostgreSQL for DB changes.

Notes: `application.yml` contains local defaults (`${ENV:default}`) and placeholder Keycloak values. Export `MIP_VERSION` before local runs.

## `.github/workflows`

Purpose: Repository automation.

Key files: `publish_images.yml`, `ebrains.yml`.

Used by: GitHub Actions release publishing and EBRAINS mirror sync.

Rules: Treat registry credentials, mirror tokens, image tags, and release triggers as high-risk.

Tests: Validate workflow syntax and review secret usage before editing.

Notes: No test/build CI workflow was found beyond release image publishing.
