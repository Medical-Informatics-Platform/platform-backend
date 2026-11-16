# Risk Register

| Area | Risk | Evidence | Agent guidance | Human review required? |
|---|---|---|---|---|
| Authentication and OAuth2 | Login, logout, JWT, CSRF, and session behavior can lock users out or weaken protection | `SecurityConfiguration.java`, `SpaRedirectAuthenticationSuccessHandler.java`, `FrontendRedirectCaptureFilter.java` | Add focused tests and manually review auth flows before changing | Yes |
| Authority and claim mapping | Dataset/analysis access depends on raw authority strings and Keycloak claims | `SecurityConfiguration.java`, `ClaimUtils.java` | Do not add `ROLE_` prefixes or rename claims without migration/compat notes | Yes |
| Dataset authorization | Users may see unauthorized data models or datasets if filtering changes | `DataModelService.java`, `ClaimUtils.java` | Cover authenticated and authentication-disabled behavior | Yes |
| Analysis authorization | Owners/shared/admin-like access rules protect analysis read/update/delete | `AnalysisService.java`, `AnalysisSpecifications.java` | Test owner, shared, not-owner, and all-analyses authority cases. Shared analyses need all their datasets: a row naming none, such as a legacy one, is readable only by its owner and the all-analyses role. Keep `canRead` and the `analysis_datasets_readable` database function (V6) in step | Yes |
| Analysis deletion | Deletion is destructive and authorization-sensitive | `AnalysisAPI.java`, `AnalysisService.java` | Require focused tests and rollback/restore discussion for behavior changes | Yes |
| Analysis execution | Synchronous execution retains successful unsaved runs before a separate save | `AnalysisService.java` | Preserve preview/run/save, draft expiry, owner-only drafts, and raw results | Yes |
| Exaflow external APIs | Runtime depends on external service contracts and availability | `AnalysisExecutionService.java`, `SpecificationsService.java`, `DataModelService.java`, `AnalysisService.java`, `HTTPUtil.java` | Mock response codes/bodies and avoid unreviewed wire-shape changes | Yes |
| Database migrations | Schema drift can break JPA queries and startup | `PersistenceConfiguration.java`, `V6__AnalysisStudyTerminology.sql` | Add new Flyway migrations; verify on PostgreSQL | Yes |
| Secrets and config | Keycloak, database, registry, and mirror credentials must stay private | `application.yml`, `.github/workflows/*` | Never print or commit secrets; review env/config changes carefully | Yes |
| Logging sensitive data | Request bodies, results, or tokens may include sensitive values | `Logger.java`, API/services logging request details | Avoid adding sensitive logs; redact where possible | Yes |
| Release publishing | Workflow pushes public/private images on release | `.github/workflows/publish_images.yml` | Review registry targets, tags, cache, and secret usage | Yes |
| Repository mirroring | Mirror workflow can publish refs to EBRAINS GitLab | `.github/workflows/ebrains.yml` | Review branch/tag triggers and token usage | Yes |
| Dependency updates | Framework/security/library upgrades can change runtime behavior | `pom.xml` | Explain need, run Maven checks, and consider Docker build | Yes |
| Token-heavy tool output | Broad file dumps, full logs, or unbounded diffs can exhaust agent context and hide relevant facts | Agent workflow instructions in `AGENTS.md` and `docs/context/conventions.md` | Use bounded searches and summaries; require approval before high-output commands | Yes |
