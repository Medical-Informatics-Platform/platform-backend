# Risk Register

| Area | Risk | Evidence | Agent guidance | Human review required? |
|---|---|---|---|---|
| Authentication and OAuth2 | Login, logout, JWT, CSRF, and session behavior can lock users out or weaken protection | `SecurityConfiguration.java`, `SpaRedirectAuthenticationSuccessHandler.java`, `FrontendRedirectCaptureFilter.java` | Add focused tests and manually review auth flows before changing | Yes |
| Authority and claim mapping | Dataset/experiment access depends on raw authority strings and Keycloak claims | `SecurityConfiguration.java`, `ClaimUtils.java` | Do not add `ROLE_` prefixes or rename claims without migration/compat notes | Yes |
| Active user token endpoint | `/activeUser/token` can expose access tokens to authenticated callers | `ActiveUserAPI.java` | Do not broaden access, log token values, or change response semantics without review | Yes |
| Dataset authorization | Users may see unauthorized pathologies or datasets if filtering changes | `DataModelService.java`, `ClaimUtils.java` | Cover authenticated and authentication-disabled behavior | Yes |
| Experiment authorization | Owners/shared/admin-like access rules protect experiment read/update/delete | `ExperimentService.java`, `ExperimentSpecifications.java` | Test owner, shared, not-owner, and all-experiments authority cases | Yes |
| Experiment deletion | Deletion is destructive and authorization-sensitive | `ExperimentAPI.java`, `ExperimentService.java` | Require focused tests and rollback/restore discussion for behavior changes | Yes |
| Experiment execution | Background thread updates status/result after Exaflow execution | `ExperimentService.java` | Preserve pending/success/error transitions and repository finish behavior | Yes |
| Exaflow external APIs | Runtime depends on external service contracts and availability | `AlgorithmService.java`, `DataModelService.java`, `ExperimentService.java`, `HTTPUtil.java` | Mock response codes/bodies and avoid unreviewed wire-shape changes | Yes |
| Database migrations | Schema drift can break startup because Hibernate validates schema | `PersistenceConfiguration.java`, `V1__InitialSchema.sql` | Add new Flyway migrations; verify on PostgreSQL | Yes |
| Secrets and config | Keycloak, database, registry, and mirror credentials must stay private | `application.yml`, `config/application.tmpl`, `.github/workflows/*` | Never print or commit secrets; review env/template changes carefully | Yes |
| Logging sensitive data | Request bodies, results, or tokens may include sensitive values | `Logger.java`, API/services logging request details | Avoid adding sensitive logs; redact where possible | Yes |
| Release publishing | Workflow pushes public/private images on release | `.github/workflows/publish_images.yml` | Review registry targets, tags, cache, and secret usage | Yes |
| Repository mirroring | Mirror workflow can publish refs to EBRAINS GitLab | `.github/workflows/ebrains.yml` | Review branch/tag triggers and token usage | Yes |
| Dependency updates | Framework/security/library upgrades can change runtime behavior | `pom.xml` | Explain need, run Maven checks, and consider Docker build | Yes |
| Token-heavy tool output | Broad file dumps, full logs, or unbounded diffs can exhaust agent context and hide relevant facts | Agent workflow instructions in `AGENTS.md` and `docs/context/conventions.md` | Use bounded searches and summaries; require approval before high-output commands | Yes |
