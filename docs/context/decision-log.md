# Decision Log

Use this file for durable architectural decisions.

## Template

### Decision: <title>

Status: Proposed / Accepted / Deprecated

Context:

Decision:

Consequences:

Files affected:

Date:

## Inferred / Verify Decisions

### Decision: Use Spring Boot and Maven for the backend service

Status: Inferred / verify

Context: `pom.xml` defines a Spring Boot parent, Java 21, and jar packaging.

Decision: Build and run the backend as a Spring Boot Maven application.

Consequences: Java compilation and packaging use Maven commands; application behavior is driven by Spring configuration.

Files affected: `pom.xml`, `src/main/java/hbp/mip/MIPApplication.java`

Date: Unknown / TODO: verify

### Decision: Use Flyway migrations with Hibernate schema validation

Status: Inferred / verify

Context: `PersistenceConfiguration` creates a Flyway bean and `application.yml` configures `spring.jpa.hibernate.ddl-auto: validate`.

Decision: Schema changes should be applied through Flyway and validated by Hibernate at startup.

Consequences: Do not edit shipped migrations; add new migration files for schema changes.

Files affected: `src/main/resources/db/migration`, `src/main/java/hbp/mip/configurations/PersistenceConfiguration.java`

Date: Unknown / TODO: verify

### Decision: Support both browser OAuth2 login and bearer JWT API clients

Status: Inferred / verify

Context: `SecurityConfiguration` configures `oauth2Login` and `oauth2ResourceServer().jwt(...)`.

Decision: Keep session-based frontend login and token-based API client access working together.

Consequences: Auth changes must verify both flows and CSRF behavior.

Files affected: `src/main/java/hbp/mip/configurations/SecurityConfiguration.java`, `src/main/java/hbp/mip/user/ActiveUserAPI.java`

Date: Unknown / TODO: verify

### Decision: Keep every pinned dependency on the newest stable release

Status: Verified

Context: The SCA gate (`.github/workflows/sca.yml`, Trivy + osv-scanner over the CycloneDX SBOM) reported one finding on the pre-bump dependency set: `tools.jackson.core:jackson-databind:3.1.4` (CVE-2026-59889 / GHSA-5gvw-p9qm-jgwh, CVSS 6.5), pulled in transitively by Flyway and pinned by the `jackson-bom.version` property.

Decision: Bump `pom.xml` to the newest stable releases across the board (Boot parent 4.1.1, Hibernate 7.4.8.Final, Flyway 13.6.0, springdoc 3.1.1, PostgreSQL JDBC 42.7.13, Jackson BOMs 2.22.2 / 3.2.2) and keep the Tomcat 11.0.25 override, because Boot 4.1.1 still manages the vulnerable 11.0.24. Prereleases (Boot 4.2.0-M1, Hibernate 8.0.0.Beta1, Jakarta Persistence 4.0.0-M6) are intentionally excluded.

Consequences: The obsolete Jackson suppressions were deleted from `ci/suppress_osv_scanner.toml` and `ci/suppress_trivy.yaml`. Flyway 12 to 13 is a major jump and only the programmatic `Flyway.configure()` API in `PersistenceConfiguration` is used, so migration behaviour against PostgreSQL still needs a human check on a real database.

Validation: `mvn clean package` passed 62/62 tests. Regenerated SBOM scanned with the CI-pinned scanners: osv-scanner and Trivy both report 0 findings and no unused ignores (pre-bom baseline: 1 finding each).

Files affected: `pom.xml`, `ci/suppress_osv_scanner.toml`, `ci/suppress_trivy.yaml`, `ci/setup-tools.sh`, `.github/workflows/sca.yml`, `.github/workflows/sast.yml`, `.github/workflows/container-scan.yml`

Date: 2026-09-15

### Decision: Keep CI security tooling and pinned GitHub Actions current

Status: Verified locally / needs one CI run

Context: The SCA, SAST and container pipelines install release assets by exact version plus SHA256 (`ci/setup-tools.sh`) and the workflows pin actions by commit SHA, so both drift silently.

Decision: Bumped Trivy v0.71.1 -> v0.74.0, osv-scanner v2.4.0 -> v2.5.1, OpenGrep v1.25.0 -> v1.30.0, Hadolint v2.14.0 -> v2.15.1, `@cyclonedx/cyclonedx-npm` 6.0.0 -> 6.0.1, workflow Python 3.14.4 -> 3.14.7, and the action pins `actions/checkout` v6.0.3 -> v7.0.1, `actions/setup-python` v6.2.0 -> v7.0.0, `github/codeql-action/upload-sarif` v2.25.6 -> v4.38.0, `docker/setup-buildx-action` v4.2.0 -> v4.3.0, `docker/login-action` v4.5.2 -> v4.6.0. New SHA256 values were computed from the same release assets the script downloads. osv-scanner stays on v2.5.1 rather than v2.6.0 because v2.6.0 is younger than the 7-day `minimumReleaseAge` policy in `renovate.json`.

Consequences: All new checksums must match the assets GitHub downloads, or `ci/setup-tools.sh` fails fast. `upload-sarif` v4.38.0 keeps the same inputs but runs on node24 instead of the EOL node16. Latest `semgrep-rules` (not bumped here) reports ERROR-level `dockerfile-source-not-pinned` findings on this Dockerfile, so bumping `SEMGREP_RULES_REF` will fail the container SAST gate until the `FROM` lines are digest-pinned.

Validation: Ran each upgraded tool with the exact command lines from `ci/sca_scan.py` and `ci/container_scan.py`: Trivy and osv-scanner report 0 findings on the regenerated SBOM, Hadolint passes `--failure-threshold error`, and OpenGrep v1.30.0 passes the `--severity=ERROR --error` gate against the pinned rules ref. `docker build` and the workflow runner behaviour could not be checked locally (no Docker daemon).

Files affected: `ci/setup-tools.sh`, `.github/workflows/sca.yml`, `.github/workflows/sast.yml`, `.github/workflows/container-scan.yml`, `.github/workflows/publish_images.yml`

Date: 2026-09-15
