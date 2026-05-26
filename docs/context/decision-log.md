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
