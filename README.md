[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.html)
[![DockerHub](https://img.shields.io/badge/docker-hbpmip%2Fplatform--backend-008bb8.svg)](https://hub.docker.com/r/hbpmip/platform-backend/)

# Backend for the MIP platform

## DEV Deployment
To run the backend using an IDE for development, such as IntelliJ, you need a running instance of PostgreSQL.

## Deployment (using a Docker image)
Build the image: `docker build -t hbpmip/platform-backend:testing .`

To use this image, you need a running instance of PostgreSQL and to configure the software using the following environment variables.

#### LOG LEVELS ###
* LOG_LEVEL: log level for the developer added logs. Default is "ERROR".
* LOG_LEVEL_FRAMEWORK: log level for all the framework logs. Default is "ERROR".

#### AUTHENTICATION ###
* AUTHENTICATION: true for production, false for development.
* `authentication.all_analyses_allowed_claim`: defaults to the existing external authority `research_experiment_all`. Preserve that authority and existing grants.

#### DATABASE CONFIGURATION ###
* PLATFORM_DB_URL: JDBC URL to connect to the platform database, default value is "jdbc:postgresql://127.0.0.1:5432/platform".
* PLATFORM_DB_SCHEMA: Database schema, default value is "public".
* PLATFORM_DB_USER: User to use when connecting to the platform database, default value is "postgres".
* PLATFORM_DB_PASSWORD: Password to use when connecting to the platform database.

#### EXTERNAL SERVICES ###
* EXAFLOW_URL: URL to Exaflow server. Default is "http://localhost:5000". Specifications, data models, and metadata use this HTTP URL.
* RABBITMQ_URL: AMQP URI (`amqp[s]://user:pass@host:port/vhost`) for the analysis broker. Default is "amqp://127.0.0.1:5672". Analysis execution is submitted over RabbitMQ and requires an Exaflow build that includes madgik/exaflow#673 and madgik/exaflow#681 with its RabbitMQ consumer enabled.
* EXAFLOW_RABBITMQ_REQUEST_QUEUE: Exaflow-owned analysis request queue. Default is "exaflow.analysis.requests".
* EXAFLOW_RABBITMQ_REPLY_QUEUE: Durable reply queue this backend declares. Default is "platform-backend.analysis.replies". One name per deployment; a single replica is assumed.
* EXAFLOW_RABBITMQ_REPLY_TIMEOUT: How long to wait for a correlated reply, as an ISO-8601 duration. Default is "PT1H".
* EXAFLOW_RABBITMQ_PUBLISH_TIMEOUT: How long to wait for the broker consumer check, publish, and publisher confirm, as an ISO-8601 duration. Default is "PT30S".

The request and reply queues must be non-blank and different, and both timeouts must be positive; invalid values stop startup.

`RABBITMQ_URL` is parsed with the RabbitMQ Java client (`ConnectionFactory.setUri`), the same rules Exaflow uses. `%2F` is the default virtual host, and percent-encoded passwords are decoded. Do not copy that URI into `spring.rabbitmq.addresses`: Spring Boot does not decode `%XX` and would override the host, port, and virtual host. The broker TCP connection timeout is 5 seconds, the channel RPC timeout is 10 seconds, and the requested heartbeat is 30 seconds, matching Exaflow.

Analysis transport failures are HTTP responses with a fixed message:
* 503 when the broker cannot take the request. That includes the broker being down, the request queue missing, a preview request (`POST /analyses/preview`) when the queue has no consumer, a stalled or failed publish, a nacked or returned publish, a timeout before broker confirmation, and shutdown while a submit is waiting. Message: "The analysis service is not available right now. Please try again later or inform the system administrator."
* 504 when the broker confirmed the publish and no reply arrives within `EXAFLOW_RABBITMQ_REPLY_TIMEOUT`. Message: "The analysis did not finish in time. Please try again later or inform the system administrator."

Transient preview requests (`POST /analyses/preview`) check `consumer_count == 0` and fail immediately with 503 so they do not wait during an Exaflow restart. Normal analysis runs (`POST /analyses/runs`) skip the consumer check and queue in RabbitMQ (a missing request queue still fails immediately with 503 via `mandatory` return).

#### ANALYSES ###
* ANALYSIS_RUN_DRAFT_TTL: How long an unsaved studio run can still be saved without re-running it, as an ISO-8601 duration. Default is "PT24H".

The backend uses Analysis, Study, and Analysis Group terminology. See the [module index](docs/context/module-index.md) for API and persistence details. Run `mvn test`, `mvn -Ppostgres-integration verify` against a disposable PostgreSQL database, and `mvn clean package`; connection settings are in [the testing guide](docs/context/testing.md).

#### KEYCLOAK ###
* KEYCLOAK_AUTH_URL: Keycloak authentication URL.
* KEYCLOAK_REALM: Keycloak realm user for authentication.
* KEYCLOAK_CLIENT_ID: The keycloak client id.
* KEYCLOAK_CLIENT_SECRET: The keycloak secret to be able to authenticate.
* KEYCLOAK_CLI_CLIENT_ID: Public Keycloak client (device flow) for `mip login` on users' own computers. Empty (default): not offered.

# Acknowledgement
This project/research received funding from the European Union’s Horizon 2020 Framework Programme for Research and Innovation under the Framework Partnership Agreement No. 650003 (HBP FPA).
