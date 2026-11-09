#######################################################
# Build the spring boot maven project
#######################################################
# Digest is the multi-arch index for this tag (registry, 2026-11-09).
FROM maven:3.9.16-amazoncorretto-21@sha256:efdf660ec74911594e2a7f642e177ffba21b741c8e848223bf41a6d0fc367692 AS mvn-build-env
LABEL maintainer="Thanasis Karampatsis <tkarabatsis@athenarc.gr>"

ENV CODE_PATH="/opt/code"
WORKDIR $CODE_PATH

COPY pom.xml $CODE_PATH/

# Pre-fetch dependencies first to improve build cache efficiency.
RUN mvn -B -ntp dependency:go-offline

COPY src/ $CODE_PATH/src

RUN mvn -B -ntp clean package

#######################################################
# Setup the running container
#######################################################
# Digest is the multi-arch index for this tag (registry, 2026-11-09).
FROM amazoncorretto:21-alpine3.24@sha256:e37320b8ccdb61ed4272edf1f3c9836ca4ea660b37f048dbb6858901d5322145

#######################################################
# Setting up timezone
#######################################################
ENV TZ=Etc/GMT
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

#######################################################
# Setting up environment
#######################################################
ENV SERVICE="platform-backend"
ENV FEDERATION="default"
ENV LOG_LEVEL="INFO"
ENV FRAMEWORK_LOG_LEVEL="INFO"

WORKDIR /opt

# Pin Alpine 3.24 versions. openssl 3.5.9-r0 is past 3.5.8-r0, which fixed
# CVE-2026-14456, CVE-2026-63073 and CVE-2026-75803. The base image may still
# ship the older build, so install these explicitly.
RUN apk add --no-cache \
    libcrypto3=3.5.9-r0 \
    libssl3=3.5.9-r0 \
    curl=8.23.0-r0

#######################################################
# Prepare the spring boot application files
#######################################################
COPY --from=mvn-build-env /opt/code/target/platform-backend.jar /usr/share/jars/

VOLUME /opt/platform/api

RUN addgroup -g 10001 appgroup && adduser -D -H -u 10001 -G appgroup appuser \
    && mkdir -p /opt/platform/api \
    && chown -R 10001:10001 /opt/platform/api /usr/share/jars

USER 10001
ENTRYPOINT ["java", "--add-opens", "java.base/java.io=ALL-UNNAMED", "-Daeron.term.buffer.length", "-jar", "/usr/share/jars/platform-backend.jar"]
EXPOSE 8080
HEALTHCHECK --start-period=60s CMD ["sh", "-c", "set -o pipefail; curl --fail --silent --show-error http://localhost:8080/services/actuator/health | grep -q '\"status\":\"UP\"'"]
