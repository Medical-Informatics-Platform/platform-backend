package hbp.mip.configurations;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.time.Duration;

/**
 * Validates the Exaflow RabbitMQ analysis transport settings at startup.
 */
@Configuration
public class ExaflowTransportConfiguration {

    public ExaflowTransportConfiguration(
            @Value("${services.exaflow.rabbitmq.requestQueue:exaflow.analysis.requests}") String requestQueue,
            @Value("${services.exaflow.rabbitmq.replyQueue:platform-backend.analysis.replies}") String replyQueue,
            @Value("${services.exaflow.rabbitmq.replyTimeout:PT1H}") Duration replyTimeout,
            @Value("${services.exaflow.rabbitmq.publishTimeout:PT30S}") Duration publishTimeout) {
        if (!StringUtils.hasText(requestQueue) || !StringUtils.hasText(replyQueue) || requestQueue.equals(replyQueue)) {
            throw new IllegalStateException(
                    "services.exaflow.rabbitmq.requestQueue and replyQueue must be non-blank and distinct");
        }
        if (!replyTimeout.isPositive() || !publishTimeout.isPositive()) {
            throw new IllegalStateException(
                    "services.exaflow.rabbitmq.replyTimeout and publishTimeout must be strictly positive");
        }
    }
}
