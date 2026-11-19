package hbp.mip.configurations;

import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.rabbit.AsyncRabbitTemplate;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.connection.ConnectionNameStrategy;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.listener.SimpleMessageListenerContainer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.amqp.autoconfigure.ConnectionFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

@Configuration
public class ExaflowAmqpConfiguration {

    public static final String CONNECTION_NAME = "platform-backend-exaflow";

    // Note: single replica shares this reply queue. Multiple replicas need a per-instance EXAFLOW_RABBITMQ_REPLY_QUEUE.
    @Bean
    public Queue exaflowAnalysisReplyQueue(@Value("${services.exaflow.rabbitmq.replyQueue}") String name) {
        return replyQueue(name);
    }

    public static Queue replyQueue(String name) {
        return QueueBuilder.durable(name)
                .withArgument("x-queue-type", "quorum")
                .withArgument("x-max-length-bytes", 268435456)
                .withArgument("x-overflow", "reject-publish")
                .build();
    }

    @Bean
    public ConnectionNameStrategy exaflowConnectionNameStrategy() {
        return connectionFactory -> CONNECTION_NAME;
    }

    /**
     * {@code spring.rabbitmq.addresses} does not decode {@code %XX}. Publishing uses
     * {@link com.rabbitmq.client.ConnectionFactory#setUri} on {@code RABBITMQ_URL} instead.
     * Parse errors stay free of the URI, which contains the password.
     */
    @Bean
    public static ConnectionFactoryCustomizer exaflowRabbitUri(
            @Value("${RABBITMQ_URL:amqp://127.0.0.1:5672}") String rabbitUrl) {
        return factory -> applyRabbitUrl(factory, rabbitUrl);
    }

    /**
     * Boot applies addresses after customizers, as {@code host:port} only. That list overrides
     * the host and port from {@code setUri}. Put the decoded host and port back, including on the
     * publisher connection.
     */
    @Bean
    public static BeanPostProcessor exaflowRabbitAddressAligner(
            @Value("${RABBITMQ_URL:amqp://127.0.0.1:5672}") String rabbitUrl) {
        com.rabbitmq.client.ConnectionFactory parsed = new com.rabbitmq.client.ConnectionFactory();
        applyRabbitUrl(parsed, rabbitUrl);
        String address = parsed.getHost() + ":" + parsed.getPort();
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof CachingConnectionFactory caching) {
                    applyRabbitUrl(caching.getRabbitConnectionFactory(), rabbitUrl);
                    caching.setAddresses(address);
                }
                return bean;
            }
        };
    }

    public static void applyRabbitUrl(com.rabbitmq.client.ConnectionFactory factory, String rabbitUrl) {
        try {
            factory.setUri(rabbitUrl);
        } catch (IllegalArgumentException | URISyntaxException | NoSuchAlgorithmException
                | KeyManagementException ex) {
            throw new IllegalStateException("RABBITMQ_URL is not a valid AMQP URI");
        }
    }

    @Bean
    public SimpleMessageListenerContainer exaflowReplyContainer(ConnectionFactory connectionFactory,
            @Value("${services.exaflow.rabbitmq.replyQueue}") String replyQueue) {
        return replyContainer(connectionFactory, replyQueue);
    }

    public static SimpleMessageListenerContainer replyContainer(ConnectionFactory connectionFactory, String replyQueue) {
        SimpleMessageListenerContainer container = new SimpleMessageListenerContainer(connectionFactory);
        container.setQueueNames(replyQueue);
        // Broker down, or the queue not declared yet, must not fail context startup.
        container.setMissingQueuesFatal(false);
        // The container stays a bean so RabbitAdmin is wired. AsyncRabbitTemplate starts and stops it.
        container.setAutoStartup(false);
        return container;
    }

    @Bean
    public AsyncRabbitTemplate exaflowAsyncRabbitTemplate(ConnectionFactory connectionFactory,
            SimpleMessageListenerContainer exaflowReplyContainer,
            @Value("${services.exaflow.rabbitmq.replyQueue}") String replyQueue,
            @Value("${services.exaflow.rabbitmq.replyTimeout}") Duration replyTimeout) {
        return wire(new RabbitTemplate(connectionFactory), exaflowReplyContainer, replyQueue, replyTimeout);
    }

    public static AsyncRabbitTemplate asyncTemplate(ConnectionFactory connectionFactory, String replyQueue,
            Duration replyTimeout) {
        return wire(new RabbitTemplate(connectionFactory), replyContainer(connectionFactory, replyQueue), replyQueue,
                replyTimeout);
    }

    private static AsyncRabbitTemplate wire(RabbitTemplate rabbitTemplate, SimpleMessageListenerContainer container,
            String replyQueue, Duration replyTimeout) {
        // A broker memory alarm blocks publishes. Keep that off the connection that acks replies.
        rabbitTemplate.setUsePublisherConnection(true);
        AsyncRabbitTemplate async = new AsyncRabbitTemplate(rabbitTemplate, container, replyQueue);
        async.setMandatory(true);
        async.setEnableConfirms(true);
        async.setReceiveTimeout(replyTimeout.toMillis());
        return async;
    }
}
