package hbp.mip.algorithm;

import hbp.mip.configurations.ExaflowAmqpConfiguration;
import hbp.mip.configurations.ExaflowTransportConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.rabbit.AsyncRabbitTemplate;
import org.springframework.amqp.rabbit.connection.AbstractConnectionFactory;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.connection.ConnectionNameStrategy;
import org.springframework.amqp.rabbit.listener.SimpleMessageListenerContainer;
import org.springframework.boot.amqp.autoconfigure.RabbitAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ExaflowAmqpTransportConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(context -> context.getBeanFactory()
                    .setConversionService(ApplicationConversionService.getSharedInstance()))
            .withConfiguration(AutoConfigurations.of(RabbitAutoConfiguration.class))
            .withUserConfiguration(ExaflowAmqpConfiguration.class, ExaflowAmqpClient.class,
                    ExaflowTransportConfiguration.class, PlaceholderConfig.class);

    private final ApplicationContextRunner validator = new ApplicationContextRunner()
            .withInitializer(context -> context.getBeanFactory()
                    .setConversionService(ApplicationConversionService.getSharedInstance()))
            .withUserConfiguration(ExaflowTransportConfiguration.class);

    @Configuration(proxyBeanMethods = false)
    static class PlaceholderConfig {
        @Bean
        static PropertySourcesPlaceholderConfigurer placeholderConfigurer() {
            return new PropertySourcesPlaceholderConfigurer();
        }
    }

    @Test
    void rabbitmqTransport_alwaysWiresPublisherConnectionAndDecodedUri() throws Exception {
        runner.withSystemProperties("RABBITMQ_URL=amqp://guest:p%40ss@127.0.0.1:1/%2F")
                .withPropertyValues(
                        "spring.rabbitmq.addresses=amqp://guest:guest@10.255.255.1:9/%2F",
                        "spring.rabbitmq.publisher-confirm-type=correlated",
                        "spring.rabbitmq.publisher-returns=true",
                        "spring.rabbitmq.connection-timeout=5s",
                        "spring.rabbitmq.channel-rpc-timeout=10s",
                        "spring.rabbitmq.requested-heartbeat=30s",
                        "services.exaflow.rabbitmq.requestQueue=exaflow.analysis.requests",
                        "services.exaflow.rabbitmq.replyQueue=platform-backend.analysis.replies",
                        "services.exaflow.rabbitmq.replyTimeout=PT1H",
                        "services.exaflow.rabbitmq.publishTimeout=PT30S")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(ExaflowAmqpClient.class);
                    assertThat(context).hasSingleBean(ExaflowAmqpConfiguration.class);
                    assertThat(context).hasSingleBean(AsyncRabbitTemplate.class);
                    assertThat(context).hasSingleBean(SimpleMessageListenerContainer.class);
                    assertThat(context).hasSingleBean(Queue.class);
                    AsyncRabbitTemplate async = context.getBean(AsyncRabbitTemplate.class);
                    assertThat(async.getRabbitTemplate().isUsePublisherConnection()).isTrue();
                    assertThat(context.getBean(SimpleMessageListenerContainer.class).isAutoStartup()).isFalse();
                    CachingConnectionFactory caching = context.getBean(CachingConnectionFactory.class);
                    assertThat(context.getBean(ConnectionNameStrategy.class).obtainNewConnectionName(caching))
                            .isEqualTo(ExaflowAmqpConfiguration.CONNECTION_NAME);
                    com.rabbitmq.client.ConnectionFactory client = caching.getRabbitConnectionFactory();
                    assertThat(client.getVirtualHost()).isEqualTo("/");
                    assertThat(client.getHost()).isEqualTo("127.0.0.1");
                    assertThat(client.getPort()).isEqualTo(1);
                    assertThat(client.getUsername()).isEqualTo("guest");
                    assertThat(client.getPassword()).isEqualTo("p@ss");
                    assertThat(client.getRequestedHeartbeat()).isEqualTo(30);
                    assertThat(client.getConnectionTimeout()).isEqualTo(5_000);
                    assertThat(client.getChannelRpcTimeout()).isEqualTo(10_000);
                    assertThat(addressList(caching)).containsExactly("127.0.0.1:1");
                    assertThat(addressList((AbstractConnectionFactory) caching.getPublisherConnectionFactory()))
                            .containsExactly("127.0.0.1:1");
                });
    }

    @Test
    void invalidRabbitUrl_failsWithoutTheUri() {
        runner.withSystemProperties("RABBITMQ_URL=amqp://user:s3cret password@127.0.0.1:1/%2F")
                .withPropertyValues(rabbitProperties("exaflow.analysis.requests",
                        "platform-backend.analysis.replies", "PT1H", "PT30S"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    StringWriter text = new StringWriter();
                    context.getStartupFailure().printStackTrace(new PrintWriter(text));
                    assertThat(text.toString()).contains("RABBITMQ_URL is not a valid AMQP URI");
                    assertThat(text.toString()).doesNotContain("s3cret");
                });
    }

    @Test
    void blankOrIdenticalQueues_failStartup() {
        validator.withPropertyValues(rabbitProperties("  ", "platform-backend.analysis.replies", "PT1H", "PT30S"))
                .run(context -> assertRejected(context,
                        "services.exaflow.rabbitmq.requestQueue and replyQueue must be non-blank and distinct"));
        validator.withPropertyValues(rabbitProperties("same.queue", "same.queue", "PT1H", "PT30S"))
                .run(context -> assertRejected(context,
                        "services.exaflow.rabbitmq.requestQueue and replyQueue must be non-blank and distinct"));
    }

    @Test
    void nonPositiveTimeouts_failStartup() {
        validator.withPropertyValues(rabbitProperties("exaflow.analysis.requests",
                        "platform-backend.analysis.replies", "PT0S", "PT30S"))
                .run(context -> assertRejected(context,
                        "services.exaflow.rabbitmq.replyTimeout and publishTimeout must be strictly positive"));
        validator.withPropertyValues(rabbitProperties("exaflow.analysis.requests",
                        "platform-backend.analysis.replies", "PT1H", "-PT1S"))
                .run(context -> assertRejected(context,
                        "services.exaflow.rabbitmq.replyTimeout and publishTimeout must be strictly positive"));
    }

    @Test
    void applyRabbitUrl_decodesPasswordAndDefaultVhost() {
        var factory = new com.rabbitmq.client.ConnectionFactory();
        ExaflowAmqpConfiguration.applyRabbitUrl(factory, "amqp://user:a%2Fb@127.0.0.1:5672/%2F");
        assertThat(factory.getVirtualHost()).isEqualTo("/");
        assertThat(factory.getPassword()).isEqualTo("a/b");
        assertThat(factory.getUsername()).isEqualTo("user");
        assertThat(factory.getHost()).isEqualTo("127.0.0.1");
        assertThat(factory.getPort()).isEqualTo(5672);
    }

    private static String[] rabbitProperties(String requestQueue, String replyQueue, String replyTimeout,
            String publishTimeout) {
        return new String[] {
                "services.exaflow.rabbitmq.requestQueue=" + requestQueue,
                "services.exaflow.rabbitmq.replyQueue=" + replyQueue,
                "services.exaflow.rabbitmq.replyTimeout=" + replyTimeout,
                "services.exaflow.rabbitmq.publishTimeout=" + publishTimeout
        };
    }

    private static void assertRejected(org.springframework.boot.test.context.assertj.AssertableApplicationContext context,
            String message) {
        assertThat(context).hasFailed();
        assertThat(context.getStartupFailure()).rootCause().hasMessage(message);
    }

    @SuppressWarnings("unchecked")
    private static List<String> addressList(AbstractConnectionFactory factory) throws Exception {
        Field field = AbstractConnectionFactory.class.getDeclaredField("addresses");
        field.setAccessible(true);
        var addresses = (List<com.rabbitmq.client.Address>) field.get(factory);
        return addresses.stream().map(Object::toString).toList();
    }
}
