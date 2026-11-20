package hbp.mip.algorithm;

import com.google.gson.JsonParser;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.Delivery;
import hbp.mip.configurations.ExaflowAmqpConfiguration;
import hbp.mip.configurations.ExaflowTransportConfiguration;
import hbp.mip.utils.Exceptions.GatewayTimeoutException;
import hbp.mip.utils.Exceptions.ServiceUnavailableException;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.rabbit.AsyncRabbitTemplate;
import org.springframework.amqp.rabbit.connection.AbstractConnectionFactory;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.boot.amqp.autoconfigure.RabbitAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

import java.lang.reflect.Field;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@EnabledIfEnvironmentVariable(named = "RABBITMQ_TEST_URL", matches = ".+")
class ExaflowAmqpClientBrokerTest {

    private static final String UNAVAILABLE =
            "The analysis service is not available right now. Please try again later or inform the system administrator.";
    private static final String TIMED_OUT =
            "The analysis did not finish in time. Please try again later or inform the system administrator.";

    private com.rabbitmq.client.ConnectionFactory rabbit;
    private CachingConnectionFactory connectionFactory;
    private String requestQueue;
    private String replyQueue;
    private AsyncRabbitTemplate template;
    private final List<ExaflowAmqpClient> clients = new ArrayList<>();
    private Connection responderConnection;
    private Channel consumeChannel;
    private ExecutorService responderPool;
    private final AtomicReference<Throwable> responderError = new AtomicReference<>();

    @BeforeEach
    void connectAndDeclareReplyQueue() throws Exception {
        rabbit = new com.rabbitmq.client.ConnectionFactory();
        rabbit.setUri(System.getenv("RABBITMQ_TEST_URL"));
        connectionFactory = new CachingConnectionFactory(rabbit);
        connectionFactory.setPublisherConfirmType(CachingConnectionFactory.ConfirmType.CORRELATED);
        connectionFactory.setPublisherReturns(true);
        String suffix = UUID.randomUUID().toString();
        requestQueue = "exaflow.analysis.requests." + suffix;
        replyQueue = "platform-backend.analysis.replies." + suffix;
        new RabbitAdmin(connectionFactory).declareQueue(ExaflowAmqpConfiguration.replyQueue(replyQueue));
    }

    @AfterEach
    void tearDown() throws Exception {
        for (ExaflowAmqpClient client : clients) {
            client.close();
        }
        clients.clear();
        if (template != null) {
            template.stop();
        }
        if (consumeChannel != null) {
            consumeChannel.close();
        }
        if (responderConnection != null) {
            responderConnection.close();
        }
        if (responderPool != null) {
            responderPool.shutdownNow();
        }
        try (Connection connection = rabbit.newConnection(); Channel channel = connection.createChannel()) {
            channel.queueDelete(requestQueue);
            channel.queueDelete(replyQueue);
        } catch (Exception ignored) {
            // The queue was never declared, or the broker is already gone.
        }
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class PlaceholderConfig {
        @Bean
        static PropertySourcesPlaceholderConfigurer placeholderConfigurer() {
            return new PropertySourcesPlaceholderConfigurer();
        }
    }

    @Test
    void submit_returnsCorrelatedReply() throws Exception {
        var seen = new AtomicReference<Delivery>();
        startResponder(delivery -> {
            seen.set(delivery);
            reply(delivery, "{\"status\":\"succeeded\",\"result\":{\"ok\":1}}");
        });
        String requestId = UUID.randomUUID().toString();
        Duration replyTimeout = Duration.ofSeconds(30);

        ExaflowAmqpClient.ExaflowReply reply = client(replyTimeout, Duration.ofSeconds(10))
                .submit(requestId, body(requestId), new Logger("user", "test"));

        assertThat(reply).isEqualTo(new ExaflowAmqpClient.ExaflowReply(200, "{\"ok\":1}"));
        Delivery delivery = seen.get();
        assertThat(delivery).isNotNull();
        AMQP.BasicProperties properties = delivery.getProperties();
        assertThat(properties.getCorrelationId()).isEqualTo(requestId);
        assertThat(JsonParser.parseString(new String(delivery.getBody(), StandardCharsets.UTF_8))
                .getAsJsonObject().get("request_id").getAsString()).isEqualTo(requestId);
        assertThat(properties.getContentType()).isEqualTo("application/json");
        assertThat(properties.getContentEncoding()).isEqualTo("UTF-8");
        assertThat(properties.getDeliveryMode()).isEqualTo(2);
        assertThat(properties.getReplyTo()).isEqualTo(replyQueue);
        assertThat(properties.getExpiration()).isEqualTo(String.valueOf(replyTimeout.toMillis()));
        assertThat(responderError.get()).isNull();
    }

    @Test
    void submit_withoutRequestQueue_failsFast() {
        Duration replyTimeout = Duration.ofSeconds(30);
        long started = System.nanoTime();

        assertThatThrownBy(() -> client(replyTimeout, Duration.ofSeconds(5))
                .submit(UUID.randomUUID().toString(), body("ignored"), new Logger("user", "test")))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessage(UNAVAILABLE);

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(10));
    }

    @Test
    void submit_withQueueButNoConsumer_failsFastWhenConsumerRequired() throws Exception {
        try (Connection connection = rabbit.newConnection(); Channel channel = connection.createChannel()) {
            channel.queueDeclare(requestQueue, true, false, false, null);
        }
        Duration replyTimeout = Duration.ofSeconds(30);
        long started = System.nanoTime();

        assertThatThrownBy(() -> client(replyTimeout, Duration.ofSeconds(5))
                .submit(UUID.randomUUID().toString(), body("ignored"), true, new Logger("user", "test")))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessage(UNAVAILABLE);

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(5));
    }

    @Test
    void submit_withoutConsumerCheck_missingQueue_failsFastViaMandatoryReturn() {
        Duration replyTimeout = Duration.ofSeconds(30);
        long started = System.nanoTime();

        assertThatThrownBy(() -> client(replyTimeout, Duration.ofSeconds(5))
                .submit(UUID.randomUUID().toString(), body("ignored"), false, new Logger("user", "test")))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessage(UNAVAILABLE);

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(10));
    }

    @Test
    void submit_withoutConsumerCheck_queuesUntilConsumerJoins() throws Exception {
        try (Connection connection = rabbit.newConnection(); Channel channel = connection.createChannel()) {
            channel.queueDeclare(requestQueue, true, false, false, null);
        }
        String requestId = UUID.randomUUID().toString();
        ExaflowAmqpClient client = client(Duration.ofSeconds(30), Duration.ofSeconds(10));
        ExecutorService callers = Executors.newSingleThreadExecutor();
        try {
            Future<ExaflowAmqpClient.ExaflowReply> pendingReply = callers.submit(
                    () -> client.submit(requestId, body(requestId), false, new Logger("user", "test")));

            // Wait until the message is buffered in RabbitMQ while consumer_count == 0.
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            try (Connection connection = rabbit.newConnection(); Channel channel = connection.createChannel()) {
                while (channel.queueDeclarePassive(requestQueue).getMessageCount() == 0) {
                    assertThat(System.nanoTime()).isLessThan(deadline);
                    Thread.sleep(50);
                }
            }

            // Now attach the consumer; the queued run must be picked up and succeed.
            startResponder(delivery -> reply(delivery, succeeded(delivery.getProperties().getCorrelationId())));

            ExaflowAmqpClient.ExaflowReply reply = pendingReply.get(20, TimeUnit.SECONDS);
            assertThat(reply.code()).isEqualTo(200);
            assertThat(JsonParser.parseString(reply.body()).getAsJsonObject().get("id").getAsString())
                    .isEqualTo(requestId);
        } finally {
            callers.shutdownNow();
        }
        assertThat(responderError.get()).isNull();
    }

    @Test
    void submit_timesOut() throws Exception {
        startResponder(delivery -> {
            // Consume the request and never reply.
        });

        assertThatThrownBy(() -> client(Duration.ofSeconds(1), Duration.ofSeconds(5))
                .submit(UUID.randomUUID().toString(), body("ignored"), new Logger("user", "test")))
                .isInstanceOf(GatewayTimeoutException.class)
                .hasMessage(TIMED_OUT);
        assertThat(pending(template)).isEmpty();
    }

    @Test
    void lateAndDuplicateReplies_areDropped() throws Exception {
        String first = UUID.randomUUID().toString();
        String second = UUID.randomUUID().toString();
        var releaseLateReply = new CountDownLatch(1);
        startResponder(delivery -> responderPool.submit(() -> {
            try {
                String correlationId = delivery.getProperties().getCorrelationId();
                if (first.equals(correlationId)) {
                    assertThat(releaseLateReply.await(20, TimeUnit.SECONDS)).isTrue();
                    reply(delivery, succeeded(correlationId));
                    reply(delivery, succeeded(correlationId));
                } else {
                    reply(delivery, succeeded(correlationId));
                }
            } catch (Exception e) {
                responderError.set(e);
            }
        }));
        ExaflowAmqpClient client = client(Duration.ofSeconds(1), Duration.ofSeconds(5));

        assertThatThrownBy(() -> client.submit(first, body(first), new Logger("user", "test")))
                .isInstanceOf(GatewayTimeoutException.class)
                .hasMessage(TIMED_OUT);
        releaseLateReply.countDown();
        assertThat(waitForQuietReplyQueue()).isTrue();

        ExaflowAmqpClient.ExaflowReply reply = client.submit(second, body(second), new Logger("user", "test"));

        assertThat(reply.code()).isEqualTo(200);
        assertThat(JsonParser.parseString(reply.body()).getAsJsonObject().get("id").getAsString()).isEqualTo(second);
        assertThat(responderError.get()).isNull();
    }

    @Test
    void concurrentSubmits_getOwnReplies() throws Exception {
        startResponder(delivery -> responderPool.submit(() -> {
            try {
                Thread.sleep(ThreadLocalRandom.current().nextInt(201));
                reply(delivery, succeeded(delivery.getProperties().getCorrelationId()));
            } catch (Exception e) {
                responderError.set(e);
            }
        }));
        ExaflowAmqpClient client = client(Duration.ofSeconds(30), Duration.ofSeconds(10));
        List<String> ids = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            ids.add(UUID.randomUUID().toString());
        }
        ExecutorService callers = Executors.newFixedThreadPool(20);
        try {
            List<Future<ExaflowAmqpClient.ExaflowReply>> replies = new ArrayList<>();
            for (String id : ids) {
                replies.add(callers.submit(() -> client.submit(id, body(id), new Logger("user", "test"))));
            }
            for (int i = 0; i < ids.size(); i++) {
                ExaflowAmqpClient.ExaflowReply reply = replies.get(i).get(30, TimeUnit.SECONDS);
                assertThat(reply.code()).isEqualTo(200);
                assertThat(JsonParser.parseString(reply.body()).getAsJsonObject().get("id").getAsString())
                        .isEqualTo(ids.get(i));
            }
        } finally {
            callers.shutdownNow();
        }
        assertThat(responderError.get()).isNull();
    }

    @Test
    void replyQueueDeclaration_matchesConstraints() throws Exception {
        client(Duration.ofSeconds(30), Duration.ofSeconds(5));
        Queue declared = ExaflowAmqpConfiguration.replyQueue(replyQueue);

        try (Connection connection = rabbit.newConnection(); Channel channel = connection.createChannel()) {
            channel.queueDeclarePassive(replyQueue);
            channel.queueDeclare(declared.getName(), declared.isDurable(), declared.isExclusive(),
                    declared.isAutoDelete(), Map.of(
                            "x-queue-type", "quorum",
                            "x-max-length-bytes", 268435456,
                            "x-overflow", "reject-publish"));
        }
    }

    @Test
    void submit_brokerNack_cancelsPendingFuture() throws Exception {
        try (Connection connection = rabbit.newConnection(); Channel channel = connection.createChannel()) {
            channel.queueDeclare(requestQueue, true, false, false, Map.of(
                    "x-queue-type", "classic",
                    "x-max-length", 1,
                    "x-overflow", "reject-publish"));
            var held = new CountDownLatch(1);
            channel.basicQos(1);
            channel.basicConsume(requestQueue, false, (tag, delivery) -> held.countDown(), tag -> {
            });
            // One message is delivered but unacked and held by the consumer; the next stays ready.
            // Together they keep the queue at x-max-length so the confirmed submit gets a nack.
            channel.basicPublish("", requestQueue, null, new byte[] {1});
            assertThat(held.await(10, TimeUnit.SECONDS)).isTrue();
            channel.basicPublish("", requestQueue, null, new byte[] {2});

            ExaflowAmqpClient client = client(Duration.ofHours(1), Duration.ofSeconds(5));
            var logger = new CapturingLogger();
            long started = System.nanoTime();
            assertThatThrownBy(() -> client.submit(UUID.randomUUID().toString(), body("nack"), logger))
                    .isInstanceOf(ServiceUnavailableException.class)
                    .hasMessage(UNAVAILABLE);

            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(5));
            assertThat(logger.errors).anyMatch(line -> line.contains("cause=nack"));
            assertThat(pending(template)).isEmpty();
        }
    }

    @Test
    void submit_unroutablePublish_logsReplyCodeAndDropsPending() throws Exception {
        startResponder(delivery -> {
        });
        ExaflowAmqpClient client = client(Duration.ofHours(1), Duration.ofSeconds(5));
        template.getRabbitTemplate().setExchange("amq.fanout");
        var logger = new CapturingLogger();
        String requestId = UUID.randomUUID().toString();

        assertThatThrownBy(() -> client.submit(requestId, body(requestId), logger))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessage(UNAVAILABLE);

        assertThat(logger.errors).anyMatch(line -> line.contains("cause=AmqpMessageReturnedException replyCode=312"));
        assertThat(logger.errors).noneMatch(line -> line.contains("request_id") || line.contains("{"));
        assertThat(pending(template)).isEmpty();
    }

    @Test
    void submit_whenTemplateStops_isUnavailable() throws Exception {
        var received = new CountDownLatch(1);
        startResponder(delivery -> received.countDown());
        ExaflowAmqpClient client = client(Duration.ofHours(1), Duration.ofSeconds(10));
        var error = new AtomicReference<Throwable>();
        Thread caller = new Thread(() -> {
            try {
                client.submit(UUID.randomUUID().toString(), body("stop"), new Logger("user", "test"));
            } catch (Throwable thrown) {
                error.set(thrown);
            }
        });
        caller.start();
        try {
            assertThat(received.await(10, TimeUnit.SECONDS)).isTrue();
            template.stop();
            caller.join(10_000);
            assertThat(caller.isAlive()).isFalse();
            assertThat(error.get()).isInstanceOf(ServiceUnavailableException.class).hasMessage(UNAVAILABLE);
            assertThat(pending(template)).isEmpty();
        } finally {
            caller.interrupt();
            caller.join(1_000);
        }
    }

    @Test
    void encodedDefaultVhost_declaresReplyQueueThroughSpring() throws Exception {
        String uri = withEncodedDefaultVhost(System.getenv("RABBITMQ_TEST_URL"));
        String springReplyQueue = "platform-backend.analysis.replies." + UUID.randomUUID();
        var runner = new ApplicationContextRunner()
                .withInitializer(context -> context.getBeanFactory()
                        .setConversionService(ApplicationConversionService.getSharedInstance()))
                .withConfiguration(AutoConfigurations.of(RabbitAutoConfiguration.class))
                .withUserConfiguration(ExaflowAmqpConfiguration.class, ExaflowAmqpClient.class,
                        ExaflowTransportConfiguration.class, PlaceholderConfig.class)
                .withSystemProperties("RABBITMQ_URL=" + uri)
                .withPropertyValues(
                        "services.exaflow.rabbitmq.requestQueue=exaflow.analysis.requests." + UUID.randomUUID(),
                        "services.exaflow.rabbitmq.replyQueue=" + springReplyQueue,
                        "services.exaflow.rabbitmq.replyTimeout=PT1H",
                        "services.exaflow.rabbitmq.publishTimeout=PT30S",
                        "spring.rabbitmq.publisher-confirm-type=correlated",
                        "spring.rabbitmq.publisher-returns=true",
                        "spring.rabbitmq.connection-timeout=5s",
                        "spring.rabbitmq.channel-rpc-timeout=10s",
                        "spring.rabbitmq.requested-heartbeat=30s",
                        "spring.rabbitmq.addresses=amqp://guest:guest@10.255.255.1:9/%2F");
        try {
            runner.run(context -> {
                assertThat(context).hasNotFailed();
                CachingConnectionFactory caching = context.getBean(CachingConnectionFactory.class);
                com.rabbitmq.client.ConnectionFactory client = caching.getRabbitConnectionFactory();
                URI parsed = URI.create(uri);
                assertThat(client.getVirtualHost()).isEqualTo("/");
                assertThat(client.getHost()).isEqualTo(parsed.getHost());
                assertThat(client.getPort()).isEqualTo(parsed.getPort());
                assertThat(client.getUsername()).isEqualTo("guest");
                assertThat(client.getRequestedHeartbeat()).isEqualTo(30);
                assertThat(client.getConnectionTimeout()).isEqualTo(5_000);
                assertThat(client.getChannelRpcTimeout()).isEqualTo(10_000);
                assertThat(addressList(caching)).containsExactly(parsed.getHost() + ":" + parsed.getPort());
                assertThat(addressList((AbstractConnectionFactory) caching.getPublisherConnectionFactory()))
                        .containsExactly(parsed.getHost() + ":" + parsed.getPort());
                awaitQueue(springReplyQueue);
                try (Connection connection = rabbit.newConnection(); Channel channel = connection.createChannel()) {
                    channel.queueDeclarePassive(springReplyQueue);
                    Queue declared = ExaflowAmqpConfiguration.replyQueue(springReplyQueue);
                    channel.queueDeclare(declared.getName(), declared.isDurable(), declared.isExclusive(),
                            declared.isAutoDelete(), Map.of(
                                    "x-queue-type", "quorum",
                                    "x-max-length-bytes", 268435456,
                                    "x-overflow", "reject-publish"));
                }
            });
        } finally {
            try (Connection connection = rabbit.newConnection(); Channel channel = connection.createChannel()) {
                channel.queueDelete(springReplyQueue);
            } catch (Exception ignored) {
                // The queue was never declared, or the broker is already gone.
            }
        }
    }

    private ExaflowAmqpClient client(Duration replyTimeout, Duration publishTimeout) {
        template = ExaflowAmqpConfiguration.asyncTemplate(connectionFactory, replyQueue, replyTimeout);
        template.start();
        ExaflowAmqpClient created = new ExaflowAmqpClient(template, requestQueue, replyQueue, replyTimeout,
                publishTimeout);
        clients.add(created);
        return created;
    }

    private void startResponder(Consumer<Delivery> handler) throws Exception {
        responderPool = Executors.newCachedThreadPool();
        responderConnection = rabbit.newConnection("pb-test-responder");
        consumeChannel = responderConnection.createChannel();
        consumeChannel.queueDeclare(requestQueue, true, false, false, null);
        consumeChannel.basicConsume(requestQueue, true, (tag, delivery) -> {
            try {
                handler.accept(delivery);
            } catch (Exception e) {
                responderError.set(e);
            }
        }, tag -> {
        });
    }

    private void reply(Delivery delivery, String json) {
        try (Channel channel = responderConnection.createChannel()) {
            AMQP.BasicProperties properties = new AMQP.BasicProperties.Builder()
                    .correlationId(delivery.getProperties().getCorrelationId())
                    .contentType("application/json")
                    .deliveryMode(2)
                    .build();
            channel.basicPublish("", delivery.getProperties().getReplyTo(), true, properties,
                    json.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private boolean waitForQuietReplyQueue() throws Exception {
        for (int attempt = 0; attempt < 50; attempt++) {
            try (Connection connection = rabbit.newConnection(); Channel channel = connection.createChannel()) {
                if (channel.queueDeclarePassive(replyQueue).getMessageCount() == 0) {
                    return true;
                }
            }
            Thread.sleep(100);
        }
        return false;
    }

    private static String body(String requestId) {
        return "{\"request_id\":\"" + requestId + "\"}";
    }

    private static String succeeded(String requestId) {
        return "{\"status\":\"succeeded\",\"result\":{\"id\":\"" + requestId + "\"}}";
    }

    private static String withEncodedDefaultVhost(String url) {
        int scheme = url.indexOf("://");
        int path = url.indexOf('/', scheme + 3);
        int query = url.indexOf('?');
        int cut = path >= 0 ? path : (query >= 0 ? query : url.length());
        return url.substring(0, cut) + "/%2F";
    }

    private void awaitQueue(String queue) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        Exception last = null;
        while (System.nanoTime() < deadline) {
            try (Connection connection = rabbit.newConnection(); Channel channel = connection.createChannel()) {
                channel.queueDeclarePassive(queue);
                return;
            } catch (Exception e) {
                last = e;
                Thread.sleep(200);
            }
        }
        if (last != null) {
            throw last;
        }
        throw new IllegalStateException("Reply queue was not declared: " + queue);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, ?> pending(AsyncRabbitTemplate async) throws Exception {
        Field field = AsyncRabbitTemplate.class.getDeclaredField("pending");
        field.setAccessible(true);
        return (Map<String, ?>) field.get(async);
    }

    @SuppressWarnings("unchecked")
    private static List<String> addressList(AbstractConnectionFactory factory) throws Exception {
        Field field = AbstractConnectionFactory.class.getDeclaredField("addresses");
        field.setAccessible(true);
        var addresses = (List<com.rabbitmq.client.Address>) field.get(factory);
        return addresses.stream().map(Object::toString).toList();
    }

    private static final class CapturingLogger extends Logger {
        private final List<String> errors = new ArrayList<>();

        private CapturingLogger() {
            super("user", "test");
        }

        @Override
        public void error(String message) {
            errors.add(message);
        }
    }
}
