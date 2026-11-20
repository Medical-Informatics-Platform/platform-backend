package hbp.mip.algorithm;

import com.rabbitmq.client.AMQP;
import hbp.mip.utils.Exceptions.GatewayTimeoutException;
import hbp.mip.utils.Exceptions.ServiceUnavailableException;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.AmqpConnectException;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.AsyncRabbitTemplate;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.ChannelCallback;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.listener.SimpleMessageListenerContainer;

import java.io.IOException;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class ExaflowAmqpClientTest {

    private static final String REQUEST_QUEUE = "exaflow.analysis.requests";
    private static final String REPLY_QUEUE = "platform-backend.analysis.replies";

    private AsyncRabbitTemplate asyncTemplate;
    private ExaflowAmqpClient client;

    @AfterEach
    void tearDown() {
        if (client != null) {
            client.close();
        }
        if (asyncTemplate != null) {
            asyncTemplate.stop();
        }
    }

    @Test
    void submit_whenPublishThrows_clearsPendingEntry() throws Exception {
        var sends = new AtomicInteger();
        client = createClient(
                Duration.ofHours(1),
                Duration.ofSeconds(5),
                () -> declareOk(1),
                (message, correlation) -> {
                    sends.incrementAndGet();
                    throw new AmqpConnectException(new IOException("broker connection reset"));
                });

        for (int i = 0; i < 3; i++) {
            String requestId = UUID.randomUUID().toString();
            var logger = new CapturingLogger();
            assertThatThrownBy(() -> client.submit(requestId, "{\"request_id\":\"" + requestId + "\"}", logger))
                    .isInstanceOf(ServiceUnavailableException.class)
                    .hasMessage(ExaflowAmqpClient.UNAVAILABLE);
            assertThat(pending(asyncTemplate)).isEmpty();
            assertThat(logger.errors).anyMatch(line -> line.contains("cause=AmqpConnectException"));
        }
        assertThat(sends.get()).isEqualTo(3);
    }

    @Test
    void submit_whenConsumerCheckStalls_respectsPublishTimeoutAndDoesNotSend() throws Exception {
        var releaseCheck = new CountDownLatch(1);
        var sends = new AtomicInteger();
        client = createClient(
                Duration.ofHours(1),
                Duration.ofMillis(150),
                () -> {
                    try {
                        releaseCheck.await(5, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return declareOk(1);
                },
                (message, correlation) -> sends.incrementAndGet());

        long started = System.nanoTime();
        var logger = new CapturingLogger();
        try {
            assertThatThrownBy(() -> client.submit(UUID.randomUUID().toString(), "{\"a\":1}", logger))
                    .isInstanceOf(ServiceUnavailableException.class)
                    .hasMessage(ExaflowAmqpClient.UNAVAILABLE);
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(1));
            assertThat(pending(asyncTemplate)).isEmpty();
            assertThat(logger.errors).anyMatch(line -> line.contains("cause=TimeoutException"));
        } finally {
            releaseCheck.countDown();
        }

        // Wait briefly to confirm the abandoned worker does not publish after unblocking.
        Thread.sleep(100);
        assertThat(sends.get()).isZero();
        assertThat(pending(asyncTemplate)).isEmpty();
    }

    @Test
    void submit_whenSendStalls_respectsPublishTimeoutAndClearsPending() throws Exception {
        var sendEntered = new CountDownLatch(1);
        var releaseSend = new CountDownLatch(1);
        var sendFinished = new CountDownLatch(1);
        client = createClient(
                Duration.ofHours(1),
                Duration.ofMillis(150),
                () -> declareOk(1),
                (message, correlation) -> {
                    sendEntered.countDown();
                    try {
                        releaseSend.await(5, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        sendFinished.countDown();
                    }
                });

        long started = System.nanoTime();
        try {
            assertThatThrownBy(() -> client.submit(UUID.randomUUID().toString(), "{\"a\":1}", new CapturingLogger()))
                    .isInstanceOf(ServiceUnavailableException.class)
                    .hasMessage(ExaflowAmqpClient.UNAVAILABLE);
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(1));
            assertThat(sendEntered.await(1, TimeUnit.SECONDS)).isTrue();
            assertThat(pending(asyncTemplate)).isEmpty();
        } finally {
            releaseSend.countDown();
        }

        assertThat(sendFinished.await(2, TimeUnit.SECONDS)).isTrue();
        // Give the worker a moment to finish cancelling the returned future if send returned normally.
        Thread.sleep(50);
        assertThat(pending(asyncTemplate)).isEmpty();
    }

    @Test
    void submit_whenReplyTimesOutBeforeConfirm_returnsServiceUnavailable() throws Exception {
        client = createClient(
                Duration.ofMillis(100),
                Duration.ofSeconds(5),
                () -> declareOk(1),
                (message, correlation) -> {
                    // Never confirm the publish; replyTimeout fires first.
                });

        var logger = new CapturingLogger();
        assertThatThrownBy(() -> client.submit(UUID.randomUUID().toString(), "{\"a\":1}", logger))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessage(ExaflowAmqpClient.UNAVAILABLE);
        assertThat(logger.errors).anyMatch(line -> line.contains("cause=AmqpReplyTimeoutException"));
        assertThat(logger.warnings).isEmpty();
        assertThat(pending(asyncTemplate)).isEmpty();
    }

    @Test
    void submit_whenReplyTimesOutAfterConfirm_returnsGatewayTimeout() throws Exception {
        client = createClient(
                Duration.ofMillis(100),
                Duration.ofSeconds(5),
                () -> declareOk(1),
                (message, correlation) -> asyncTemplate.confirm(correlation, true, null));

        var logger = new CapturingLogger();
        assertThatThrownBy(() -> client.submit(UUID.randomUUID().toString(), "{\"a\":1}", logger))
                .isInstanceOf(GatewayTimeoutException.class)
                .hasMessage(ExaflowAmqpClient.TIMED_OUT);
        assertThat(logger.warnings).anyMatch(line -> line.contains("cause=AmqpReplyTimeoutException"));
        assertThat(logger.errors).isEmpty();
        assertThat(pending(asyncTemplate)).isEmpty();
    }

    @Test
    void submit_sharesSinglePublishDeadlineAcrossCheckSendAndConfirm() throws Exception {
        client = createClient(
                Duration.ofHours(1),
                Duration.ofMillis(450),
                () -> {
                    try {
                        Thread.sleep(300);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return declareOk(1);
                },
                (message, correlation) -> {
                    // Never confirm; confirm wait must use only the remaining ~150ms of publishTimeout.
                });

        long started = System.nanoTime();
        assertThatThrownBy(() -> client.submit(UUID.randomUUID().toString(), "{\"a\":1}", new CapturingLogger()))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessage(ExaflowAmqpClient.UNAVAILABLE);
        Duration elapsed = Duration.ofNanos(System.nanoTime() - started);
        // A fresh publishTimeout after the 300ms check would take >= 750ms.
        assertThat(elapsed).isLessThan(Duration.ofMillis(650));
        assertThat(pending(asyncTemplate)).isEmpty();
    }

    private ExaflowAmqpClient createClient(Duration replyTimeout, Duration publishTimeout,
            Supplier<AMQP.Queue.DeclareOk> declareHandler, BiConsumer<Message, CorrelationData> sendHandler) {
        RabbitTemplate rabbitTemplate = new StubRabbitTemplate(declareHandler, sendHandler);
        SimpleMessageListenerContainer container = mock(SimpleMessageListenerContainer.class);
        asyncTemplate = new AsyncRabbitTemplate(rabbitTemplate, container, REPLY_QUEUE);
        asyncTemplate.setMandatory(true);
        asyncTemplate.setEnableConfirms(true);
        asyncTemplate.setReceiveTimeout(replyTimeout.toMillis());
        asyncTemplate.start();
        return new ExaflowAmqpClient(asyncTemplate, REQUEST_QUEUE, REPLY_QUEUE, replyTimeout, publishTimeout);
    }

    private static AMQP.Queue.DeclareOk declareOk(int consumers) {
        return new AMQP.Queue.DeclareOk.Builder()
                .queue(REQUEST_QUEUE)
                .messageCount(0)
                .consumerCount(consumers)
                .build();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, ?> pending(AsyncRabbitTemplate async) throws Exception {
        Field field = AsyncRabbitTemplate.class.getDeclaredField("pending");
        field.setAccessible(true);
        return (Map<String, ?>) field.get(async);
    }

    private static final class StubRabbitTemplate extends RabbitTemplate {
        private final Supplier<AMQP.Queue.DeclareOk> declareHandler;
        private final BiConsumer<Message, CorrelationData> sendHandler;

        private StubRabbitTemplate(Supplier<AMQP.Queue.DeclareOk> declareHandler,
                BiConsumer<Message, CorrelationData> sendHandler) {
            super(mock(ConnectionFactory.class));
            this.declareHandler = declareHandler;
            this.sendHandler = sendHandler;
        }

        @Override
        @SuppressWarnings("unchecked")
        public <T> T execute(ChannelCallback<T> action) {
            return (T) declareHandler.get();
        }

        @Override
        public void send(String exchange, String routingKey, Message message, CorrelationData correlationData) {
            sendHandler.accept(message, correlationData);
        }
    }

    private static final class CapturingLogger extends Logger {
        private final List<String> errors = new ArrayList<>();
        private final List<String> warnings = new ArrayList<>();

        private CapturingLogger() {
            super("user", "test");
        }

        @Override
        public void error(String message) {
            errors.add(message);
        }

        @Override
        public void warn(String message) {
            warnings.add(message);
        }
    }
}
