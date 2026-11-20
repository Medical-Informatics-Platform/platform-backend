package hbp.mip.algorithm;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.rabbitmq.client.AMQP;
import hbp.mip.utils.Exceptions.GatewayTimeoutException;
import hbp.mip.utils.Exceptions.ServiceUnavailableException;
import hbp.mip.utils.Logger;
import org.springframework.amqp.AmqpException;
import org.springframework.amqp.core.AmqpMessageReturnedException;
import org.springframework.amqp.core.AmqpReplyTimeoutException;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageDeliveryMode;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.core.ReturnedMessage;
import org.springframework.amqp.rabbit.AsyncRabbitTemplate;
import org.springframework.amqp.rabbit.RabbitMessageFuture;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Submits one analysis to Exaflow's request queue and waits for the correlated reply.
 */
@Component
public class ExaflowAmqpClient implements AutoCloseable, DisposableBean {

    public static final String UNAVAILABLE =
            "The analysis service is not available right now. Please try again later or inform the system administrator.";
    public static final String TIMED_OUT =
            "The analysis did not finish in time. Please try again later or inform the system administrator.";

    private static final long REPLY_MARGIN_MS = 1000;

    private final AsyncRabbitTemplate template;
    private final String requestQueue;
    private final String replyQueue;
    private final Duration replyTimeout;
    private final Duration publishTimeout;
    private final ExecutorService dispatchPool;

    public ExaflowAmqpClient(AsyncRabbitTemplate template,
            @Value("${services.exaflow.rabbitmq.requestQueue}") String requestQueue,
            @Value("${services.exaflow.rabbitmq.replyQueue}") String replyQueue,
            @Value("${services.exaflow.rabbitmq.replyTimeout}") Duration replyTimeout,
            @Value("${services.exaflow.rabbitmq.publishTimeout}") Duration publishTimeout) {
        this.template = template;
        this.requestQueue = requestQueue;
        this.replyQueue = replyQueue;
        this.replyTimeout = replyTimeout;
        this.publishTimeout = publishTimeout;
        this.dispatchPool = createDispatchPool();
    }

    private static ExecutorService createDispatchPool() {
        AtomicInteger counter = new AtomicInteger(1);
        return Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "exaflow-amqp-dispatch-" + counter.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        });
    }

    @Override
    public void destroy() {
        close();
    }

    @Override
    public void close() {
        dispatchPool.shutdownNow();
    }

    public ExaflowReply submit(String requestId, String requestBody, Logger logger) {
        return submit(requestId, requestBody, true, logger);
    }

    public ExaflowReply submit(String requestId, String requestBody, boolean requireConsumer, Logger logger) {
        long publishDeadlineNanos = System.nanoTime() + publishTimeout.toNanos();
        RabbitMessageFuture future = dispatchPublish(requestId, requestBody, requireConsumer, publishDeadlineNanos,
                logger);
        return awaitReply(future, publishDeadlineNanos, requestId, logger);
    }

    public record ExaflowReply(int code, String body) {
    }

    private RabbitMessageFuture dispatchPublish(String requestId, String requestBody, boolean requireConsumer,
            long publishDeadlineNanos, Logger logger) {
        AtomicBoolean abandoned = new AtomicBoolean(false);
        AtomicBoolean sendStarted = new AtomicBoolean(false);
        Future<RabbitMessageFuture> dispatch;
        try {
            dispatch = dispatchPool.submit(() -> {
                if (abandoned.get() || Thread.currentThread().isInterrupted()) {
                    return null;
                }
                if (requireConsumer) {
                    requireRequestConsumer(requestId, abandoned, logger);
                    if (abandoned.get() || Thread.currentThread().isInterrupted()) {
                        return null;
                    }
                }
                Message message = buildRequestMessage(requestId, requestBody);
                sendStarted.set(true);
                if (abandoned.get() || Thread.currentThread().isInterrupted()) {
                    return null;
                }
                RabbitMessageFuture future;
                try {
                    future = template.sendAndReceive(requestQueue, message);
                } catch (RuntimeException | Error e) {
                    discardPending(requestId);
                    throw e;
                }
                if (abandoned.get()) {
                    future.cancel(false);
                    return null;
                }
                return future;
            });
        } catch (RejectedExecutionException e) {
            logFailure(logger, requestId, e, true);
            throw new ServiceUnavailableException(UNAVAILABLE);
        }

        long remainingNanos = publishDeadlineNanos - System.nanoTime();
        if (remainingNanos <= 0) {
            abandonDispatch(abandoned, sendStarted, dispatch, requestId);
            logFailure(logger, requestId, "publish-timeout", true);
            throw new ServiceUnavailableException(UNAVAILABLE);
        }
        try {
            RabbitMessageFuture future = dispatch.get(remainingNanos, TimeUnit.NANOSECONDS);
            if (future == null) {
                logFailure(logger, requestId, "publish-abandoned", true);
                throw new ServiceUnavailableException(UNAVAILABLE);
            }
            return future;
        } catch (TimeoutException e) {
            abandonDispatch(abandoned, sendStarted, dispatch, requestId);
            logFailure(logger, requestId, e, true);
            throw new ServiceUnavailableException(UNAVAILABLE);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            abandonDispatch(abandoned, sendStarted, dispatch, requestId);
            logFailure(logger, requestId, e, true);
            throw new ServiceUnavailableException(UNAVAILABLE);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() == null ? e : unwrap(e.getCause());
            if (cause instanceof ServiceUnavailableException unavailable) {
                throw unavailable;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            logFailure(logger, requestId, cause, true);
            throw new ServiceUnavailableException(UNAVAILABLE);
        }
    }

    private void abandonDispatch(AtomicBoolean abandoned, AtomicBoolean sendStarted,
            Future<RabbitMessageFuture> dispatch, String requestId) {
        abandoned.set(true);
        dispatch.cancel(true);
        if (sendStarted.get()) {
            discardPending(requestId);
        }
    }

    private Message buildRequestMessage(String requestId, String requestBody) {
        MessageProperties properties = new MessageProperties();
        properties.setContentType(MessageProperties.CONTENT_TYPE_JSON);
        properties.setContentEncoding("UTF-8");
        properties.setDeliveryMode(MessageDeliveryMode.PERSISTENT);
        properties.setCorrelationId(requestId);
        properties.setReplyTo(replyQueue);
        properties.setExpiration(Long.toString(replyTimeout.toMillis()));
        return new Message(requestBody.getBytes(StandardCharsets.UTF_8), properties);
    }

    private void discardPending(String requestId) {
        MessageProperties properties = new MessageProperties();
        properties.setCorrelationId(requestId);
        // AsyncRabbitTemplate inserts into its pending map before RabbitTemplate.send(...) and does not
        // remove the entry if send throws. returnedMessage(...) removes that correlationId via public API.
        template.returnedMessage(new ReturnedMessage(new Message(new byte[0], properties), 0, "publish-failed", "", ""));
    }

    private void requireRequestConsumer(String requestId, AtomicBoolean abandoned, Logger logger) {
        AMQP.Queue.DeclareOk declared;
        try {
            declared = template.getRabbitTemplate().execute(channel -> channel.queueDeclarePassive(requestQueue));
        } catch (AmqpException e) {
            if (!abandoned.get()) {
                logFailure(logger, requestId, e, true);
            }
            throw new ServiceUnavailableException(UNAVAILABLE);
        }
        if (declared == null || declared.getConsumerCount() == 0) {
            if (!abandoned.get()) {
                logFailure(logger, requestId, "no-consumer", true);
            }
            throw new ServiceUnavailableException(UNAVAILABLE);
        }
    }

    /**
     * A reply (or a returned publish) can arrive before the publisher confirm. Spring AMQP then
     * discards the confirm, so this waits for whichever finishes first instead of blocking on the confirm alone.
     */
    private ExaflowReply awaitReply(RabbitMessageFuture future, long publishDeadlineNanos, String requestId,
            Logger logger) {
        boolean publishConfirmed = false;
        try {
            long remainingNanos = publishDeadlineNanos - System.nanoTime();
            Object winner;
            if (remainingNanos > 0) {
                winner = CompletableFuture.anyOf(future.getConfirm(), future)
                        .get(remainingNanos, TimeUnit.NANOSECONDS);
            } else if (future.getConfirm().isDone() || future.isDone()) {
                winner = CompletableFuture.anyOf(future.getConfirm(), future).get(0, TimeUnit.NANOSECONDS);
            } else {
                throw new TimeoutException("publish deadline elapsed");
            }
            if (winner instanceof Boolean ack) {
                if (!ack) {
                    logFailure(logger, requestId, "nack", true);
                    throw new ServiceUnavailableException(UNAVAILABLE);
                }
                publishConfirmed = true;
                winner = future.get(replyTimeout.toMillis() + REPLY_MARGIN_MS, TimeUnit.MILLISECONDS);
            }
            if (winner instanceof Message reply) {
                return toHttpEquivalent(new String(reply.getBody(), StandardCharsets.UTF_8));
            }
            logFailure(logger, requestId, "unexpected-confirm", true);
            throw new ServiceUnavailableException(UNAVAILABLE);
        } catch (TimeoutException e) {
            logFailure(logger, requestId, e, !publishConfirmed);
            if (publishConfirmed) {
                throw new GatewayTimeoutException(TIMED_OUT);
            }
            throw new ServiceUnavailableException(UNAVAILABLE);
        } catch (CancellationException e) {
            // AsyncRabbitTemplate.stop() cancels in-flight futures during shutdown.
            logFailure(logger, requestId, e, true);
            throw new ServiceUnavailableException(UNAVAILABLE);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() == null ? e : unwrap(e.getCause());
            if (cause instanceof CancellationException) {
                logFailure(logger, requestId, cause, true);
                throw new ServiceUnavailableException(UNAVAILABLE);
            }
            throw failure(cause, isConfirmed(future, publishConfirmed), requestId, logger);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logFailure(logger, requestId, e, true);
            throw new ServiceUnavailableException(UNAVAILABLE);
        } finally {
            // A nack, publish timeout, or interrupt otherwise leaves the request body pending
            // until replyTimeout.
            if (!future.isDone()) {
                future.cancel(false);
            }
        }
    }

    private static boolean isConfirmed(RabbitMessageFuture future, boolean publishConfirmed) {
        if (publishConfirmed) {
            return true;
        }
        CompletableFuture<Boolean> confirm = future.getConfirm();
        return confirm != null && confirm.isDone() && !confirm.isCompletedExceptionally()
                && Boolean.TRUE.equals(confirm.getNow(Boolean.FALSE));
    }

    private RuntimeException failure(Throwable cause, boolean publishConfirmed, String requestId, Logger logger) {
        boolean timedOut = publishConfirmed
                && (cause instanceof AmqpReplyTimeoutException || cause instanceof TimeoutException);
        logFailure(logger, requestId, cause, !timedOut);
        if (timedOut) {
            return new GatewayTimeoutException(TIMED_OUT);
        }
        return new ServiceUnavailableException(UNAVAILABLE);
    }

    private static Throwable unwrap(Throwable cause) {
        if (cause instanceof java.util.concurrent.CompletionException && cause.getCause() != null) {
            return cause.getCause();
        }
        return cause;
    }

    private static void logFailure(Logger logger, String requestId, Throwable cause, boolean error) {
        String causeType = cause.getClass().getSimpleName();
        if (cause instanceof AmqpMessageReturnedException returned) {
            causeType = causeType + " replyCode=" + returned.getReplyCode();
        }
        logFailure(logger, requestId, causeType, error);
    }

    private static void logFailure(Logger logger, String requestId, String causeType, boolean error) {
        String text = "Exaflow AMQP failure correlationId=" + requestId + " cause=" + causeType;
        if (error) {
            logger.error(text);
        } else {
            logger.warn(text);
        }
    }

    public static ExaflowReply toHttpEquivalent(String replyBody) {
        JsonElement parsed;
        try {
            parsed = JsonParser.parseString(replyBody);
        } catch (JsonSyntaxException | NullPointerException e) {
            return new ExaflowReply(500, "");
        }
        if (!parsed.isJsonObject()) {
            return new ExaflowReply(500, "");
        }
        JsonObject envelope = parsed.getAsJsonObject();
        String status = stringOrNull(envelope.get("status"));
        if ("succeeded".equals(status)) {
            JsonElement result = envelope.get("result");
            return new ExaflowReply(200, result == null ? "null" : result.toString());
        }
        if (!"failed".equals(status)) {
            return new ExaflowReply(500, "");
        }
        String message = "";
        String errorCode = null;
        JsonElement error = envelope.get("error");
        if (error != null && error.isJsonObject()) {
            JsonObject errorObject = error.getAsJsonObject();
            errorCode = stringOrNull(errorObject.get("code"));
            String extracted = stringOrNull(errorObject.get("message"));
            message = extracted == null ? "" : extracted;
        }
        return new ExaflowReply(httpCode(errorCode), message);
    }

    private static String stringOrNull(JsonElement element) {
        if (element == null || element.isJsonNull() || !element.isJsonPrimitive()
                || !element.getAsJsonPrimitive().isString()) {
            return null;
        }
        return element.getAsString();
    }

    private static int httpCode(String errorCode) {
        if (errorCode == null) {
            return 500;
        }
        return switch (errorCode) {
            case "BadRequest", "FilterError" -> 400;
            case "request_too_large", "result_too_large", "WorkerMessageTooLargeError" -> 413;
            case "invalid_request" -> 422;
            case "BadUserInput", "DataModelUnavailable", "DatasetUnavailable" -> 460;
            case "insufficient_data" -> 461;
            case "WorkerUnresponsiveError" -> 512;
            case "WorkerTaskTimeoutError" -> 513;
            case "GlobalWorkerUnavailableError" -> 503;
            default -> 500;
        };
    }
}
