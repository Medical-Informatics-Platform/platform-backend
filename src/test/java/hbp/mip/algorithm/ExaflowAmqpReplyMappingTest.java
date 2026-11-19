package hbp.mip.algorithm;

import com.google.gson.JsonParser;
import hbp.mip.utils.Logger;
import hbp.mip.utils.RawJson;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class ExaflowAmqpReplyMappingTest {

    @ParameterizedTest
    @MethodSource("mappingRows")
    void mapsEveryReplyRow(String replyBody, int code, String body) {
        assertThat(ExaflowAmqpClient.toHttpEquivalent(replyBody))
                .isEqualTo(new ExaflowAmqpClient.ExaflowReply(code, body));
    }

    static Stream<Arguments> mappingRows() {
        return Stream.of(
                Arguments.of(succeeded("{\"n_obs\":1}"), 200, "{\"n_obs\":1}"),
                Arguments.of(failed("BadRequest", "bad request"), 400, "bad request"),
                Arguments.of(failed("FilterError", "filter"), 400, "filter"),
                Arguments.of(failed("request_too_large", "request too large"), 413, "request too large"),
                Arguments.of(failed("result_too_large", "result too large"), 413, "result too large"),
                Arguments.of(failed("WorkerMessageTooLargeError", "worker too large"), 413, "worker too large"),
                Arguments.of(failed("invalid_request", "invalid"), 422, "invalid"),
                Arguments.of(failed("BadUserInput", "user input"), 460, "user input"),
                Arguments.of(failed("DataModelUnavailable", "model"), 460, "model"),
                Arguments.of(failed("DatasetUnavailable", "dataset"), 460, "dataset"),
                Arguments.of(failed("insufficient_data", "not enough"), 461, "not enough"),
                Arguments.of(failed("SMPCUsageError", "smpc"), 500, "smpc"),
                Arguments.of(failed("WorkerUnresponsiveError", "unresponsive"), 512, "unresponsive"),
                Arguments.of(failed("WorkerTaskTimeoutError", "task timeout"), 513, "task timeout"),
                Arguments.of(failed("GlobalWorkerUnavailableError", "no workers"), 503, "no workers"),
                Arguments.of(failed("internal_error", "boom"), 500, "boom"),
                Arguments.of("{\"status\":\"weird\"}", 500, ""),
                Arguments.of("not json", 500, ""));
    }

    @Test
    void succeeded_returnsResultJsonUnwrapped() {
        var reply = ExaflowAmqpClient.toHttpEquivalent(
                "{\"status\":\"succeeded\",\"result\":{\"n_obs\":217,\"p\":null}}");

        assertThat(reply.code()).isEqualTo(200);
        assertThat(JsonParser.parseString(reply.body()))
                .isEqualTo(JsonParser.parseString("{\"n_obs\":217,\"p\":null}"));
    }

    @Test
    void unparseableBody_isInternal() {
        assertThat(ExaflowAmqpClient.toHttpEquivalent("not json").code()).isEqualTo(500);
    }

    @Test
    void unknownCode_isInternal() {
        var reply = ExaflowAmqpClient.toHttpEquivalent(
                "{\"status\":\"failed\",\"error\":{\"code\":\"Whatever\",\"message\":\"x\"}}");

        assertThat(reply.code()).isEqualTo(500);
        assertThat(reply.body()).isEqualTo("x");
    }

    @Test
    void globalWorkerUnavailable_usesExistingBusyConverter() {
        var reply = ExaflowAmqpClient.toHttpEquivalent(
                "{\"status\":\"failed\",\"error\":{\"code\":\"GlobalWorkerUnavailableError\",\"message\":\"no workers\"}}");

        assertThat(AnalysisExecutionService.convertResponseToAnalysisResult(
                new Logger("user", "test"), reply.code(), reply.body()))
                .isEqualTo(Map.of("data", AnalysisExecutionService.BUSY_ERROR_MESSAGE, "type", "text/plain+error"));
    }

    @Test
    void succeeded_isRawJsonThroughExistingConverter() {
        var reply = ExaflowAmqpClient.toHttpEquivalent(
                "{\"status\":\"succeeded\",\"result\":{\"n_obs\":217,\"p\":null}}");

        assertThat(AnalysisExecutionService.convertResponseToAnalysisResult(
                new Logger("user", "test"), reply.code(), reply.body()))
                .isEqualTo(new RawJson("{\"n_obs\":217,\"p\":null}"));
    }

    private static String succeeded(String resultJson) {
        return "{\"status\":\"succeeded\",\"result\":" + resultJson + "}";
    }

    private static String failed(String code, String message) {
        return "{\"status\":\"failed\",\"error\":{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}}";
    }
}
