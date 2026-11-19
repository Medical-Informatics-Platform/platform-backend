package hbp.mip.algorithm;

import com.google.gson.JsonParser;
import hbp.mip.utils.HTTPUtil;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.Logger;
import hbp.mip.utils.RawJson;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AnalysisExecutionServiceContractTest {
    @Test
    void exaflowReceivesTheUnwrappedRequestWithTheExecutionIdOverRabbitMq() {
        var request = analysisRequest();
        var executionId = UUID.randomUUID();
        String result = "{\"n_obs\":217,\"p\":null}";
        ExaflowAmqpClient amqp = mock(ExaflowAmqpClient.class);
        when(amqp.submit(eq(executionId.toString()), anyString(), eq(false), any()))
                .thenReturn(new ExaflowAmqpClient.ExaflowReply(200, result));
        try (var http = mockStatic(HTTPUtil.class)) {
            var response = new AnalysisExecutionService(amqp)
                    .runAnalysis(executionId, request, new Logger("user", "test"));
            var expected = JsonParser.parseString(JsonConverters.convertObjectToJsonString(request)).getAsJsonObject();
            expected.addProperty("request_id", executionId.toString());
            var body = new AtomicReference<String>();
            verify(amqp).submit(eq(executionId.toString()), argThat(sent -> {
                body.set(sent);
                return true;
            }), eq(false), any());
            assertThat(JsonParser.parseString(body.get())).isEqualTo(expected);
            assertThat(response.body()).isEqualTo(new RawJson(result));
            assertThat(response.code()).isEqualTo(200);
            assertThat(request.request_id()).isEqualTo("original-request-id");
            http.verifyNoInteractions();
        }
    }

    @Test
    void previewAnalysisRequiresActiveConsumer() {
        var executionId = UUID.randomUUID();
        ExaflowAmqpClient amqp = mock(ExaflowAmqpClient.class);
        when(amqp.submit(eq(executionId.toString()), anyString(), eq(true), any()))
                .thenReturn(new ExaflowAmqpClient.ExaflowReply(200, "{\"ok\":true}"));

        var response = new AnalysisExecutionService(amqp)
                .previewAnalysis(executionId, analysisRequest(), new Logger("user", "test"));

        verify(amqp).submit(eq(executionId.toString()), anyString(), eq(true), any());
        assertThat(response.code()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(new RawJson("{\"ok\":true}"));
    }

    @Test
    void errorReplyGoesThroughExistingConverter() {
        ExaflowAmqpClient amqp = mock(ExaflowAmqpClient.class);
        when(amqp.submit(anyString(), anyString(), eq(false), any()))
                .thenReturn(new ExaflowAmqpClient.ExaflowReply(461, "Insufficient data for this analysis."));

        var response = new AnalysisExecutionService(amqp)
                .runAnalysis(UUID.randomUUID(), analysisRequest(), new Logger("user", "test"));

        assertThat(response.body()).isEqualTo(
                Map.of("data", "Insufficient data for this analysis.", "type", "text/plain+error"));
        assertThat(response.code()).isEqualTo(461);
    }

    private static AnalysisRequestDTO analysisRequest() {
        return new AnalysisRequestDTO("original-request-id",
                new AnalysisRequestDTO.AnalysisInputDataDTO("dm:1", List.of("ds1"), List.of("validation"),
                        Map.of("condition", "AND"), List.of("age")),
                List.of(new AnalysisRequestDTO.AnalysisPreprocessingStepDTO("scale", Map.of("method", "standard"))),
                new AnalysisRequestDTO.AnalysisAlgorithmDTO("histogram", List.of("age"), null, Map.of("bins", 10)));
    }
}
