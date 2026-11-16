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
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mockStatic;

class AnalysisExecutionServiceContractTest {
    @Test
    void exaflowStillReceivesTheUnwrappedRequestWithTheExecutionId() {
        var request = new AnalysisRequestDTO("original-request-id",
                new AnalysisRequestDTO.AnalysisInputDataDTO("dm:1", List.of("ds1"), List.of("validation"),
                        Map.of("condition", "AND"), List.of("age")),
                List.of(new AnalysisRequestDTO.AnalysisPreprocessingStepDTO("scale", Map.of("method", "standard"))),
                new AnalysisRequestDTO.AnalysisAlgorithmDTO("histogram", List.of("age"), null, Map.of("bins", 10)),
                Map.of("option", true));
        var executionId = UUID.randomUUID();
        var sent = new AtomicReference<String>();
        String result = "{\"n_obs\":217,\"p\":null}";
        try (var http = mockStatic(HTTPUtil.class)) {
            http.when(() -> HTTPUtil.sendPost(eq("http://exaflow/analysis"), isNull(), anyString(), any()))
                    .thenAnswer(call -> {
                        sent.set(call.getArgument(2));
                        call.<StringBuilder>getArgument(3).append(result);
                        return 200;
                    });
            var response = new AnalysisExecutionService("http://exaflow/analysis")
                    .runAnalysis(executionId, request, new Logger("user", "test"));
            var expected = JsonParser.parseString(JsonConverters.convertObjectToJsonString(request)).getAsJsonObject();
            expected.addProperty("request_id", executionId.toString());
            assertThat(JsonParser.parseString(sent.get())).isEqualTo(expected);
            assertThat(response.body()).isEqualTo(new RawJson(result));
            assertThat(request.request_id()).isEqualTo("original-request-id");
        }
    }
}
