package hbp.mip.algorithm;

import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AnalysisServiceRequestIdTest {

    private final AnalysisService analysisService = new AnalysisService("http://127.0.0.1:5000/analysis");

    @Test
    void runAnalysis_rejectsInvalidRequestId() {
        var analysis = new AnalysisRequestDTO(
                "not-a-uuid",
                new AnalysisRequestDTO.AnalysisInputDataDTO(
                        "dm:1",
                        List.of("ds1"),
                        null,
                        null,
                        List.of("age")),
                null,
                new AnalysisRequestDTO.AnalysisAlgorithmDTO(
                        "histogram",
                        null,
                        List.of("age"),
                        Map.of()),
                null);

        assertThatThrownBy(() -> analysisService.runAnalysis(analysis, new Logger("user", "test")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Invalid request_id");
    }
}
