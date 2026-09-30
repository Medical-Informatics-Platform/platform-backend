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

    @Test
    void requireRunnable_rejectsMissingAlgorithmAndInputdataAsBadRequest() {
        var inputdata = new AnalysisRequestDTO.AnalysisInputDataDTO("dm:1", List.of("ds1"), null, null, List.of("age"));
        var algorithm = new AnalysisRequestDTO.AnalysisAlgorithmDTO("histogram", null, List.of("age"), Map.of());
        var logger = new Logger("user", "test");

        assertThatThrownBy(() -> AnalysisService.requireRunnable(null, logger))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("analysis");
        assertThatThrownBy(() -> AnalysisService.requireRunnable(
                new AnalysisRequestDTO(null, inputdata, null, null, null), logger))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("algorithm.name");
        assertThatThrownBy(() -> AnalysisService.requireRunnable(
                new AnalysisRequestDTO(null, null, null, algorithm, null), logger))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("inputdata");
        AnalysisService.requireRunnable(new AnalysisRequestDTO(null, inputdata, null, algorithm, null), logger);
    }

}
