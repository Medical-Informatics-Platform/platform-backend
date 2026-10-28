package hbp.mip.algorithm;

import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AnalysisServiceRequestIdTest {

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

    @Test
    void allDatasets_coversValidationDatasetsForAccessChecks() {
        assertThat(new AnalysisRequestDTO.AnalysisInputDataDTO("dm:1", List.of("ds1"), List.of("restricted"), null,
                List.of("age")).allDatasets()).containsExactly("ds1", "restricted");
        assertThat(new AnalysisRequestDTO.AnalysisInputDataDTO("dm:1", List.of(), List.of("restricted"), null,
                List.of("age")).allDatasets()).isEmpty();
    }

    @Test
    void convertResponse_mapsExaflowBusyToRetryMessage() {
        var exaflowBody = new StringBuilder("The controller is already running the maximum number of concurrent analyses.");

        assertThat(AnalysisService.convertResponseToAnalysisResult(new Logger("user", "test"), 503, exaflowBody))
                .isEqualTo(Map.of("data", AnalysisService.BUSY_ERROR_MESSAGE, "type", "text/plain+error"));
    }

    @Test
    void convertResponse_passesExaflowMessageTooLargeThrough() {
        var exaflowBody = new StringBuilder("result too large (>104857600 bytes / 100.0 MiB); reduce variables/levels");

        assertThat(AnalysisService.convertResponseToAnalysisResult(new Logger("user", "test"), 413, exaflowBody))
                .isEqualTo(Map.of("data", exaflowBody.toString(), "type", "text/plain+error"));
    }
}
