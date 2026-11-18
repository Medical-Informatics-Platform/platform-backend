package hbp.mip.algorithm;

import hbp.mip.datamodel.DatasetLabels;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AnalysisExecutionServiceRequestIdTest {

    @Test
    void requireRunnable_rejectsMissingAlgorithmAndInputdataAsBadRequest() {
        var inputdata = new AnalysisRequestDTO.AnalysisInputDataDTO("dm:1", List.of("ds1"), null, null, List.of("age"));
        var algorithm = new AnalysisRequestDTO.AnalysisAlgorithmDTO("histogram", null, List.of("age"), Map.of());
        var logger = new Logger("user", "test");

        assertThatThrownBy(() -> AnalysisExecutionService.requireRunnable(null, logger))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("analysisRequest");
        assertThatThrownBy(() -> AnalysisExecutionService.requireRunnable(
                new AnalysisRequestDTO(null, inputdata, null, null, null), logger))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("algorithm.name");
        assertThatThrownBy(() -> AnalysisExecutionService.requireRunnable(
                new AnalysisRequestDTO(null, null, null, algorithm, null), logger))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("inputdata");
        AnalysisExecutionService.requireRunnable(new AnalysisRequestDTO(null, inputdata, null, algorithm, null), logger);
    }

    @Test
    void allDatasets_coversValidationDatasetsForAccessChecks() {
        assertThat(new AnalysisRequestDTO.AnalysisInputDataDTO("dm:1", List.of("ds1"), List.of("restricted"), null,
                List.of("age")).allDatasets()).containsExactly("ds1", "restricted");
        assertThat(new AnalysisRequestDTO.AnalysisInputDataDTO("dm:1", List.of(), List.of("restricted"), null,
                List.of("age")).allDatasets()).isEmpty();
    }

    @Test
    void withDatasetLabels_sendsExaflowTheDatasetLabels() {
        var labels = new DatasetLabels(Map.of("tbi:1.0", Map.of("1", "Creactive", "2", "CLM")));
        var inputdata = new AnalysisRequestDTO.AnalysisInputDataDTO("tbi:1.0", List.of("1", "CLM", "unknown"),
                List.of("2"), Map.of("condition", "AND"), List.of("age"));

        var sent = AnalysisExecutionService.withDatasetLabels(inputdata, labels);

        assertThat(sent.datasets()).containsExactly("Creactive", "CLM", "unknown");
        assertThat(sent.validation_datasets()).containsExactly("CLM");
        assertThat(sent.data_model()).isEqualTo("tbi:1.0");
        assertThat(sent.filters()).isEqualTo(inputdata.filters());
        assertThat(sent.variables()).containsExactly("age");
        assertThat(AnalysisExecutionService.withDatasetLabels(
                new AnalysisRequestDTO.AnalysisInputDataDTO("tbi:1.0", List.of("1"), null, null, List.of("age")),
                labels).validation_datasets()).isNull();
    }

    @Test
    void convertResponse_mapsExaflowBusyToRetryMessage() {
        var exaflowBody = new StringBuilder("The controller is already running the maximum number of concurrent analyses.");

        assertThat(AnalysisExecutionService.convertResponseToAnalysisResult(new Logger("user", "test"), 503, exaflowBody))
                .isEqualTo(Map.of("data", AnalysisExecutionService.BUSY_ERROR_MESSAGE, "type", "text/plain+error"));
    }

    @Test
    void convertResponse_passesExaflowMessageTooLargeThrough() {
        var exaflowBody = new StringBuilder("result too large (>104857600 bytes / 100.0 MiB); reduce variables/levels");

        assertThat(AnalysisExecutionService.convertResponseToAnalysisResult(new Logger("user", "test"), 413, exaflowBody))
                .isEqualTo(Map.of("data", exaflowBody.toString(), "type", "text/plain+error"));
    }

    @Test
    void convertResponse_passesExaflowMalformedRequestThrough() {
        var exaflowBody = new StringBuilder("Request malformed:\nbody.inputdata: Field required");

        assertThat(AnalysisExecutionService.convertResponseToAnalysisResult(new Logger("user", "test"), 422, exaflowBody))
                .isEqualTo(Map.of("data", exaflowBody.toString(), "type", "text/plain+error"));
    }
}
