package hbp.mip.algorithm;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public record AnalysisRequestDTO(
        String request_id,
        AnalysisInputDataDTO inputdata,
        List<AnalysisPreprocessingStepDTO> preprocessing,
        AnalysisAlgorithmDTO algorithm,
        Map<String, Object> flags) {

    public record AnalysisInputDataDTO(
            String data_model,
            List<String> datasets,
            List<String> validation_datasets,
            Map<String, Object> filters,
            List<String> variables) {

        /** Every dataset the analysis reads, validation datasets included: what an access check must cover. */
        public List<String> allDatasets() {
            if (datasets == null || datasets.isEmpty() || validation_datasets == null) {
                return datasets;
            }
            return Stream.concat(datasets.stream(), validation_datasets.stream()).toList();
        }
    }

    public record AnalysisPreprocessingStepDTO(
            String name,
            Map<String, Object> parameters) {
    }

    public record AnalysisAlgorithmDTO(
            String name,
            List<String> x,
            List<String> y,
            Map<String, Object> parameters) {
    }
}
