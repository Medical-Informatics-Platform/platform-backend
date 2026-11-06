package hbp.mip.algorithm;

import com.google.gson.JsonParseException;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.Logger;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public record AnalysisRequestDTO(
        String request_id,
        AnalysisInputDataDTO inputdata,
        List<AnalysisPreprocessingStepDTO> preprocessing,
        AnalysisAlgorithmDTO algorithm,
        Map<String, Object> flags) {

    /** A stored analysis can be an error message, not JSON (see V2 migration); it then reads as no analysis. */
    public static AnalysisRequestDTO fromStored(String analysis) {
        try {
            return JsonConverters.convertJsonStringToObject(analysis, AnalysisRequestDTO.class);
        } catch (JsonParseException e) {
            new Logger("unknown", "AnalysisRequestDTO").warn("Stored analysis is unreadable: " + e.getClass().getSimpleName());
            return null;
        }
    }

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
