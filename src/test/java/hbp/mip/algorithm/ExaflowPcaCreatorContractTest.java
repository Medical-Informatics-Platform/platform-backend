package hbp.mip.algorithm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hbp.mip.utils.JsonConverters;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins how platform-backend forwards a PCA creator request and preserves repeated preprocessing
 * steps in order. The request DTO is an ordered List, so a request with two PCA creator steps
 * must round-trip both in the original order, and the integer {@code n_components} the UI sends
 * must survive the UI-to-Exaflow hop (Jackson read, Jackson write) as an integral number, not a
 * double: Exaflow rejects non-integer counts.
 */
class ExaflowPcaCreatorContractTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void forwardsPcaRecipeIntoCreatorStep() throws Exception {
        String resultJson = """
                {
                  "title": "Eigenvalues and Eigenvectors",
                  "n_obs": 812,
                  "eigenvalues": [1.71, 0.29],
                  "eigenvectors": [[0.707, 0.707], [-0.707, 0.707]],
                  "variables": ["lefthippocampus", "righthippocampus"],
                  "components": [
                    {"component_id": "PC1", "explained_variance": 1.71, "explained_variance_ratio": 0.855, "cumulative_explained_variance": 0.855, "loadings": {"lefthippocampus": 0.707, "righthippocampus": 0.707}},
                    {"component_id": "PC2", "explained_variance": 0.29, "explained_variance_ratio": 0.145, "cumulative_explained_variance": 1.0, "loadings": {"lefthippocampus": -0.707, "righthippocampus": 0.707}}
                  ],
                  "reusable_preprocessing": {
                    "schema_version": "1",
                    "preprocessing_name": "pca_column_creator",
                    "base_parameters": {"variables": ["lefthippocampus", "righthippocampus"], "pca_variant": "pca"},
                    "component_choices": [{"component_id": "PC1", "explained_variance_ratio": 0.855}, {"component_id": "PC2", "explained_variance_ratio": 0.145}]
                  }
                }
                """;

        Map<String, Object> result = JsonConverters.convertJsonStringToObject(resultJson, Object.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> reusable = (Map<String, Object>) result.get("reusable_preprocessing");

        Map<String, Object> parameters = Map.of(
                "reusable_preprocessing", reusable,
                "selected_components", List.of("PC1", "PC2"),
                "new_column_names", List.of("pca_pc1", "pca_pc2"),
                "n_components", 2);

        AnalysisRequestDTO request = new AnalysisRequestDTO(
                "00000000-0000-0000-0000-000000000003",
                new AnalysisRequestDTO.AnalysisInputDataDTO(
                        "dementia:0.1", List.of("edsd0"), null, null, List.of("gender")),
                List.of(
                        new AnalysisRequestDTO.AnalysisPreprocessingStepDTO("missing_values_handler", Map.of()),
                        new AnalysisRequestDTO.AnalysisPreprocessingStepDTO("pca_column_creator", parameters)),
                new AnalysisRequestDTO.AnalysisAlgorithmDTO(
                        "logistic_regression", List.of("pca_pc1", "pca_pc2"), List.of("gender"), Map.of()),
                null);

        JsonNode step = objectMapper.readTree(JsonConverters.convertObjectToJsonString(request))
                .at("/preprocessing/1");

        assertThat(step.at("/name").asText()).isEqualTo("pca_column_creator");
        assertThat(step.at("/parameters/reusable_preprocessing/preprocessing_name").asText())
                .isEqualTo("pca_column_creator");
        assertThat(step.at("/parameters/reusable_preprocessing/schema_version").asText()).isEqualTo("1");
        assertThat(step.at("/parameters/reusable_preprocessing/component_choices").size()).isEqualTo(2);
    }

    @Test
    void preservesRepeatedPreprocessingStepsInOrder() throws Exception {
        String requestJson = """
                {
                  "request_id": "22222222-2222-2222-2222-222222222222",
                  "inputdata": {
                    "data_model": "dm:1",
                    "datasets": ["ds1"],
                    "variables": ["age"]
                  },
                  "preprocessing": [
                    { "name": "missing_values_handler", "parameters": {} },
                    { "name": "pca_column_creator", "parameters": { "new_column_names": ["pca_a1"], "n_components": 1 } },
                    { "name": "kmeans_cluster_creator", "parameters": {} },
                    { "name": "pca_column_creator", "parameters": { "new_column_names": ["pca_b1"], "n_components": 1 } }
                  ],
                  "algorithm": {
                    "name": "linear_regression",
                    "x": ["pca_a1"],
                    "y": ["age"],
                    "parameters": {}
                  }
                }
                """;

        AnalysisRequestDTO request = new ObjectMapper().readValue(requestJson, AnalysisRequestDTO.class);
        JsonNode tree = objectMapper.readTree(JsonConverters.convertObjectToJsonString(request));

        assertThat(names(tree)).containsExactly(
                "missing_values_handler", "pca_column_creator", "kmeans_cluster_creator", "pca_column_creator");
        assertThat(tree.at("/preprocessing/3/parameters/new_column_names/0").asText()).isEqualTo("pca_b1");
        assertThat(tree.at("/preprocessing/3/parameters/n_components").isIntegralNumber()).isTrue();
    }

    private static List<String> names(JsonNode tree) {
        List<String> names = new ArrayList<>();
        tree.at("/preprocessing").forEach(step -> names.add(step.at("/name").asText()));
        return names;
    }
}
