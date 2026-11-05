package hbp.mip.algorithm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hbp.mip.SpringJsonMapper;
import hbp.mip.utils.JsonConverters;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins how platform-backend forwards PCA creator requests on the UI-to-Exaflow hop: the UI JSON is
 * read by Spring's configured mapper and written to Exaflow by {@link JsonConverters}. The nested
 * {@code reusable_preprocessing} recipe the UI copies from a PCA result must arrive unchanged,
 * repeated preprocessing steps must keep their order, and {@code n_components} must stay an integer.
 */
class ExaflowPcaCreatorContractTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private JsonNode forwardToExaflow(String uiRequestJson) throws Exception {
        AnalysisRequestDTO request = SpringJsonMapper.INSTANCE.readValue(uiRequestJson, AnalysisRequestDTO.class);
        return objectMapper.readTree(JsonConverters.convertObjectToJsonString(request));
    }

    @Test
    void forwardsPcaRecipeIntoCreatorStep() throws Exception {
        JsonNode step = forwardToExaflow("""
                {
                  "request_id": "00000000-0000-0000-0000-000000000003",
                  "inputdata": {"data_model": "dementia:0.1", "datasets": ["edsd0"], "variables": ["gender"]},
                  "preprocessing": [
                    {"name": "missing_values_handler", "parameters": {}},
                    {"name": "pca_column_creator", "parameters": {
                      "reusable_preprocessing": {
                        "schema_version": "1",
                        "preprocessing_name": "pca_column_creator",
                        "base_parameters": {"variables": ["lefthippocampus", "righthippocampus"], "pca_variant": "pca"},
                        "component_choices": [
                          {"component_id": "PC1", "explained_variance_ratio": 0.855},
                          {"component_id": "PC2", "explained_variance_ratio": 0.145}
                        ]
                      },
                      "selected_components": ["PC1", "PC2"],
                      "new_column_names": ["pca_pc1", "pca_pc2"],
                      "n_components": 2
                    }}
                  ],
                  "algorithm": {"name": "logistic_regression", "x": ["pca_pc1", "pca_pc2"], "y": ["gender"], "parameters": {}}
                }
                """).at("/preprocessing/1");

        assertThat(step.at("/name").asText()).isEqualTo("pca_column_creator");
        assertThat(step.at("/parameters/reusable_preprocessing/schema_version").asText()).isEqualTo("1");
        assertThat(step.at("/parameters/reusable_preprocessing/base_parameters/pca_variant").asText())
                .isEqualTo("pca");
        assertThat(step.at("/parameters/reusable_preprocessing/component_choices/1/component_id").asText())
                .isEqualTo("PC2");
        assertThat(step.at("/parameters/n_components").isIntegralNumber()).isTrue();
    }

    @Test
    void preservesRepeatedPreprocessingStepsInOrder() throws Exception {
        JsonNode tree = forwardToExaflow("""
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
                """);

        assertThat(names(tree)).containsExactly(
                "missing_values_handler", "pca_column_creator", "kmeans_cluster_creator", "pca_column_creator");
        assertThat(tree.at("/preprocessing/3/parameters/new_column_names/0").asText()).isEqualTo("pca_b1");
        assertThat(tree.at("/preprocessing/3/parameters/n_components").isIntegralNumber()).isTrue();
    }

    @Test
    void keepsCreatorCountsIntegralInASavedRun() throws Exception {
        // A kept run stores the analysis with JsonConverters and serves it back through Gson.
        AnalysisRequestDTO request = SpringJsonMapper.INSTANCE.readValue("""
                {
                  "inputdata": {"data_model": "dm:1", "datasets": ["ds1"], "variables": ["age"]},
                  "preprocessing": [
                    { "name": "pca_column_creator", "parameters": { "new_column_names": ["pca_a1", "pca_a2"], "n_components": 2 } }
                  ],
                  "algorithm": {"name": "linear_regression", "x": ["pca_a1"], "y": ["age"], "parameters": {}}
                }
                """, AnalysisRequestDTO.class);
        String stored = JsonConverters.convertObjectToJsonString(request);
        AnalysisRequestDTO served = JsonConverters.convertJsonStringToObject(stored, AnalysisRequestDTO.class);

        JsonNode tree = objectMapper.readTree(SpringJsonMapper.INSTANCE.writeValueAsString(served));

        assertThat(tree.at("/preprocessing/0/parameters/n_components").isIntegralNumber()).isTrue();
    }

    private static List<String> names(JsonNode tree) {
        List<String> names = new ArrayList<>();
        tree.at("/preprocessing").forEach(step -> names.add(step.at("/name").asText()));
        return names;
    }
}
