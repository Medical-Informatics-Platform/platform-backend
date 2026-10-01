package hbp.mip.algorithm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.reflect.TypeToken;
import hbp.mip.utils.JsonConverters;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers the Exaflow specification fields that AlgorithmSpecificationDTOTest does not:
 * parameter `enums`/`default` and inputData `stattypes`, plus a nested JSON object surviving
 * the Gson read -> Jackson write hop that the kmeans_cluster_creator preprocessing needs.
 */
class ExaflowKMeansAndSmdContractTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void deserializesParameterEnumsDefaultsAndStatTypes() {
        String payload = """
                [
                  {
                    "y": { "stattypes": ["numerical"] },
                    "x": { "stattypes": ["nominal"] },
                    "required_preprocessing": ["missing_values_handler"],
                    "parameters": {
                      "k_selection": {
                        "required": true,
                        "enums": { "type": "list", "source": ["manual", "elbow"] },
                        "default": "manual"
                      },
                      "k": { "max": 4294967276 }
                    }
                  }
                ]
                """;

        List<AlgorithmSpecificationDTO> algorithms = JsonConverters.convertJsonStringToObject(payload,
                new TypeToken<List<AlgorithmSpecificationDTO>>() {
                }.getType());
        AlgorithmSpecificationDTO algorithm = algorithms.getFirst();
        ParameterSpecificationDTO kSelection = algorithm.parameters().get("k_selection");

        assertThat(kSelection.enums().type()).isEqualTo("list");
        assertThat(kSelection.enums().source()).containsExactly("manual", "elbow");
        assertThat(kSelection.default_value()).isEqualTo("manual");
        assertThat(kSelection.required()).isTrue();
        assertThat(algorithm.parameters().get("k").max()).isEqualTo(4294967276.0);
        assertThat(algorithm.y().stattypes()).containsExactly("numerical");
        assertThat(algorithm.x().stattypes()).containsExactly("nominal");
        assertThat(algorithm.required_preprocessing()).containsExactly("missing_values_handler");
    }

    @Test
    void forwardsNestedReusablePreprocessingIntoNextRequest() throws Exception {
        String resultJson = """
                {
                  "reusable_preprocessing": {
                    "schema_version": "1",
                    "centers": { "cluster_0": { "lefthippocampus": 2.9876543210123 } },
                    "source_context": { "input_fingerprint": "abc123" },
                    "available_outputs": [{ "number_of_variables": 1, "cardinality": 2 }],
                    "cluster_choices": [{ "cluster_id": "cluster_0" }, { "cluster_id": "cluster_1" }]
                  }
                }
                """;

        Map<String, Object> result = JsonConverters.convertJsonStringToObject(resultJson, Object.class);
        Map<String, Object> parameters = Map.of("reusable_preprocessing", result.get("reusable_preprocessing"));
        AnalysisRequestDTO request = new AnalysisRequestDTO(
                "00000000-0000-0000-0000-000000000002",
                new AnalysisRequestDTO.AnalysisInputDataDTO(
                        "dementia:0.1", List.of("edsd0"), null, null, List.of("gender")),
                List.of(new AnalysisRequestDTO.AnalysisPreprocessingStepDTO("kmeans_cluster_creator", parameters)),
                new AnalysisRequestDTO.AnalysisAlgorithmDTO(
                        "chi_squared", List.of("kmeans_cluster"), List.of("gender"), Map.of()),
                null);

        JsonNode reusable = objectMapper.readTree(JsonConverters.convertObjectToJsonString(request))
                .at("/preprocessing/0/parameters/reusable_preprocessing");

        assertThat(reusable.isObject()).isTrue();
        assertThat(reusable.at("/schema_version").asText()).isEqualTo("1");
        assertThat(reusable.at("/source_context/input_fingerprint").asText()).isEqualTo("abc123");
        assertThat(reusable.at("/centers/cluster_0/lefthippocampus").asDouble()).isEqualTo(2.9876543210123);
        assertThat(reusable.at("/cluster_choices").size()).isEqualTo(2);
        assertThat(reusable.at("/available_outputs/0/cardinality").asDouble()).isEqualTo(2.0);
    }
}
