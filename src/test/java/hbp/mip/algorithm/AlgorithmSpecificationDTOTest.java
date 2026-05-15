package hbp.mip.algorithm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import hbp.mip.experiment.ExperimentExecutionDTO;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Type;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AlgorithmSpecificationDTOTest {
    private final Gson gson = new Gson();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void deserializesOutlierDictionaryMetadataAndPreprocessingOrder() throws Exception {
        String payload = """
                [
                  {
                    "name": "outlier_report",
                    "label": "Outlier Report",
                    "desc": "Detect outliers.",
                    "documentation": "Long algorithm documentation.",
                    "type": "stats",
                    "flags": ["beta"],
                    "inputdata": {
                      "data_model": { "label": "Data model", "desc": "", "types": ["text"] },
                      "datasets": { "label": "Datasets", "desc": "", "types": ["text"] },
                      "validation_datasets": { "label": "Validation datasets", "desc": "", "types": ["text"], "required": false, "min_count": 0, "max_count": 2 },
                      "y": { "label": "Y", "desc": "", "types": ["real"], "required": true, "min_count": 1, "max_count": 3 }
                    },
                    "parameters": {
                      "folds": {
                        "label": "Folds",
                        "types": ["dict"],
                        "required": false,
                        "multiple": false,
                        "min": 0,
                        "max": 10,
                        "dict_keys_enums": {
                          "type": "input_var_names",
                          "source": ["x", "y"]
                        },
                        "dict_values_type": "real"
                      }
                    },
                    "preprocessing": [
                      {
                        "name": "outlier_winsorizer",
                        "label": "Outlier Winsorizer",
                        "desc": "Clip outliers.",
                        "documentation": "Long preprocessing documentation.",
                        "order": 2,
                        "parameters": {}
                      }
                    ]
                  }
                ]
                """;

        Type algorithmListType = new TypeToken<List<AlgorithmSpecificationDTO>>() {
        }.getType();
        List<AlgorithmSpecificationDTO> algorithms = gson.fromJson(payload, algorithmListType);

        AlgorithmSpecificationDTO algorithm = algorithms.getFirst();
        AlgorithmSpecificationDTO.AlgorithmParameterSpecificationDTO folds = algorithm.parameters().get("folds");

        assertThat(folds.dict_values_type()).isEqualTo("real");
        assertThat(folds.dict_keys_enums().type()).isEqualTo("input_var_names");
        assertThat(folds.dict_keys_enums().source()).containsExactly("x", "y");
        assertThat(algorithm.documentation()).isEqualTo("Long algorithm documentation.");
        assertThat(algorithm.type()).isEqualTo("stats");
        assertThat(algorithm.flags()).containsExactly("beta");
        assertThat(algorithm.inputdata().y().min_count()).isEqualTo(1);
        assertThat(algorithm.inputdata().y().max_count()).isEqualTo(3);
        assertThat(algorithm.inputdata().validation_datasets().max_count()).isEqualTo(2);
        assertThat(folds.min()).isEqualTo("0");
        assertThat(folds.max()).isEqualTo("10");
        assertThat(algorithm.preprocessing().getFirst().order()).isEqualTo(2);
        assertThat(algorithm.preprocessing().getFirst().documentation()).isEqualTo("Long preprocessing documentation.");

        JsonNode serialized = objectMapper.readTree(objectMapper.writeValueAsString(algorithm));
        assertThat(serialized.at("/documentation").asText()).isEqualTo("Long algorithm documentation.");
        assertThat(serialized.at("/parameters/folds/dict_values_type").asText()).isEqualTo("real");
        assertThat(serialized.at("/preprocessing/0/documentation").asText()).isEqualTo("Long preprocessing documentation.");
        assertThat(serialized.at("/preprocessing/0/order").asInt()).isEqualTo(2);
    }

    @Test
    void keepsDocumentationOptionalWhenMissing() {
        String payload = """
                [
                  {
                    "name": "canonical_optional_algorithm",
                    "label": "Canonical Optional Algorithm",
                    "desc": "Canonical short description.",
                    "inputdata": {
                      "data_model": { "label": "Data model", "desc": "", "types": ["text"] },
                      "datasets": { "label": "Datasets", "desc": "", "types": ["text"] },
                      "y": { "label": "Y", "desc": "", "types": ["real"], "required": true }
                    },
                    "parameters": {},
                    "preprocessing": [
                      {
                        "name": "canonical_preprocessing",
                        "label": "Canonical Preprocessing",
                        "desc": "Canonical preprocessing summary.",
                        "order": 4,
                        "parameters": {}
                      }
                    ]
                  }
                ]
                """;

        Type algorithmListType = new TypeToken<List<AlgorithmSpecificationDTO>>() {
        }.getType();
        List<AlgorithmSpecificationDTO> algorithms = gson.fromJson(payload, algorithmListType);

        AlgorithmSpecificationDTO algorithm = algorithms.getFirst();

        assertThat(algorithm.documentation()).isNull();
        assertThat(algorithm.preprocessing().getFirst().documentation()).isNull();
    }

    @Test
    void serializesNestedOutlierPreprocessingUnchangedForExaflowRequest() throws Exception {
        Map<String, Object> outlierWinsorizer = new LinkedHashMap<>();
        outlierWinsorizer.put("strategies", Map.of("age", "iqr"));
        outlierWinsorizer.put("tails", Map.of("age", "both"));
        outlierWinsorizer.put("folds", Map.of("age", 1.5));

        Map<String, Object> preprocessing = Map.of("outlier_winsorizer", outlierWinsorizer);
        ExperimentExecutionDTO.AlgorithmExecutionDTO algorithmExecutionDTO =
                new ExperimentExecutionDTO.AlgorithmExecutionDTO(
                        "linear_regression",
                        new AlgorithmRequestDTO.InputDataRequestDTO(
                                "dm:1",
                                List.of("ds1"),
                                List.of("outcome"),
                                List.of("age"),
                                null,
                                null
                        ),
                        Map.of(),
                        preprocessing
                );

        AlgorithmRequestDTO request = AlgorithmRequestDTO.create(
                UUID.fromString("00000000-0000-0000-0000-000000000001"),
                algorithmExecutionDTO
        );

        JsonNode outlierNode = objectMapper.readTree(objectMapper.writeValueAsString(request))
                .at("/preprocessing/outlier_winsorizer");

        assertThat(outlierNode.at("/strategies/age").asText()).isEqualTo("iqr");
        assertThat(outlierNode.at("/tails/age").asText()).isEqualTo("both");
        assertThat(outlierNode.at("/folds/age").asDouble()).isEqualTo(1.5);
    }
}
