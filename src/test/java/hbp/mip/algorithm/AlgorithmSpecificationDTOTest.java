package hbp.mip.algorithm;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
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
    void deserializesHeadAlgorithmSpecificationShape() throws Exception {
        String payload = """
                [
                  {
                    "name": "linear_regression",
                    "label": "Linear Regression",
                    "desc": "Short description.",
                    "documentation": "Long algorithm documentation.",
                    "type": "exareme3",
                    "flags": ["beta"],
                    "y": { "label": "Y", "desc": "", "types": ["real"], "required": true, "min_count": 1, "max_count": 1 },
                    "x": { "label": "X", "desc": "", "types": ["real"], "required": true, "min_count": 1 },
                    "requires_validation_datasets": false,
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
                    "required_preprocessing": []
                  }
                ]
                """;

        Type algorithmListType = new TypeToken<List<AlgorithmSpecificationDTO>>() {
        }.getType();
        List<AlgorithmSpecificationDTO> algorithms = gson.fromJson(payload, algorithmListType);

        AlgorithmSpecificationDTO algorithm = algorithms.getFirst();
        ParameterSpecificationDTO folds = algorithm.parameters().get("folds");

        assertThat(folds.dict_values_type()).isEqualTo("real");
        assertThat(folds.dict_keys_enums().type()).isEqualTo("input_var_names");
        assertThat(folds.dict_keys_enums().source()).containsExactly("x", "y");
        assertThat(algorithm.documentation()).isEqualTo("Long algorithm documentation.");
        assertThat(algorithm.type()).isEqualTo("exareme3");
        assertThat(algorithm.flags()).containsExactly("beta");
        assertThat(algorithm.y().min_count()).isEqualTo(1);
        assertThat(algorithm.y().max_count()).isEqualTo(1);
        assertThat(algorithm.requires_validation_datasets()).isFalse();
        assertThat(folds.min()).isEqualTo(0.0);
        assertThat(folds.max()).isEqualTo(10.0);

        JsonNode serialized = objectMapper.readTree(objectMapper.writeValueAsString(algorithm));
        assertThat(serialized.at("/documentation").asText()).isEqualTo("Long algorithm documentation.");
        assertThat(serialized.at("/parameters/folds/dict_values_type").asText()).isEqualTo("real");
        assertThat(serialized.at("/requires_validation_datasets").asBoolean()).isFalse();
    }

    @Test
    void deserializesInputdataAndPreprocessingSpecifications() {
        String inputdataPayload = """
                {
                  "data_model": { "label": "Data model", "desc": "", "types": ["text"], "required": true },
                  "datasets": { "label": "Datasets", "desc": "", "types": ["text"], "required": true, "min_count": 1 },
                  "filters": { "label": "Filters", "desc": "", "types": ["jsonObject"], "required": false },
                  "variables": { "label": "Variables", "desc": "", "types": ["real", "int", "text"], "required": true, "min_count": 1 }
                }
                """;
        String preprocessingPayload = """
                [
                  {
                    "name": "pca_column_creator",
                    "label": "PCA Column Creator",
                    "desc": "Create principal component columns.",
                    "documentation": "Long preprocessing documentation.",
                    "parameters": {},
                    "outputs": {
                      "new_column_names_param": "new_column_names",
                      "columns": [
                        {
                          "type": "real",
                          "stattype": "numerical",
                          "column_count_param": "n_components",
                          "enumerations": null
                        }
                      ]
                    }
                  },
                  {
                    "name": "categorical_column_creator",
                    "label": "Categorical Column Creator",
                    "desc": "Create a derived column.",
                    "documentation": "Long preprocessing documentation.",
                    "parameters": {},
                    "outputs": {
                      "new_column_names_param": "new_column_names",
                      "columns": [
                        {
                          "type": "text",
                          "stattype": "nominal",
                          "column_count_param": null,
                          "enumerations": {
                            "source_parameter_name": "rules",
                            "source_type": "dict_keys",
                            "additional_value_parameter_name": "default_enumeration",
                            "prefix_parameter_name": null
                          }
                        }
                      ]
                    }
                  }
                ]
                """;

        AnalysisInputDataSpecificationDTO inputdata = gson.fromJson(inputdataPayload, AnalysisInputDataSpecificationDTO.class);
        List<PreprocessingStepSpecificationDTO> preprocessing = gson.fromJson(
                preprocessingPayload,
                new TypeToken<List<PreprocessingStepSpecificationDTO>>() {
                }.getType());

        PreprocessingStepSpecificationDTO pca = preprocessing.get(0);
        PreprocessingStepSpecificationDTO categorical = preprocessing.get(1);

        assertThat(inputdata.variables().min_count()).isEqualTo(1);
        assertThat(pca.outputs().new_column_names_param()).isEqualTo("new_column_names");
        assertThat(pca.outputs().columns().getFirst().column_count_param()).isEqualTo("n_components");
        assertThat(pca.outputs().columns().getFirst().enumerations()).isNull();
        assertThat(categorical.outputs().columns().getFirst().enumerations().source_type()).isEqualTo("dict_keys");

        // application.yml sets spring.jackson.default-property-inclusion: non_null; the outputs
        // contract must still send its nullable fields as explicit nulls.
        ObjectMapper nonNullMapper = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);
        JsonNode serialized = nonNullMapper.valueToTree(preprocessing);
        assertThat(serialized.at("/0/outputs/columns/0/column_count_param").asText()).isEqualTo("n_components");
        assertThat(serialized.at("/1/outputs/columns/0/enumerations/prefix_parameter_name").isNull()).isTrue();
        assertThat(serialized.at("/1/outputs/columns/0/column_count_param").isNull()).isTrue();
        assertThat(serialized.at("/0/outputs/columns/0/enumerations").isNull()).isTrue();
        assertThat(serialized.has("output")).isFalse();
    }

    @Test
    void serializesOrderedPreprocessingForAnalysisRequest() throws Exception {
        Map<String, Object> outlierParameters = new LinkedHashMap<>();
        outlierParameters.put("strategies", Map.of("age", "iqr"));
        outlierParameters.put("tails", Map.of("age", "both"));
        outlierParameters.put("folds", Map.of("age", 1.5));

        AnalysisRequestDTO request = new AnalysisRequestDTO(
                UUID.fromString("00000000-0000-0000-0000-000000000001").toString(),
                new AnalysisRequestDTO.AnalysisInputDataDTO(
                        "dm:1",
                        List.of("ds1"),
                        null,
                        null,
                        List.of("age", "outcome")),
                List.of(new AnalysisRequestDTO.AnalysisPreprocessingStepDTO(
                        "outlier_winsorizer",
                        outlierParameters)),
                new AnalysisRequestDTO.AnalysisAlgorithmDTO(
                        "linear_regression",
                        List.of("age"),
                        List.of("outcome"),
                        Map.of()),
                null);

        JsonNode serialized = objectMapper.readTree(objectMapper.writeValueAsString(request));
        JsonNode preprocessingNode = serialized.at("/preprocessing/0");

        assertThat(preprocessingNode.at("/name").asText()).isEqualTo("outlier_winsorizer");
        assertThat(preprocessingNode.at("/parameters/strategies/age").asText()).isEqualTo("iqr");
        assertThat(preprocessingNode.at("/parameters/tails/age").asText()).isEqualTo("both");
        assertThat(preprocessingNode.at("/parameters/folds/age").asDouble()).isEqualTo(1.5);
        assertThat(serialized.at("/algorithm/name").asText()).isEqualTo("linear_regression");
    }
}
