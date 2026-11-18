package hbp.mip.algorithm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.reflect.TypeToken;
import hbp.mip.SpringJsonMapper;
import hbp.mip.utils.JsonConverters;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Exaflow's single CDE `type` (continuous/discrete/nominal/ordinal/binary) as it reaches the UI in specifications. */
class ExaflowCdeVariableTypesContractTest {

    private static final String SPECIFICATIONS = """
            [
              {
                "name": "cox_regression_classical",
                "y": { "types": ["numerical"], "required": true },
                "x": { "types": ["numerical", "nominal", "ordinal", "binary"] },
                "parameters": {
                  "event_var": {
                    "label": "Event variable",
                    "types": ["text"],
                    "required": true,
                    "enums": { "type": "input_var_names", "source": ["x", "y"] },
                    "variable_types": ["binary"]
                  },
                  "alpha": { "types": ["real"], "variable_types": null }
                }
              },
              {
                "name": "glmm_ordinal",
                "y": { "types": ["ordinal"], "min_count": 1, "max_count": 1 },
                "x": { "types": ["binary"] }
              }
            ]
            """;

    @Test
    void keepsBinaryAndOrdinalSlotTypesAndParameterVariableTypes() throws Exception {
        List<AlgorithmSpecificationDTO> algorithms = JsonConverters.convertJsonStringToObject(SPECIFICATIONS,
                new TypeToken<List<AlgorithmSpecificationDTO>>() {
                }.getType());

        assertThat(algorithms.get(0).x().types()).containsExactly("numerical", "nominal", "ordinal", "binary");
        assertThat(algorithms.get(0).parameters().get("event_var").variable_types()).containsExactly("binary");
        assertThat(algorithms.get(0).parameters().get("alpha").variable_types()).isNull();
        assertThat(algorithms.get(1).y().types()).containsExactly("ordinal");

        JsonNode serialized = new ObjectMapper().readTree(SpringJsonMapper.INSTANCE.writeValueAsString(algorithms));
        assertThat(serialized.at("/0/parameters/event_var/variable_types/0").asText()).isEqualTo("binary");
        assertThat(serialized.at("/0/parameters/alpha").has("variable_types")).isFalse();
        assertThat(serialized.at("/1/y/types/0").asText()).isEqualTo("ordinal");
        assertThat(serialized.at("/1/x/types/0").asText()).isEqualTo("binary");
    }

    @Test
    void readsIntegerAndNumericStringDatasetCodes() throws Exception {
        String body = """
                {"name":"e","analysis":{"inputdata":{"data_model":"dementia:0.1","datasets":["12", 3],
                 "validation_datasets":["4"],"filters":{"rules":[{"id":"gender","value":1}]},"variables":["gender"]},
                 "algorithm":{"name":"logistic_regression","y":["gender"]}}}
                """;

        hbp.mip.experiment.ExperimentExecutionDTO execution =
                SpringJsonMapper.INSTANCE.readValue(body, hbp.mip.experiment.ExperimentExecutionDTO.class);

        assertThat(execution.analysis().inputdata().allDatasets()).containsExactly("12", "3", "4");
        JsonNode sent = new ObjectMapper().readTree(JsonConverters.convertObjectToJsonString(execution.analysis()));
        assertThat(sent.at("/inputdata/datasets/0").isTextual()).isTrue();
        assertThat(sent.at("/inputdata/datasets/1").asText()).isEqualTo("3");
        assertThat(sent.at("/inputdata/filters/rules/0/value").isIntegralNumber()).isTrue();
    }
}
