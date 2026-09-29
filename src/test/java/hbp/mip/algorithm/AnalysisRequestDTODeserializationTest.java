package hbp.mip.algorithm;

import com.fasterxml.jackson.databind.ObjectMapper;
import hbp.mip.experiment.ExperimentExecutionDTO;
import hbp.mip.utils.JsonConverters;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AnalysisRequestDTODeserializationTest {

    private static final String ANALYSIS_JSON = """
            {
              "request_id": "11111111-1111-1111-1111-111111111111",
              "inputdata": {
                "data_model": "dm:1",
                "datasets": ["ds1"],
                "variables": ["age"]
              },
              "preprocessing": [
                { "name": "winsorize", "parameters": { "limit": 0.05 } }
              ],
              "algorithm": {
                "name": "histogram",
                "y": ["age"],
                "parameters": {}
              }
            }
            """;

    @Test
    void jacksonReadsAnalysisFromExperimentExecutionBody() throws Exception {
        String body = "{\"name\":\"experiment\",\"analysis\":" + ANALYSIS_JSON + "}";

        ExperimentExecutionDTO execution = new ObjectMapper().readValue(body, ExperimentExecutionDTO.class);

        assertThat(execution.analysis().algorithm().name()).isEqualTo("histogram");
        assertThat(execution.analysis().inputdata().datasets()).containsExactly("ds1");
        assertThat(execution.analysis().preprocessing()).extracting("name").containsExactly("winsorize");
    }

    @Test
    void gsonReadsAnalysisFromStoredExperimentJson() {
        AnalysisRequestDTO analysis = JsonConverters.convertJsonStringToObject(ANALYSIS_JSON, AnalysisRequestDTO.class);

        assertThat(analysis.algorithm().name()).isEqualTo("histogram");
        assertThat(analysis.inputdata().variables()).containsExactly("age");
        assertThat(analysis.preprocessing()).extracting("name").containsExactly("winsorize");
    }
}
