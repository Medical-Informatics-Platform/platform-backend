package hbp.mip.algorithm;

import com.fasterxml.jackson.databind.ObjectMapper;
import hbp.mip.analysis.AnalysisExecutionDTO;
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
    void jacksonReadsAnalysisRequestFromExecutionBody() throws Exception {
        String body = "{\"name\":\"analysis\",\"analysisRequest\":" + ANALYSIS_JSON + "}";

        AnalysisExecutionDTO execution = new ObjectMapper().readValue(body, AnalysisExecutionDTO.class);

        assertThat(execution.analysisRequest().algorithm().name()).isEqualTo("histogram");
        assertThat(execution.analysisRequest().inputdata().datasets()).containsExactly("ds1");
        assertThat(execution.analysisRequest().preprocessing()).extracting("name").containsExactly("winsorize");
    }

    @Test
    void gsonReadsAnalysisFromStoredAnalysisJson() {
        AnalysisRequestDTO analysisRequest = JsonConverters.convertJsonStringToObject(ANALYSIS_JSON, AnalysisRequestDTO.class);

        assertThat(analysisRequest.algorithm().name()).isEqualTo("histogram");
        assertThat(analysisRequest.inputdata().variables()).containsExactly("age");
        assertThat(analysisRequest.preprocessing()).extracting("name").containsExactly("winsorize");
    }
}
