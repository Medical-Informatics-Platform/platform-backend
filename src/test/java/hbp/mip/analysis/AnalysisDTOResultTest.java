package hbp.mip.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hbp.mip.SpringJsonMapper;
import hbp.mip.user.UserDAO;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AnalysisDTOResultTest {

    @Test
    void servesTheStoredResultAsExaflowSentIt() throws Exception {
        AnalysisDAO analysis = new AnalysisDAO();
        analysis.setCreatedBy(new UserDAO("user", "User", "user@example.org", "sub"));
        analysis.setResult("{\"n_obs\":217,\"p\":null,\"table\":{\"se\":null}}");

        JsonNode result = new ObjectMapper()
                .readTree(SpringJsonMapper.INSTANCE.writeValueAsString(new AnalysisDTO(analysis, true)))
                .get("result");

        assertThat(result.get("n_obs").isIntegralNumber()).isTrue();
        assertThat(result.get("p").isNull()).isTrue();
        assertThat(result.at("/table/se").isNull()).isTrue();
    }
}
