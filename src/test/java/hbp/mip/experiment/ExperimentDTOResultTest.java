package hbp.mip.experiment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hbp.mip.SpringJsonMapper;
import hbp.mip.user.UserDAO;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ExperimentDTOResultTest {

    @Test
    void servesTheStoredResultAsExaflowSentIt() throws Exception {
        ExperimentDAO experiment = new ExperimentDAO();
        experiment.setCreatedBy(new UserDAO("user", "User", "user@example.org", "sub"));
        experiment.setResult("{\"n_obs\":217,\"p\":null,\"table\":{\"se\":null}}");

        JsonNode result = new ObjectMapper()
                .readTree(SpringJsonMapper.INSTANCE.writeValueAsString(new ExperimentDTO(experiment, true)))
                .get("result");

        assertThat(result.get("n_obs").isIntegralNumber()).isTrue();
        assertThat(result.get("p").isNull()).isTrue();
        assertThat(result.at("/table/se").isNull()).isTrue();
    }
}
