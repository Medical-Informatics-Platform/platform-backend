package hbp.mip.algorithm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.reflect.TypeToken;
import hbp.mip.SpringJsonMapper;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.RawJson;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the t-test result and specification shapes of Exaflow PR #656 (algorithms/t-test-corrections).
 * Results pass through as {@link RawJson}: stored for a kept run by {@link JsonConverters}, then written
 * to the UI by Spring's configured mapper. None of the PR's changes needs backend code; these tests
 * keep it that way.
 */
class ExaflowTTestContractTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    private JsonNode roundTrip(String exaflowResult) throws Exception {
        String stored = JsonConverters.convertObjectToJsonString(new RawJson(exaflowResult));
        return objectMapper.readTree(SpringJsonMapper.INSTANCE.writeValueAsString(new RawJson(stored)));
    }

    @Test
    void keepsTheOpenSideOfAOneSidedConfidenceIntervalAsAString() throws Exception {
        // Real ttest_onesample response, alt_hypothesis=greater, from the PR #656 deployment.
        JsonNode result = roundTrip("""
                {"n_obs":217,"std":0.536580284502321,"t_stat":175.26155251671003,"df":216,
                 "p":3.89674018742522e-235,"mean_diff":4.6339797235023035,"se_diff":0.036425443183801726,
                 "ci_upper":"Infinity","ci_lower":4.57380712601384,"cohens_d":11.897529424554714}
                """);

        assertThat(result.get("ci_upper").isTextual()).isTrue();
        assertThat(result.get("ci_upper").asText()).isEqualTo("Infinity");
        assertThat(result.get("ci_lower").asDouble()).isEqualTo(4.57380712601384);
        // The survival-function p-value no longer underflows to 0 and must not be rounded to it here.
        assertThat(result.get("p").asDouble()).isEqualTo(3.89674018742522e-235);
    }

    @Test
    void keepsNullStatisticsWhenExaflowCannotComputeThem() throws Exception {
        // Before PR #656 an independent t-test with a one-row group returned nulls; a zero-variance
        // sample still can. They stay explicit nulls despite application.yml's non_null inclusion.
        JsonNode result = roundTrip("""
                {"n_obs":15,"t_stat":null,"df":14.0,"p":null,"mean_diff":0.0624,"se_diff":null,
                 "ci_upper":null,"ci_lower":null,"cohens_d":null}
                """);

        assertThat(result.get("p").isNull()).isTrue();
        assertThat(result.get("ci_lower").isNull()).isTrue();
        assertThat(result.get("mean_diff").asDouble()).isEqualTo(0.0624);
        assertThat(result.get("n_obs").isIntegralNumber()).isTrue();
    }

    @Test
    void forwardsThePairedMeasurementLabelsAsExaflowDefinesThem() throws Exception {
        // PR #656 labels x "Measurement 1" and y "Measurement 2"; mean_diff is x - y.
        String payload = """
                [{"name":"ttest_paired","label":"Paired t-test",
                  "documentation":"Compare the mean of paired differences (measurement 1 minus measurement 2)",
                  "y":{"label":"Measurement 2","desc":"Second numerical measurement in each pair.","max_count":1},
                  "x":{"label":"Measurement 1","desc":"First numerical measurement in each pair.","max_count":1},
                  "parameters":{"alt_hypothesis":{"enums":{"type":"list","source":["two-sided","less","greater"]}}}}]
                """;

        List<AlgorithmSpecificationDTO> algorithms = JsonConverters.convertJsonStringToObject(payload,
                new TypeToken<List<AlgorithmSpecificationDTO>>() {
                }.getType());
        JsonNode paired = objectMapper.readTree(SpringJsonMapper.INSTANCE.writeValueAsString(algorithms)).get(0);

        assertThat(paired.at("/x/label").asText()).isEqualTo("Measurement 1");
        assertThat(paired.at("/y/label").asText()).isEqualTo("Measurement 2");
        assertThat(paired.at("/documentation").asText()).contains("measurement 1 minus measurement 2");
        assertThat(paired.at("/parameters/alt_hypothesis/enums/source")).extracting(JsonNode::asText)
                .containsExactly("two-sided", "less", "greater");
    }

    @Test
    void sendsOneSidedRunParametersToExaflowUnchanged() throws Exception {
        // UI JSON in through Spring's mapper, out to Exaflow through JsonConverters.
        AnalysisRequestDTO request = SpringJsonMapper.INSTANCE.readValue("""
                {
                  "request_id": "00000000-0000-0000-0000-000000000656",
                  "inputdata": {"data_model": "dementia:0.1", "datasets": ["edsd0"], "variables": ["x1", "y1"]},
                  "algorithm": {
                    "name": "ttest_paired",
                    "x": ["x1"],
                    "y": ["y1"],
                    "parameters": {"alt_hypothesis": "less", "alpha": 0.05}
                  }
                }
                """, AnalysisRequestDTO.class);

        JsonNode sent = objectMapper.readTree(JsonConverters.convertObjectToJsonString(request));

        assertThat(sent.at("/algorithm/parameters/alt_hypothesis").asText()).isEqualTo("less");
        assertThat(sent.at("/algorithm/parameters/alpha").asDouble()).isEqualTo(0.05);
        assertThat(sent.at("/algorithm/x/0").asText()).isEqualTo("x1");
    }
}
