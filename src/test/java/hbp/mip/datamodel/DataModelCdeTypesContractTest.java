package hbp.mip.datamodel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.reflect.TypeToken;
import hbp.mip.SpringJsonMapper;
import hbp.mip.utils.JsonConverters;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The CDE shape Exaflow sends after the variable-type refactor, and what the UI receives from /data-models. */
class DataModelCdeTypesContractTest {

    private static final String ATTRIBUTES = """
            {"dementia:0.1": {"properties": {"cdes": [{
              "code": "dementia", "version": "0.1", "label": "Dementia", "longitudinal": false,
              "variables": [
                {"code": "gender", "label": "Gender", "type": "binary",
                 "enumerations": [{"code": "0", "label": "F"}, {"code": 1, "label": "M"}]},
                {"code": "agegroup", "label": "Age group", "type": "ordinal",
                 "enumerations": [{"code": "1", "label": "<65"}, {"code": "2", "label": ">=65"}]},
                {"code": "age", "label": "Age", "type": "continuous", "minValue": 0, "maxValue": 120.5},
                {"code": "dataset", "label": "Dataset", "type": "nominal",
                 "enumerations": [{"code": "12", "label": "EDSD"}]}
              ],
              "groups": [],
              "datasets": [{"code": "12", "label": "EDSD"}]
            }]}, "tags": []}}
            """;

    @Test
    void passesCdeTypeAndIntegerCodedEnumerationsToTheUi() throws Exception {
        Map<String, DataModelService.DataModelAttributes> attributes = JsonConverters.convertJsonStringToObject(
                ATTRIBUTES, new TypeToken<Map<String, DataModelService.DataModelAttributes>>() {
                }.getType());
        DataModelDTO dataModel = attributes.get("dementia:0.1").properties().get("cdes").getFirst();

        JsonNode json = new ObjectMapper().readTree(SpringJsonMapper.INSTANCE.writeValueAsString(dataModel));

        assertThat(json.at("/variables/0/type").asText()).isEqualTo("binary");
        assertThat(json.at("/variables/1/type").asText()).isEqualTo("ordinal");
        assertThat(json.at("/variables/2/type").asText()).isEqualTo("continuous");
        assertThat(json.at("/variables/0/enumerations/0/code").asText()).isEqualTo("0");
        assertThat(json.at("/variables/0/enumerations/1/code").asText()).isEqualTo("1");
        assertThat(json.at("/variables/0/enumerations/1/label").asText()).isEqualTo("M");
        assertThat(json.at("/variables/3/enumerations/0/code").asText()).isEqualTo("12");
        assertThat(json.at("/datasets/0/code").asText()).isEqualTo("12");
        assertThat(json.at("/datasets/0/label").asText()).isEqualTo("EDSD");
        for (JsonNode variable : json.at("/variables")) {
            assertThat(variable.has("sql_type")).isFalse();
            assertThat(variable.has("isCategorical")).isFalse();
            assertThat(variable.has("is_categorical")).isFalse();
        }
    }

    @Test
    void readsDatasetEnumerationsFromCdesMetadataWithNumericCodes() {
        Map<String, Map<String, DataModelService.CDEMetadata>> metadata = JsonConverters.convertJsonStringToObject(
                "{\"dementia:0.1\":{\"dataset\":{\"code\":\"dataset\",\"type\":\"nominal\",\"min\":null,"
                        + "\"enumerations\":{\"12\":\"EDSD\",\"13\":\"PPMI\"}}}}",
                new TypeToken<Map<String, Map<String, DataModelService.CDEMetadata>>>() {
                }.getType());

        assertThat(metadata.get("dementia:0.1").get("dataset").enumerations())
                .containsOnly(Map.entry("12", "EDSD"), Map.entry("13", "PPMI"));
    }

    @Test
    void keysDatasetVariablesByNumericDatasetCode() {
        Map<String, Map<String, List<String>>> exaflow = JsonConverters.convertJsonStringToObject(
                "{\"dementia:0.1\":{\"12\":[\"dataset\",\"gender\"]}}",
                new TypeToken<Map<String, Map<String, List<String>>>>() {
                }.getType());

        DataModelDTO dataModel = new DataModelDTO("dementia", "0.1", "d", false, List.of(), List.of(), List.of(), null);
        assertThat(DataModelService.selectDatasetVariables(exaflow, dataModel))
                .containsOnly(Map.entry("12", List.of("dataset", "gender")));
    }
}
