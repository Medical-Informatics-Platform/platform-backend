package hbp.mip.datamodel;

import com.google.gson.reflect.TypeToken;
import hbp.mip.utils.JsonConverters;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DataModelServiceDatasetVariablesTest {

    private static final Type DATASETS_VARIABLES_TYPE =
            new TypeToken<Map<String, Map<String, List<String>>>>() {}.getType();

    private static DataModelDTO dataModel(String code, String version) {
        return new DataModelDTO(code, version, code, false, List.of(), List.of(), List.of(), null);
    }

    @Test
    void passesThroughRealVariableListsFromExaflow() {
        Map<String, Map<String, List<String>>> exaflow = JsonConverters.convertJsonStringToObject(
                "{\"dementia:0.1\":{\"edsd\":[\"dataset\",\"age\",\"gender\"],\"ppmi\":[\"dataset\",\"age\"]}}",
                DATASETS_VARIABLES_TYPE);

        Map<String, List<String>> result =
                DataModelService.selectDatasetVariables(exaflow, dataModel("dementia", "0.1"));

        assertThat(result).containsOnly(
                Map.entry("edsd", List.of("dataset", "age", "gender")),
                Map.entry("ppmi", List.of("dataset", "age")));
    }

    @Test
    void omitsDatasetsWhoseVariablesAreUnknown() {
        Map<String, Map<String, List<String>>> exaflow = JsonConverters.convertJsonStringToObject(
                "{\"dementia:0.1\":{\"edsd\":[\"dataset\",\"age\"],\"ppmi\":null,\"desd\":[]}}",
                DATASETS_VARIABLES_TYPE);

        Map<String, List<String>> result =
                DataModelService.selectDatasetVariables(exaflow, dataModel("dementia", "0.1"));

        assertThat(result).containsOnlyKeys("edsd");
        assertThat(result.get("edsd")).containsExactly("dataset", "age");
    }

    @Test
    void returnsUnmodifiableCopies() {
        Map<String, List<String>> input = new HashMap<>();
        input.put("edsd", new java.util.ArrayList<>(List.of("dataset", "age")));

        Map<String, List<String>> result = DataModelService.keepKnownDatasetVariables(input);
        input.get("edsd").add("gender");

        assertThat(result.get("edsd")).containsExactly("dataset", "age");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> result.put("ppmi", List.of()))
                .isInstanceOf(UnsupportedOperationException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> result.get("edsd").add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void dropsNullVariableEntriesInsteadOfThrowing() {
        Map<String, Map<String, List<String>>> exaflow = JsonConverters.convertJsonStringToObject(
                "{\"dementia:0.1\":{\"edsd\":[\"age\",null,\"dataset\"],\"ppmi\":[null]}}",
                DATASETS_VARIABLES_TYPE);

        Map<String, List<String>> result =
                DataModelService.selectDatasetVariables(exaflow, dataModel("dementia", "0.1"));

        assertThat(result).containsOnlyKeys("edsd");
        assertThat(result.get("edsd")).containsExactly("age", "dataset");
    }

    @Test
    void emptyListFromExaflowIsTreatedAsUnknownNotAsZeroVariables() {
        Map<String, Map<String, List<String>>> exaflow =
                Map.of("dementia:0.1", Map.of("edsd", List.of(), "ppmi", List.of()));

        assertThat(DataModelService.selectDatasetVariables(exaflow, dataModel("dementia", "0.1"))).isEmpty();
    }

    @Test
    void returnsEmptyMapWhenDataModelIsMissingOrResponseIsNull() {
        Map<String, Map<String, List<String>>> exaflow =
                Map.of("tbi:0.1", Map.of("dummy_tbi", List.of("dataset")));

        assertThat(DataModelService.selectDatasetVariables(exaflow, dataModel("dementia", "0.1"))).isEmpty();
        assertThat(DataModelService.selectDatasetVariables(null, dataModel("dementia", "0.1"))).isEmpty();
        assertThat(DataModelService.keepKnownDatasetVariables(null)).isEmpty();
    }

    @Test
    void fallsBackToUnversionedDataModelKey() {
        Map<String, Map<String, List<String>>> exaflow =
                Map.of("dementia", Map.of("edsd", List.of("dataset", "age")));

        assertThat(DataModelService.selectDatasetVariables(exaflow, dataModel("dementia", "0.1")))
                .containsOnly(Map.entry("edsd", List.of("dataset", "age")));
    }

    @Test
    void versionedKeyTakesPrecedenceOverUnversionedKey() {
        Map<String, Map<String, List<String>>> exaflow = new HashMap<>();
        exaflow.put("dementia:0.1", Map.of("edsd", List.of("dataset", "age")));
        exaflow.put("dementia", Map.of("edsd", List.of("dataset")));

        assertThat(DataModelService.selectDatasetVariables(exaflow, dataModel("dementia", "0.1")))
                .containsOnly(Map.entry("edsd", List.of("dataset", "age")));
    }
}
