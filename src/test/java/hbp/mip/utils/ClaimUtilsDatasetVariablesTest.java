package hbp.mip.utils;

import hbp.mip.datamodel.DataModelDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ClaimUtilsDatasetVariablesTest {

    private final Logger logger = new Logger("user", "test");
    private ClaimUtils claimUtils;

    @BeforeEach
    void setUp() {
        claimUtils = new ClaimUtils();
        ReflectionTestUtils.setField(claimUtils, "allDatasetsAllowedClaim", "role_research_dataset_all");
        ReflectionTestUtils.setField(claimUtils, "allExperimentsAllowedClaim", "role_research_experiment_all");
        ReflectionTestUtils.setField(claimUtils, "datasetClaimPrefix", "role_research_dataset_");
    }

    private static Authentication withRoles(String... roles) {
        return new UsernamePasswordAuthenticationToken("user", "n/a",
                java.util.Arrays.stream(roles).map(SimpleGrantedAuthority::new).toList());
    }

    private static DataModelDTO dataModel(Map<String, List<String>> datasetsVariables) {
        return new DataModelDTO("dementia", "0.1", "Dementia", false, List.of(), List.of(),
                List.of(new DataModelDTO.EnumerationDTO("edsd", "EDSD"),
                        new DataModelDTO.EnumerationDTO("ppmi", "PPMI"),
                        new DataModelDTO.EnumerationDTO("desd", "DESD")),
                datasetsVariables);
    }

    @Test
    void omitsAuthorizedDatasetWithoutVariableInfoInsteadOfSendingEmptyList() {
        DataModelDTO model = dataModel(Map.of("edsd", List.of("dataset", "age")));

        List<DataModelDTO> result = claimUtils.getAuthorizedDataModels(logger,
                withRoles("role_research_dataset_edsd", "role_research_dataset_ppmi"), List.of(model));

        assertThat(result).hasSize(1);
        assertThat(result.get(0).datasets()).extracting(DataModelDTO.EnumerationDTO::code)
                .containsExactly("edsd", "ppmi");
        assertThat(result.get(0).datasetsVariables())
                .containsOnly(Map.entry("edsd", List.of("dataset", "age")));
    }

    @Test
    void omitsAuthorizedDatasetWithEmptyVariableListLikeDataModelService() {
        DataModelDTO model = dataModel(Map.of("edsd", List.of("dataset", "age"), "ppmi", List.of()));

        List<DataModelDTO> result = claimUtils.getAuthorizedDataModels(logger,
                withRoles("role_research_dataset_edsd", "role_research_dataset_ppmi"), List.of(model));

        assertThat(result).hasSize(1);
        assertThat(result.get(0).datasets()).extracting(DataModelDTO.EnumerationDTO::code)
                .containsExactly("edsd", "ppmi");
        assertThat(result.get(0).datasetsVariables())
                .containsOnly(Map.entry("edsd", List.of("dataset", "age")));
    }

    @Test
    void keepsAuthorizedDatasetsWhenDatasetsVariablesIsNull() {
        List<DataModelDTO> result = claimUtils.getAuthorizedDataModels(logger,
                withRoles("role_research_dataset_ppmi"), List.of(dataModel(null)));

        assertThat(result).hasSize(1);
        assertThat(result.get(0).datasets()).extracting(DataModelDTO.EnumerationDTO::code)
                .containsExactly("ppmi");
        assertThat(result.get(0).datasetsVariables()).isEmpty();
    }

    @Test
    void filtersVariablesToAuthorizedDatasetsAndPassesListsThrough() {
        DataModelDTO model = dataModel(Map.of(
                "edsd", List.of("dataset", "age"),
                "ppmi", List.of("dataset", "gender"),
                "desd", List.of("dataset")));

        List<DataModelDTO> result = claimUtils.getAuthorizedDataModels(logger,
                withRoles("role_research_dataset_ppmi"), List.of(model));

        assertThat(result).hasSize(1);
        assertThat(result.get(0).datasetsVariables())
                .containsOnly(Map.entry("ppmi", List.of("dataset", "gender")));
    }

    @Test
    void sendsEmptyMapWhenNoAuthorizedDatasetHasVariableInfo() {
        List<DataModelDTO> result = claimUtils.getAuthorizedDataModels(logger,
                withRoles("role_research_dataset_ppmi"), List.of(dataModel(Map.of())));

        assertThat(result).hasSize(1);
        assertThat(result.get(0).datasetsVariables()).isEmpty();
    }

    @Test
    void returnsModelsUnchangedForAllDatasetsClaim() {
        DataModelDTO model = dataModel(Map.of("edsd", List.of("dataset")));

        List<DataModelDTO> result = claimUtils.getAuthorizedDataModels(logger,
                withRoles("role_research_dataset_all"), List.of(model));

        assertThat(result).containsExactly(model);
    }
}
