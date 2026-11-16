package hbp.mip.utils;

import hbp.mip.datamodel.DataModelDTO;
import hbp.mip.datamodel.DatasetLabels;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.UnauthorizedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Dataset roles name the dataset LABEL; numeric codes are only resolved to a label, never granted on their own. */
class ClaimUtilsDatasetLabelAccessTest {

    private static final String MODEL = "dementia:0.1";
    private static final DatasetLabels LABELS = new DatasetLabels(Map.of(
            MODEL, Map.of("12", "EDSD", "13", "Adni Study"),
            "tbi:0.1", Map.of("12", "TBI Core")));

    private final Logger logger = new Logger("user", "test");
    private ClaimUtils claimUtils;

    @BeforeEach
    void setUp() {
        claimUtils = new ClaimUtils();
        ReflectionTestUtils.setField(claimUtils, "allDatasetsAllowedClaim", "research_dataset_all");
        ReflectionTestUtils.setField(claimUtils, "allExperimentsAllowedClaim", "research_experiment_all");
        ReflectionTestUtils.setField(claimUtils, "datasetClaimPrefix", "research_dataset_");
    }

    private static Authentication withRoles(String... roles) {
        return new UsernamePasswordAuthenticationToken("user", "n/a",
                java.util.Arrays.stream(roles).map(SimpleGrantedAuthority::new).toList());
    }

    private boolean allowed(Authentication user, String dataModel, String... datasets) {
        return claimUtils.hasAccessRightsOnDatasets(user, dataModel, List.of(datasets), () -> LABELS, logger);
    }

    private void validate(Authentication user, String dataModel, String... datasets) {
        claimUtils.validateAccessRightsOnDatasets(user, dataModel, List.of(datasets), () -> LABELS, logger);
    }

    @Test
    void numericCodeIsAllowedWithTheLabelRole() {
        assertThat(allowed(withRoles("research_dataset_edsd"), MODEL, "12")).isTrue();
        assertThatCode(() -> validate(withRoles("research_dataset_edsd"), MODEL, "12")).doesNotThrowAnyException();
    }

    @Test
    void numericCodeIsDeniedWithOnlyTheCodeRole() {
        assertThat(allowed(withRoles("research_dataset_12"), MODEL, "12")).isFalse();
        assertThatThrownBy(() -> validate(withRoles("research_dataset_12"), MODEL, "12"))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void unknownCodeIsDeniedEvenWhenTheRoleExists() {
        assertThat(allowed(withRoles("research_dataset_99", "research_dataset_edsd"), MODEL, "99")).isFalse();
        assertThatThrownBy(() -> validate(withRoles("research_dataset_99"), MODEL, "99"))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void unknownDataModelOrNoLabelsAtAllIsDenied() {
        assertThat(allowed(withRoles("research_dataset_edsd"), "other:1.0", "12")).isFalse();
        assertThat(allowed(withRoles("research_dataset_edsd"), null, "12")).isFalse();
        assertThat(claimUtils.hasAccessRightsOnDatasets(withRoles("research_dataset_edsd"), MODEL, List.of("12"),
                () -> DatasetLabels.NONE, logger)).isFalse();
    }

    @Test
    void codesAreResolvedInsideTheirOwnDataModel() {
        assertThat(allowed(withRoles("research_dataset_tbi core"), "tbi:0.1", "12")).isTrue();
        assertThat(allowed(withRoles("research_dataset_edsd"), "tbi:0.1", "12")).isFalse();
    }

    @Test
    void legacyTextCodeMatchingALabelIsAllowedIgnoringCase() {
        assertThat(allowed(withRoles("research_dataset_edsd"), MODEL, "edsd")).isTrue();
        assertThat(allowed(withRoles("research_dataset_edsd"), MODEL, "EDSD")).isTrue();
        assertThat(allowed(withRoles("research_dataset_other"), MODEL, "edsd")).isFalse();
    }

    @Test
    void legacyTextCodeMatchingNoLabelIsDenied() {
        assertThat(allowed(withRoles("research_dataset_oldname"), MODEL, "oldname")).isFalse();
        assertThatThrownBy(() -> validate(withRoles("research_dataset_oldname"), MODEL, "oldname"))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void aCodeThatIsAlsoALabelOfAnotherDatasetResolvesAsTheCode() {
        DatasetLabels labels = new DatasetLabels(Map.of(MODEL, Map.of("1", "Two", "2", "One")));

        assertThat(labels.labelsFor(MODEL, "1")).containsExactly("Two");
        assertThat(labels.labelsFor(MODEL, "one")).containsExactly("One");
    }

    @Test
    void anAmbiguousReferenceNeedsTheRoleOfEveryDatasetItCouldBe() {
        DatasetLabels labels = new DatasetLabels(Map.of(MODEL, Map.of("a", "First", "A", "Second")));

        assertThat(claimUtils.hasAccessRightsOnDatasets(withRoles("research_dataset_first"), MODEL, List.of("a"),
                () -> labels, logger)).isFalse();
        assertThat(claimUtils.hasAccessRightsOnDatasets(withRoles("research_dataset_first", "research_dataset_second"),
                MODEL, List.of("a"), () -> labels, logger)).isTrue();
    }

    @Test
    void labelRolesIgnoreCaseAndWhitespaceLikeCodeRolesDid() {
        assertThat(allowed(withRoles("RESEARCH_DATASET_ADNI STUDY"), MODEL, "13")).isTrue();
        assertThat(allowed(withRoles("research_dataset_adnistudy"), MODEL, "13")).isTrue();
        assertThat(allowed(withRoles(" research_dataset_Adni  Study "), MODEL, "13")).isTrue();
    }

    @Test
    void everyDatasetOfTheRequestNeedsItsRole() {
        assertThat(allowed(withRoles("research_dataset_edsd"), MODEL, "12", "13")).isFalse();
        assertThat(allowed(withRoles("research_dataset_edsd", "research_dataset_adni study"), MODEL, "12", "13"))
                .isTrue();
    }

    @Test
    void allDatasetsRoleNeedsNoLabelsAndNeverFetchesThem() {
        Authentication admin = withRoles("research_dataset_all");

        assertThatCode(() -> claimUtils.validateAccessRightsOnDatasets(admin, MODEL, List.of("99", "unknown"),
                () -> {
                    throw new AssertionError("labels must not be fetched");
                }, logger)).doesNotThrowAnyException();
        assertThat(claimUtils.hasAccessRightsOnDatasets(admin, "x", List.of("99"), () -> {
            throw new AssertionError("labels must not be fetched");
        }, logger)).isTrue();
        assertThat(claimUtils.usableDatasets(admin, () -> {
            throw new AssertionError("labels must not be fetched");
        }, logger)).isNull();
    }

    @Test
    void noDatasetsIsStillABadRequestOrNoAccess() {
        assertThatThrownBy(() -> claimUtils.validateAccessRightsOnDatasets(withRoles("research_dataset_all"), MODEL,
                List.of(), () -> LABELS, logger)).isInstanceOf(BadRequestException.class);
        assertThat(claimUtils.hasAccessRightsOnDatasets(withRoles("research_dataset_all"), MODEL, null,
                () -> LABELS, logger)).isFalse();
    }

    @Test
    void aRoleWithCommasCannotImpersonateAnother() {
        assertThat(allowed(withRoles("x,research_dataset_edsd"), MODEL, "12")).isFalse();
    }

    @Test
    void usableDatasetsListsCodesAndLabelsPerDataModelForTheLabelRolesHeld() {
        Map<String, List<String>> usable = claimUtils.usableDatasets(
                withRoles("research_dataset_edsd", "research_dataset_12"), () -> LABELS, logger);

        assertThat(usable).containsOnly(Map.entry(MODEL, List.of("12", "edsd")));
    }

    @Test
    void dataModelsListOnlyDatasetsWhoseLabelRoleIsHeld() {
        DataModelDTO model = new DataModelDTO("dementia", "0.1", "Dementia", false, List.of(), List.of(),
                List.of(new DataModelDTO.EnumerationDTO("12", "EDSD"),
                        new DataModelDTO.EnumerationDTO("13", "Adni Study"),
                        new DataModelDTO.EnumerationDTO("14", null),
                        new DataModelDTO.EnumerationDTO("15", " ")),
                Map.of("12", List.of("age"), "13", List.of("age")));

        List<DataModelDTO> byLabel = claimUtils.getAuthorizedDataModels(logger,
                withRoles("research_dataset_edsd", "research_dataset_14", "research_dataset_15"), List.of(model));
        List<DataModelDTO> byCode = claimUtils.getAuthorizedDataModels(logger,
                withRoles("research_dataset_12", "research_dataset_13"), List.of(model));

        assertThat(byLabel).singleElement().satisfies(m -> {
            assertThat(m.datasets()).extracting(DataModelDTO.EnumerationDTO::code).containsExactly("12");
            assertThat(m.datasetsVariables()).containsOnlyKeys("12");
        });
        assertThat(byCode).isEmpty();
        assertThat(claimUtils.getAuthorizedDataModels(logger, withRoles("research_dataset_all"), List.of(model)))
                .containsExactly(model);
    }
}
