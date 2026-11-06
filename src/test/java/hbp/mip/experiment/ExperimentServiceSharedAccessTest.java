package hbp.mip.experiment;

import hbp.mip.algorithm.AnalysisService;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDAO;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.ClaimUtils;
import hbp.mip.utils.Exceptions.NoContent;
import hbp.mip.utils.Exceptions.UnauthorizedException;
import hbp.mip.utils.Logger;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Sharing does not open the data: readers of someone else's experiment need its datasets. Real ClaimUtils. */
@ExtendWith(MockitoExtension.class)
class ExperimentServiceSharedAccessTest {

    private static final String ANALYSIS = "{\"inputdata\":{\"data_model\":\"dm:1\",\"datasets\":[\"ds1\"]}}";

    @Mock
    private ActiveUserService activeUserService;
    @Mock
    private ExperimentRepository experimentRepository;
    @Mock
    private ExperimentRunRepository experimentRunRepository;
    @Mock
    private AnalysisService analysisService;

    private final Logger logger = new Logger("reader", "test");
    private ExperimentService service;

    @BeforeEach
    void setUp() {
        ClaimUtils claimUtils = new ClaimUtils();
        ReflectionTestUtils.setField(claimUtils, "allDatasetsAllowedClaim", "research_dataset_all");
        ReflectionTestUtils.setField(claimUtils, "allExperimentsAllowedClaim", "research_experiment_all");
        ReflectionTestUtils.setField(claimUtils, "datasetClaimPrefix", "research_dataset_");
        service = new ExperimentService(activeUserService, claimUtils, experimentRepository, experimentRunRepository,
                analysisService, true, "9.0.0", Duration.ofHours(24));
        lenient().when(activeUserService.getActiveUser(any()))
                .thenReturn(new UserDTO("reader", "Reader", "reader@example.org", "subject", true));
    }

    @Test
    void sharedExperimentNeedsItsDatasets() {
        ExperimentDAO shared = stored(experiment("owner", true, ANALYSIS));

        assertThatThrownBy(() -> read(shared, "research_dataset_other")).isInstanceOf(UnauthorizedException.class);
        assertThat(read(shared, "research_dataset_ds1")).isSameAs(shared);
        assertThat(read(shared, "research_dataset_all")).isSameAs(shared);
    }

    @Test
    void sharedExperimentWithoutKnownDatasetsIsRefused() {
        ExperimentDAO shared = stored(experiment("owner", true, "{}"));

        assertThatThrownBy(() -> read(shared, "research_dataset_ds1")).isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void ownerAndAllExperimentsRoleNeedNoDatasetRole() {
        ExperimentDAO mine = stored(experiment("reader", false, ANALYSIS));
        assertThat(read(mine)).isSameAs(mine);

        ExperimentDAO others = stored(experiment("owner", false, ANALYSIS));
        assertThat(read(others, "research_experiment_all")).isSameAs(others);
    }

    @Test
    void unsharedExperimentStaysPrivateEvenWithItsDatasets() {
        ExperimentDAO others = stored(experiment("owner", false, ANALYSIS));

        assertThatThrownBy(() -> read(others, "research_dataset_ds1")).isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void listAsksTheDatabaseOnlyForSharedExperimentsOnTheUsersDatasets() {
        CriteriaBuilder cb = listedWith("research_dataset_DS1", "research_dataset_ds2", "other_role");

        verify(cb).literal("[\"ds1\",\"ds2\"]");
    }

    @Test
    void listDoesNotFilterOnDatasetsForTheAllDatasetsOrAllExperimentsRole() {
        verify(listedWith("research_dataset_all"), never()).literal(anyString());
        verify(listedWith("research_experiment_all"), never()).literal(anyString());
    }

    @Test
    void listWithNothingVisibleIsNoContent() {
        when(experimentRepository.findAll(any(Specification.class), any(Pageable.class))).thenReturn(Page.empty());

        assertThatThrownBy(() -> list()).isInstanceOf(NoContent.class);
    }

    @Test
    void storedAnalysisThatIsNotJsonListsAsNoAnalysisAndIsRefusedToOthers() {
        String errorMessage = "Failed to serialize the analysis";
        when(experimentRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(experiment("reader", false, errorMessage))));

        assertThat(list().experiments()).singleElement().satisfies(listed -> assertThat(listed.analysis()).isNull());

        ExperimentDAO shared = stored(experiment("owner", true, errorMessage));
        assertThatThrownBy(() -> read(shared, "research_dataset_ds1")).isInstanceOf(UnauthorizedException.class);
    }

    private ExperimentsDTO list(String... authorities) {
        return service.getExperiments(user(authorities), null, null, null, null, true, false, false, 0, 10, "created",
                true, logger);
    }

    @SuppressWarnings("unchecked")
    private CriteriaBuilder listedWith(String... authorities) {
        clearInvocations(experimentRepository);
        when(experimentRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(experiment("reader", false, ANALYSIS))));
        list(authorities);

        ArgumentCaptor<Specification<ExperimentDAO>> spec = ArgumentCaptor.forClass(Specification.class);
        verify(experimentRepository).findAll(spec.capture(), any(Pageable.class));
        CriteriaBuilder cb = mock(CriteriaBuilder.class, RETURNS_DEEP_STUBS);
        spec.getValue().toPredicate(mock(Root.class, RETURNS_DEEP_STUBS), mock(CriteriaQuery.class, RETURNS_DEEP_STUBS), cb);
        return cb;
    }

    private ExperimentDAO read(ExperimentDAO experiment, String... authorities) {
        return service.assertExperimentAccessible(user(authorities), experiment.getUuid().toString(), logger);
    }

    private ExperimentDAO stored(ExperimentDAO experiment) {
        when(experimentRepository.loadExperiment(experiment.getUuid().toString(), logger)).thenReturn(experiment);
        return experiment;
    }

    private static Authentication user(String... authorities) {
        return new TestingAuthenticationToken("reader", "n/a", authorities);
    }

    private static ExperimentDAO experiment(String owner, boolean shared, String analysis) {
        ExperimentDAO experiment = new ExperimentDAO();
        experiment.setUuid(UUID.randomUUID());
        experiment.setCreatedBy(new UserDAO(owner, owner, owner + "@example.org", owner));
        experiment.setShared(shared);
        experiment.setAnalysis(analysis);
        return experiment;
    }
}
