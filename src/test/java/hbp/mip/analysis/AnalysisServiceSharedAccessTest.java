package hbp.mip.analysis;

import hbp.mip.algorithm.AnalysisExecutionService;
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

/** Sharing does not open the data: readers of someone else's analysis need its datasets. Real ClaimUtils. */
@ExtendWith(MockitoExtension.class)
class AnalysisServiceSharedAccessTest {

    private static final String ANALYSIS = "{\"inputdata\":{\"data_model\":\"dm:1\",\"datasets\":[\"ds1\"]}}";

    @Mock
    private ActiveUserService activeUserService;
    @Mock
    private AnalysisRepository analysisRepository;
    @Mock
    private AnalysisRunRepository analysisRunRepository;
    @Mock
    private AnalysisExecutionService analysisExecutionService;

    private final Logger logger = new Logger("reader", "test");
    private AnalysisService service;

    @BeforeEach
    void setUp() {
        ClaimUtils claimUtils = new ClaimUtils();
        ReflectionTestUtils.setField(claimUtils, "allDatasetsAllowedClaim", "research_dataset_all");
        ReflectionTestUtils.setField(claimUtils, "allAnalysesAllowedClaim", "research_analysis_all");
        ReflectionTestUtils.setField(claimUtils, "datasetClaimPrefix", "research_dataset_");
        service = new AnalysisService(activeUserService, claimUtils, analysisRepository, analysisRunRepository,
                analysisExecutionService, true, "9.0.0", Duration.ofHours(24));
        lenient().when(activeUserService.getActiveUser(any()))
                .thenReturn(new UserDTO("reader", "Reader", "reader@example.org", "subject", true));
    }

    @Test
    void sharedAnalysisNeedsItsDatasets() {
        AnalysisDAO shared = stored(analysis("owner", true, ANALYSIS));

        assertThatThrownBy(() -> read(shared, "research_dataset_other")).isInstanceOf(UnauthorizedException.class);
        assertThat(read(shared, "research_dataset_ds1")).isSameAs(shared);
        assertThat(read(shared, "research_dataset_all")).isSameAs(shared);
    }

    @Test
    void sharedAnalysisWithoutKnownDatasetsIsRefused() {
        AnalysisDAO shared = stored(analysis("owner", true, "{}"));

        assertThatThrownBy(() -> read(shared, "research_dataset_ds1")).isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void ownerAndAllAnalysesRoleNeedNoDatasetRole() {
        AnalysisDAO mine = stored(analysis("reader", false, ANALYSIS));
        assertThat(read(mine)).isSameAs(mine);

        AnalysisDAO others = stored(analysis("owner", false, ANALYSIS));
        assertThat(read(others, "research_analysis_all")).isSameAs(others);
    }

    @Test
    void unsharedAnalysisStaysPrivateEvenWithItsDatasets() {
        AnalysisDAO others = stored(analysis("owner", false, ANALYSIS));

        assertThatThrownBy(() -> read(others, "research_dataset_ds1")).isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void listAsksTheDatabaseOnlyForSharedAnalysesOnTheUsersDatasets() {
        CriteriaBuilder cb = listedWith("research_dataset_DS1", "research_dataset_ds2", "other_role");

        verify(cb).literal("[\"ds1\",\"ds2\"]");
    }

    @Test
    void listDoesNotFilterOnDatasetsForTheAllDatasetsOrAllAnalysesRole() {
        verify(listedWith("research_dataset_all"), never()).literal(anyString());
        verify(listedWith("research_analysis_all"), never()).literal(anyString());
    }

    @Test
    void listWithNothingVisibleIsNoContent() {
        when(analysisRepository.findAll(any(Specification.class), any(Pageable.class))).thenReturn(Page.empty());

        assertThatThrownBy(() -> list()).isInstanceOf(NoContent.class);
    }

    @Test
    void storedAnalysisThatIsNotJsonListsAsNoAnalysisAndIsRefusedToOthers() {
        String errorMessage = "Failed to serialize the analysis";
        when(analysisRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(analysis("reader", false, errorMessage))));

        assertThat(list().analyses()).singleElement().satisfies(listed -> assertThat(listed.analysisRequest()).isNull());

        AnalysisDAO shared = stored(analysis("owner", true, errorMessage));
        assertThatThrownBy(() -> read(shared, "research_dataset_ds1")).isInstanceOf(UnauthorizedException.class);
    }

    private AnalysesDTO list(String... authorities) {
        return service.getAnalyses(user(authorities), null, null, null, null, true, false, false, 0, 10, "created",
                true, logger);
    }

    @SuppressWarnings("unchecked")
    private CriteriaBuilder listedWith(String... authorities) {
        clearInvocations(analysisRepository);
        when(analysisRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(analysis("reader", false, ANALYSIS))));
        list(authorities);

        ArgumentCaptor<Specification<AnalysisDAO>> spec = ArgumentCaptor.forClass(Specification.class);
        verify(analysisRepository).findAll(spec.capture(), any(Pageable.class));
        CriteriaBuilder cb = mock(CriteriaBuilder.class, RETURNS_DEEP_STUBS);
        spec.getValue().toPredicate(mock(Root.class, RETURNS_DEEP_STUBS), mock(CriteriaQuery.class, RETURNS_DEEP_STUBS), cb);
        return cb;
    }

    private AnalysisDAO read(AnalysisDAO analysis, String... authorities) {
        return service.assertAnalysisAccessible(user(authorities), analysis.getUuid().toString(), logger);
    }

    private AnalysisDAO stored(AnalysisDAO analysis) {
        when(analysisRepository.loadAnalysis(analysis.getUuid().toString(), logger)).thenReturn(analysis);
        return analysis;
    }

    private static Authentication user(String... authorities) {
        return new TestingAuthenticationToken("reader", "n/a", authorities);
    }

    private static AnalysisDAO analysis(String owner, boolean shared, String analysis) {
        AnalysisDAO analysis = new AnalysisDAO();
        analysis.setUuid(UUID.randomUUID());
        analysis.setCreatedBy(new UserDAO(owner, owner, owner + "@example.org", owner));
        analysis.setShared(shared);
        analysis.setAnalysisRequest(analysis);
        return analysis;
    }
}
