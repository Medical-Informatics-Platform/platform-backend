package hbp.mip.analysis;

import hbp.mip.algorithm.AnalysisRequestDTO;
import hbp.mip.algorithm.AnalysisExecutionService;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.ClaimUtils;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.AnalysisNotFoundException;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AnalysisServiceRunSaveTest {

    private static final UserDTO USER = new UserDTO("user", "User", "user@example.org", "subject", true);

    @Mock
    private ActiveUserService activeUserService;

    @Mock
    private ClaimUtils claimUtils;

    @Mock
    private AnalysisRepository analysisRepository;

    @Mock
    private AnalysisRunRepository analysisRunRepository;

    @Mock
    private AnalysisExecutionService analysisExecutionService;

    @Mock
    private Authentication authentication;

    private final Logger logger = new Logger("user", "test");

    private AnalysisService analysisService;

    @BeforeEach
    void setUp() {
        analysisService = service(false);
    }

    @Test
    void runAnalysis_keepsSuccessfulRunForSaving() {
        var execution = sampleExecution();
        when(analysisExecutionService.runAnalysis(any(UUID.class), eq(execution.analysisRequest()), any(Logger.class)))
                .thenReturn(new AnalysisExecutionService.AnalysisResultDTO(200, Map.of("ok", true)));

        var response = analysisService.runAnalysis(authentication, USER, execution, logger);

        var kept = ArgumentCaptor.forClass(AnalysisRunDAO.class);
        verify(analysisRunRepository).deleteCreatedBefore(any(Date.class));
        verify(analysisRunRepository).save(kept.capture());
        assertThat(response.status()).isEqualTo(AnalysisDAO.Status.success);
        assertThat(kept.getValue().getUuid()).isEqualTo(response.uuid());
        assertThat(kept.getValue().getCreatedByUsername()).isEqualTo("user");
        assertThat(kept.getValue().getAlgorithmId()).isEqualTo("histogram");
        assertThat(kept.getValue().getResult()).isEqualTo(JsonConverters.convertObjectToJsonString(Map.of("ok", true)));
        assertThat(kept.getValue().getMipVersion()).isEqualTo("9.0.0");
        assertThat(kept.getValue().getCreated()).isBeforeOrEqualTo(kept.getValue().getFinished());
    }

    @Test
    void runAnalysis_doesNotKeepFailedRun() {
        var execution = sampleExecution();
        when(analysisExecutionService.runAnalysis(any(UUID.class), eq(execution.analysisRequest()), any(Logger.class)))
                .thenReturn(new AnalysisExecutionService.AnalysisResultDTO(500, Map.of("message", "boom")));

        var response = analysisService.runAnalysis(authentication, USER, execution, logger);

        assertThat(response.status()).isEqualTo(AnalysisDAO.Status.error);
        verify(analysisRunRepository, never()).save(any());
    }

    @Test
    void runAnalysis_returnsResultWhenRunCannotBeKept() {
        var execution = sampleExecution();
        when(analysisExecutionService.runAnalysis(any(UUID.class), eq(execution.analysisRequest()), any(Logger.class)))
                .thenReturn(new AnalysisExecutionService.AnalysisResultDTO(200, Map.of("ok", true)));
        when(analysisRunRepository.deleteCreatedBefore(any(Date.class))).thenThrow(new RuntimeException("purge"));
        when(analysisRunRepository.save(any())).thenThrow(new RuntimeException("db down"));

        var response = analysisService.runAnalysis(authentication, USER, execution, logger);

        assertThat(response.status()).isEqualTo(AnalysisDAO.Status.success);
        assertThat(response.result()).isEqualTo(Map.of("ok", true));
    }

    @Test
    void saveAnalysisRun_rejectsInvalidRunId() {
        assertThatThrownBy(() -> analysisService.saveAnalysisRun(USER, "not-a-uuid", "name",
                logger)).isInstanceOf(BadRequestException.class);
        verifyNoInteractions(analysisRunRepository, analysisRepository);
    }

    @Test
    void saveAnalysisRun_copiesKeptRunWithoutRunningAnalysis() {
        var run = keptRun("user", hoursAgo(2));
        when(analysisRunRepository.findById(run.getUuid())).thenReturn(Optional.of(run));
        when(analysisRepository.createAnalysisFromRun(any(), anyString(), any(), any())).thenCallRealMethod();

        var response = analysisService.saveAnalysisRun(USER, run.getUuid().toString(),
                "  My analysis  ", logger);

        var saved = ArgumentCaptor.forClass(AnalysisDAO.class);
        verify(analysisRepository).save(saved.capture());
        var analysis = saved.getValue();
        assertThat(analysis.getUuid()).isNotEqualTo(run.getUuid());
        assertThat(analysis.getName()).isEqualTo("My analysis");
        assertThat(analysis.getCreatedBy().getUsername()).isEqualTo("user");
        assertThat(analysis.getStatus()).isEqualTo(AnalysisDAO.Status.success);
        assertThat(analysis.getResult()).isEqualTo(run.getResult());
        assertThat(analysis.getAnalysisRequest()).isEqualTo(run.getAnalysisRequest());
        assertThat(analysis.getAlgorithmId()).isEqualTo("histogram");
        assertThat(analysis.getCreated()).isEqualTo(run.getCreated());
        assertThat(analysis.getFinished()).isEqualTo(run.getFinished());
        assertThat(analysis.getMipVersion()).isEqualTo("8.0.0");
        assertThat(response.uuid()).isEqualTo(analysis.getUuid());
        assertThat(response.status()).isEqualTo(AnalysisDAO.Status.success);
        verifyNoInteractions(analysisExecutionService);
    }

    @Test
    void saveAnalysisRun_doesNotRecheckDatasetAccess() {
        analysisService = service(true);
        var run = keptRun("user", hoursAgo(1));
        when(analysisRunRepository.findById(run.getUuid())).thenReturn(Optional.of(run));
        when(analysisRepository.createAnalysisFromRun(any(), anyString(), any(), any())).thenCallRealMethod();

        analysisService.saveAnalysisRun(USER, run.getUuid().toString(), "name", logger);

        verifyNoInteractions(claimUtils);
    }

    @Test
    void saveAnalysisRun_treatsAnotherUsersRunAsMissing() {
        var run = keptRun("someone-else", hoursAgo(1));
        when(analysisRunRepository.findById(run.getUuid())).thenReturn(Optional.of(run));

        assertThatThrownBy(() -> analysisService.saveAnalysisRun(USER, run.getUuid().toString(),
                "name", logger)).isInstanceOf(AnalysisNotFoundException.class);
        verify(analysisRepository, never()).save(any());
    }

    @Test
    void saveAnalysisRun_rejectsExpiredRun() {
        var run = keptRun("user", hoursAgo(25));
        when(analysisRunRepository.findById(run.getUuid())).thenReturn(Optional.of(run));

        assertThatThrownBy(() -> analysisService.saveAnalysisRun(USER, run.getUuid().toString(),
                "name", logger)).isInstanceOf(AnalysisNotFoundException.class);
        verify(analysisRepository, never()).save(any());
    }

    @Test
    void saveAnalysisRun_rejectsUnknownRun() {
        var runId = UUID.randomUUID();
        when(analysisRunRepository.findById(runId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> analysisService.saveAnalysisRun(USER, runId.toString(), "name", logger))
                .isInstanceOf(AnalysisNotFoundException.class);
    }

    @Test
    void saveAnalysisRun_rejectsMissingRunId() {
        assertThatThrownBy(() -> analysisService.saveAnalysisRun(USER, null, "name", logger))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(analysisRunRepository, analysisRepository);
    }

    @Test
    void saveAnalysisRun_rejectsBlankName() {
        assertThatThrownBy(() -> analysisService.saveAnalysisRun(USER, UUID.randomUUID().toString(),
                "   ", logger)).isInstanceOf(BadRequestException.class);
        verifyNoInteractions(analysisRunRepository, analysisRepository);
    }

    private AnalysisService service(boolean authenticationIsEnabled) {
        return new AnalysisService(activeUserService, claimUtils, analysisRepository, analysisRunRepository,
                analysisExecutionService, authenticationIsEnabled, "9.0.0", Duration.ofHours(24));
    }

    private AnalysisRunDAO keptRun(String owner, Date created) {
        var run = new AnalysisRunDAO();
        run.setUuid(UUID.randomUUID());
        run.setCreatedByUsername(owner);
        run.setAnalysisRequest(JsonConverters.convertObjectToJsonString(sampleExecution().analysisRequest()));
        run.setAlgorithmId("histogram");
        run.setResult("{\"ok\":true}");
        run.setCreated(created);
        run.setFinished(new Date(created.getTime() + 1000));
        run.setMipVersion("8.0.0");
        return run;
    }

    private static Date hoursAgo(long hours) {
        return new Date(System.currentTimeMillis() - Duration.ofHours(hours).toMillis());
    }

    private AnalysisExecutionDTO sampleExecution() {
        var analysis = new AnalysisRequestDTO(
                null,
                new AnalysisRequestDTO.AnalysisInputDataDTO(
                        "dm:1",
                        List.of("ds1"),
                        null,
                        null,
                        List.of("age")),
                null,
                new AnalysisRequestDTO.AnalysisAlgorithmDTO(
                        "histogram",
                        null,
                        List.of("age"),
                        Map.of()),
                null);
        return new AnalysisExecutionDTO("test analysis", analysis);
    }
}
