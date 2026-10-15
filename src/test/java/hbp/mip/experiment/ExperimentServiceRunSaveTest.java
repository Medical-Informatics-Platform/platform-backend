package hbp.mip.experiment;

import hbp.mip.algorithm.AnalysisRequestDTO;
import hbp.mip.algorithm.AnalysisService;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.ClaimUtils;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.ExperimentNotFoundException;
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
class ExperimentServiceRunSaveTest {

    private static final UserDTO USER = new UserDTO("user", "User", "user@example.org", "subject", true);

    @Mock
    private ActiveUserService activeUserService;

    @Mock
    private ClaimUtils claimUtils;

    @Mock
    private ExperimentRepository experimentRepository;

    @Mock
    private ExperimentRunRepository experimentRunRepository;

    @Mock
    private AnalysisService analysisService;

    @Mock
    private Authentication authentication;

    private final Logger logger = new Logger("user", "test");

    private ExperimentService experimentService;

    @BeforeEach
    void setUp() {
        experimentService = service(false);
    }

    @Test
    void runExperiment_keepsSuccessfulRunForSaving() {
        var execution = sampleExecution();
        when(analysisService.runAnalysis(any(UUID.class), eq(execution.analysis()), any(Logger.class)))
                .thenReturn(new AnalysisService.AnalysisResultDTO(200, Map.of("ok", true)));

        var response = experimentService.runExperiment(authentication, USER, execution, logger);

        var kept = ArgumentCaptor.forClass(ExperimentRunDAO.class);
        verify(experimentRunRepository).deleteCreatedBefore(any(Date.class));
        verify(experimentRunRepository).save(kept.capture());
        assertThat(response.status()).isEqualTo(ExperimentDAO.Status.success);
        assertThat(kept.getValue().getUuid()).isEqualTo(response.uuid());
        assertThat(kept.getValue().getCreatedByUsername()).isEqualTo("user");
        assertThat(kept.getValue().getAlgorithmId()).isEqualTo("histogram");
        assertThat(kept.getValue().getResult()).isEqualTo(JsonConverters.convertObjectToJsonString(Map.of("ok", true)));
        assertThat(kept.getValue().getMipVersion()).isEqualTo("9.0.0");
        assertThat(kept.getValue().getCreated()).isBeforeOrEqualTo(kept.getValue().getFinished());
    }

    @Test
    void runExperiment_doesNotKeepFailedRun() {
        var execution = sampleExecution();
        when(analysisService.runAnalysis(any(UUID.class), eq(execution.analysis()), any(Logger.class)))
                .thenReturn(new AnalysisService.AnalysisResultDTO(500, Map.of("message", "boom")));

        var response = experimentService.runExperiment(authentication, USER, execution, logger);

        assertThat(response.status()).isEqualTo(ExperimentDAO.Status.error);
        verify(experimentRunRepository, never()).save(any());
    }

    @Test
    void runExperiment_returnsResultWhenRunCannotBeKept() {
        var execution = sampleExecution();
        when(analysisService.runAnalysis(any(UUID.class), eq(execution.analysis()), any(Logger.class)))
                .thenReturn(new AnalysisService.AnalysisResultDTO(200, Map.of("ok", true)));
        when(experimentRunRepository.deleteCreatedBefore(any(Date.class))).thenThrow(new RuntimeException("purge"));
        when(experimentRunRepository.save(any())).thenThrow(new RuntimeException("db down"));

        var response = experimentService.runExperiment(authentication, USER, execution, logger);

        assertThat(response.status()).isEqualTo(ExperimentDAO.Status.success);
        assertThat(response.result()).isEqualTo(Map.of("ok", true));
    }

    @Test
    void saveExperimentRun_rejectsInvalidRunId() {
        assertThatThrownBy(() -> experimentService.saveExperimentRun(authentication, USER, "not-a-uuid", "name",
                logger)).isInstanceOf(BadRequestException.class);
        verifyNoInteractions(experimentRunRepository, experimentRepository);
    }

    @Test
    void saveExperimentRun_copiesKeptRunWithoutRunningAnalysis() {
        var run = keptRun("user", hoursAgo(2));
        when(experimentRunRepository.findById(run.getUuid())).thenReturn(Optional.of(run));
        when(experimentRepository.createExperimentFromRun(any(), anyString(), any(), any())).thenCallRealMethod();

        var response = experimentService.saveExperimentRun(authentication, USER, run.getUuid().toString(),
                "  My experiment  ", logger);

        var saved = ArgumentCaptor.forClass(ExperimentDAO.class);
        verify(experimentRepository).save(saved.capture());
        var experiment = saved.getValue();
        assertThat(experiment.getUuid()).isNotEqualTo(run.getUuid());
        assertThat(experiment.getName()).isEqualTo("My experiment");
        assertThat(experiment.getCreatedBy().getUsername()).isEqualTo("user");
        assertThat(experiment.getStatus()).isEqualTo(ExperimentDAO.Status.success);
        assertThat(experiment.getResult()).isEqualTo(run.getResult());
        assertThat(experiment.getAlgorithm()).isEqualTo(run.getAlgorithm());
        assertThat(experiment.getAlgorithmId()).isEqualTo("histogram");
        assertThat(experiment.getCreated()).isEqualTo(run.getCreated());
        assertThat(experiment.getFinished()).isEqualTo(run.getFinished());
        assertThat(experiment.getMipVersion()).isEqualTo("8.0.0");
        assertThat(response.uuid()).isEqualTo(experiment.getUuid());
        assertThat(response.status()).isEqualTo(ExperimentDAO.Status.success);
        verifyNoInteractions(analysisService);
    }

    @Test
    void saveExperimentRun_rechecksDatasetAccessWhenAuthenticationIsEnabled() {
        experimentService = service(true);
        var run = keptRun("user", hoursAgo(1));
        when(experimentRunRepository.findById(run.getUuid())).thenReturn(Optional.of(run));
        when(experimentRepository.createExperimentFromRun(any(), anyString(), any(), any())).thenCallRealMethod();

        experimentService.saveExperimentRun(authentication, USER, run.getUuid().toString(), "name", logger);

        verify(claimUtils).validateAccessRightsOnDatasets(eq(authentication), eq(List.of("ds1")), any(Logger.class));
    }

    @Test
    void saveExperimentRun_treatsAnotherUsersRunAsMissing() {
        var run = keptRun("someone-else", hoursAgo(1));
        when(experimentRunRepository.findById(run.getUuid())).thenReturn(Optional.of(run));

        assertThatThrownBy(() -> experimentService.saveExperimentRun(authentication, USER, run.getUuid().toString(),
                "name", logger)).isInstanceOf(ExperimentNotFoundException.class);
        verify(experimentRepository, never()).save(any());
    }

    @Test
    void saveExperimentRun_rejectsExpiredRun() {
        var run = keptRun("user", hoursAgo(25));
        when(experimentRunRepository.findById(run.getUuid())).thenReturn(Optional.of(run));

        assertThatThrownBy(() -> experimentService.saveExperimentRun(authentication, USER, run.getUuid().toString(),
                "name", logger)).isInstanceOf(ExperimentNotFoundException.class);
        verify(experimentRepository, never()).save(any());
    }

    @Test
    void saveExperimentRun_rejectsUnknownRun() {
        var runId = UUID.randomUUID();
        when(experimentRunRepository.findById(runId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> experimentService.saveExperimentRun(authentication, USER, runId.toString(), "name", logger))
                .isInstanceOf(ExperimentNotFoundException.class);
    }

    @Test
    void saveExperimentRun_rejectsBlankName() {
        assertThatThrownBy(() -> experimentService.saveExperimentRun(authentication, USER, UUID.randomUUID().toString(),
                "   ", logger)).isInstanceOf(BadRequestException.class);
        verifyNoInteractions(experimentRunRepository, experimentRepository);
    }

    private ExperimentService service(boolean authenticationIsEnabled) {
        return new ExperimentService(activeUserService, claimUtils, experimentRepository, experimentRunRepository,
                analysisService, authenticationIsEnabled, "9.0.0", Duration.ofHours(24));
    }

    private ExperimentRunDAO keptRun(String owner, Date created) {
        var run = new ExperimentRunDAO();
        run.setUuid(UUID.randomUUID());
        run.setCreatedByUsername(owner);
        run.setAlgorithm(JsonConverters.convertObjectToJsonString(sampleExecution().analysis()));
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

    private ExperimentExecutionDTO sampleExecution() {
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
        return new ExperimentExecutionDTO("test experiment", analysis);
    }
}
