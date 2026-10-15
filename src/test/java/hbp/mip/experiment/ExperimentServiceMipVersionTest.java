package hbp.mip.experiment;

import hbp.mip.algorithm.AnalysisRequestDTO;
import hbp.mip.algorithm.AnalysisService;
import hbp.mip.user.ActiveUserService;
import hbp.mip.utils.ClaimUtils;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ExperimentServiceMipVersionTest {

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

    private ExperimentService experimentService;

    @BeforeEach
    void setUp() {
        experimentService = new ExperimentService(activeUserService, claimUtils, experimentRepository,
                experimentRunRepository, analysisService, false, "9.0.0", Duration.ofHours(24));
    }

    @Test
    void previewExperiment_returnsMipVersionFromEnvironment() {
        var execution = sampleExecution();

        when(analysisService.runAnalysis(any(UUID.class), eq(execution.analysis()), any(Logger.class)))
                .thenReturn(new AnalysisService.AnalysisResultDTO(200, Map.of("ok", true)));

        var response = experimentService.previewExperiment(authentication, execution, new Logger("user", "test"));

        assertThat(response.mipVersion()).isEqualTo("9.0.0");
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
