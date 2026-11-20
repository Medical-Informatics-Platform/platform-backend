package hbp.mip.analysis;

import hbp.mip.algorithm.AnalysisRequestDTO;
import hbp.mip.algorithm.AnalysisExecutionService;
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
class AnalysisServiceMipVersionTest {

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

    private AnalysisService analysisService;

    @BeforeEach
    void setUp() {
        analysisService = new AnalysisService(activeUserService, claimUtils, analysisRepository,
                analysisRunRepository, analysisExecutionService, false, "9.0.0", Duration.ofHours(24));
    }

    @Test
    void previewAnalysis_returnsMipVersionFromEnvironment() {
        var execution = sampleExecution();

        when(analysisExecutionService.previewAnalysis(any(UUID.class), eq(execution.analysisRequest()), any(Logger.class)))
                .thenReturn(new AnalysisExecutionService.AnalysisResultDTO(200, Map.of("ok", true)));

        var response = analysisService.previewAnalysis(authentication, execution, new Logger("user", "test"));

        assertThat(response.mipVersion()).isEqualTo("9.0.0");
    }

    private AnalysisExecutionDTO sampleExecution() {
        var analysisRequest = new AnalysisRequestDTO(
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
                        Map.of()));
        return new AnalysisExecutionDTO("test analysis", analysisRequest);
    }
}
