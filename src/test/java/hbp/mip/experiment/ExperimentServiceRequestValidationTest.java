package hbp.mip.experiment;

import hbp.mip.algorithm.AnalysisRequestDTO;
import hbp.mip.algorithm.AnalysisService;
import hbp.mip.user.ActiveUserService;
import hbp.mip.utils.ClaimUtils;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ExperimentServiceRequestValidationTest {

    @Mock
    private ActiveUserService activeUserService;

    @Mock
    private ClaimUtils claimUtils;

    @Mock
    private ExperimentRepository experimentRepository;

    @Mock
    private AnalysisService analysisService;

    @Mock
    private Authentication authentication;

    private final Logger logger = new Logger("user", "test");

    @Test
    void createExperiment_rejectsAnalysisWithoutAlgorithm() {
        var service = service(false);
        var execution = new ExperimentExecutionDTO("test", new AnalysisRequestDTO(null, null, null, null, null));

        assertThatThrownBy(() -> service.createExperiment(authentication, execution, logger))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(experimentRepository, analysisService);
    }

    @Test
    void runTransientExperiment_validatesDatasetAndValidationDatasetLists() {
        var service = service(true);
        var analysis = new AnalysisRequestDTO(
                null,
                new AnalysisRequestDTO.AnalysisInputDataDTO(
                        "dm:1",
                        List.of("ds1"),
                        List.of("dsv"),
                        null,
                        List.of("age")),
                null,
                new AnalysisRequestDTO.AnalysisAlgorithmDTO("histogram", null, List.of("age"), Map.of()),
                null);
        var execution = new ExperimentExecutionDTO("test", analysis);

        when(analysisService.runAnalysis(any(UUID.class), eq(analysis), any(Logger.class)))
                .thenReturn(new AnalysisService.AnalysisResultDTO(200, Map.of("ok", true)));

        service.runTransientExperiment(authentication, execution, logger);

        verify(claimUtils).validateAccessRightsOnDatasets(eq(authentication), eq(List.of("ds1")), any(Logger.class));
        verify(claimUtils).validateAccessRightsOnDatasets(eq(authentication), eq(List.of("dsv")), any(Logger.class));
    }

    private ExperimentService service(boolean authenticationEnabled) {
        return new ExperimentService(activeUserService, claimUtils, experimentRepository, analysisService,
                authenticationEnabled, "9.0.0");
    }
}
