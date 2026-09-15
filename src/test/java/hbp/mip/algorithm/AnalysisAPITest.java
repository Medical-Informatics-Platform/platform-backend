package hbp.mip.algorithm;

import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.ClaimUtils;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AnalysisAPITest {

    @Mock
    private ActiveUserService activeUserService;

    @Mock
    private AnalysisService analysisService;

    @Mock
    private ClaimUtils claimUtils;

    @Mock
    private Authentication authentication;

    private AnalysisAPI analysisAPI;

    @BeforeEach
    void setUp() {
        analysisAPI = new AnalysisAPI(activeUserService, analysisService, claimUtils);
        ReflectionTestUtils.setField(analysisAPI, "authenticationIsEnabled", true);
        when(activeUserService.getActiveUser(authentication))
                .thenReturn(new UserDTO("user", "User", "user@example.org", "subject", true));
    }

    @Test
    void runAnalysis_validatesValidationDatasetsToo() {
        var request = new AnalysisRequestDTO(
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
        when(analysisService.runAnalysis(eq(request), any(Logger.class)))
                .thenReturn(new AnalysisService.AnalysisResultDTO(200, Map.of("ok", true)));

        var response = analysisAPI.runAnalysis(authentication, request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        verify(claimUtils).validateAccessRightsOnDatasets(eq(authentication), eq(List.of("ds1")), any(Logger.class));
        verify(claimUtils).validateAccessRightsOnDatasets(eq(authentication), eq(List.of("dsv")), any(Logger.class));
    }
}
