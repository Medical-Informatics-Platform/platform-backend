package hbp.mip.algorithm;

import hbp.mip.user.ActiveUserService;
import hbp.mip.utils.ClaimUtils;
import hbp.mip.utils.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(value = "/analysis", produces = { APPLICATION_JSON_VALUE })
public class AnalysisAPI {

    private final AnalysisService analysisService;
    private final ActiveUserService activeUserService;
    private final ClaimUtils claimUtils;

    @Value("${authentication.enabled}")
    private boolean authenticationIsEnabled;

    public AnalysisAPI(
            ActiveUserService activeUserService,
            AnalysisService analysisService,
            ClaimUtils claimUtils) {
        this.activeUserService = activeUserService;
        this.analysisService = analysisService;
        this.claimUtils = claimUtils;
    }

    @PostMapping(consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> runAnalysis(
            Authentication authentication,
            @RequestBody AnalysisRequestDTO analysisRequest) {
        Logger logger = new Logger(activeUserService.getActiveUser(authentication).username(), "(POST) /analysis");
        logger.info("Request for analysis execution.");
        if (authenticationIsEnabled && analysisRequest.inputdata() != null) {
            claimUtils.validateAccessRightsOnDatasets(
                    authentication,
                    analysisRequest.inputdata().datasets(),
                    logger);
        }
        AnalysisService.AnalysisResultDTO result = analysisService.runAnalysis(analysisRequest, logger);
        return ResponseEntity.status(result.code()).body(result.body());
    }
}
