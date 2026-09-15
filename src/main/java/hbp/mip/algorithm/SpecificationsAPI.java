package hbp.mip.algorithm;

import hbp.mip.user.ActiveUserService;
import hbp.mip.utils.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(value = "/specifications", produces = { APPLICATION_JSON_VALUE })
public class SpecificationsAPI {

    private final SpecificationsService specificationsService;
    private final ActiveUserService activeUserService;

    public SpecificationsAPI(ActiveUserService activeUserService, SpecificationsService specificationsService) {
        this.activeUserService = activeUserService;
        this.specificationsService = specificationsService;
    }

    @GetMapping("/inputdata")
    public ResponseEntity<AnalysisInputDataSpecificationDTO> getInputdataSpecification(Authentication authentication) {
        Logger logger = new Logger(
                activeUserService.getActiveUser(authentication).username(),
                "(GET) /specifications/inputdata");
        logger.info("Request for inputdata specification.");
        AnalysisInputDataSpecificationDTO specification = specificationsService.getInputdataSpecification(logger);
        return ResponseEntity.ok(specification);
    }

    @GetMapping("/preprocessing")
    public ResponseEntity<List<PreprocessingStepSpecificationDTO>> getPreprocessingSpecifications(
            Authentication authentication) {
        Logger logger = new Logger(
                activeUserService.getActiveUser(authentication).username(),
                "(GET) /specifications/preprocessing");
        logger.info("Request for preprocessing specifications.");
        List<PreprocessingStepSpecificationDTO> specifications =
                specificationsService.getPreprocessingSpecifications(logger);
        return ResponseEntity.ok(specifications);
    }

    @GetMapping("/algorithms")
    public ResponseEntity<List<AlgorithmSpecificationDTO>> getAlgorithmSpecifications(Authentication authentication) {
        Logger logger = new Logger(
                activeUserService.getActiveUser(authentication).username(),
                "(GET) /specifications/algorithms");
        logger.info("Request for algorithm specifications.");
        List<AlgorithmSpecificationDTO> specifications = specificationsService.getAlgorithmSpecifications(logger);
        logger.info("Algorithm specifications returned: " + specifications.size());
        return ResponseEntity.ok(specifications);
    }
}
