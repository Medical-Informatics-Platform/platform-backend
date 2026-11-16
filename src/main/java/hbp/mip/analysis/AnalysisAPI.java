package hbp.mip.analysis;

import hbp.mip.user.ActiveUserService;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(value = "/analyses", produces = { APPLICATION_JSON_VALUE })
public class AnalysisAPI {

    private final AnalysisService analysisService;
    private final ActiveUserService activeUserService;

    public AnalysisAPI(
            AnalysisService analysisService,
            ActiveUserService activeUserService) {
        this.analysisService = analysisService;
        this.activeUserService = activeUserService;
    }

    @GetMapping
    public ResponseEntity<AnalysesDTO> getAnalyses(Authentication authentication,
            @RequestParam(name = "name", required = false) String name,
            @RequestParam(name = "algorithm", required = false) String algorithm,
            @RequestParam(name = "shared", required = false) Boolean shared,
            @RequestParam(name = "viewed", required = false) Boolean viewed,
            @RequestParam(name = "includeShared", required = false, defaultValue = "true") boolean includeShared,
            @RequestParam(name = "mine", required = false, defaultValue = "false") boolean mine,
            @RequestParam(name = "notMine", required = false, defaultValue = "false") boolean notMine,
            @RequestParam(name = "orderBy", required = false, defaultValue = "created") String orderBy,
            @RequestParam(name = "descending", required = false, defaultValue = "true") Boolean descending,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        var logger = new Logger(activeUserService.getActiveUser(authentication).username(), "(GET) /analyses");
        logger.info(
                "Request for analyses with parameters: " +
                        "name -> " + name +
                        " , algorithm -> " + algorithm +
                        " , shared -> " + shared +
                        " , viewed -> " + viewed +
                        " , includeShared -> " + includeShared +
                        " , mine -> " + mine +
                        " , notMine -> " + notMine +
                        " , orderBy -> " + orderBy +
                        " , descending -> " + descending +
                        " , page -> " + page +
                        " , size -> " + size);
        var analysesDTO = analysisService.getAnalyses(authentication,
                name,
                algorithm,
                shared,
                viewed,
                includeShared,
                mine,
                notMine,
                page,
                size,
                orderBy,
                descending,
                logger);
        logger.info("Analyses returned: " + analysesDTO.analyses().size());
        return new ResponseEntity<>(analysesDTO, HttpStatus.OK);
    }

    @GetMapping(value = "/{uuid}")
    public ResponseEntity<AnalysisDTO> getAnalysis(Authentication authentication,
            @PathVariable("uuid") String uuid) {
        var logger = new Logger(activeUserService.getActiveUser(authentication).username(),
                "(GET) /analyses/" + uuid);
        logger.info("Request for analysis with id: " + uuid);
        var analysisResponse = analysisService.getAnalysis(authentication, uuid, logger);
        logger.info("Analysis returned.");
        return new ResponseEntity<>(analysisResponse, HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<AnalysisDTO> saveAnalysisRun(Authentication authentication,
            @RequestBody SaveAnalysisRunDTO saveAnalysisRunDTO) {
        var user = activeUserService.getActiveUser(authentication);
        var logger = new Logger(user.username(), "(POST) /analyses");
        logger.info("Request to save analysis run with id: " + saveAnalysisRunDTO.runId());
        var analysisResponse = analysisService.saveAnalysisRun(user, saveAnalysisRunDTO.runId(),
                saveAnalysisRunDTO.name(), logger);
        logger.info("Analysis run saved. Run id: " + saveAnalysisRunDTO.runId() + ", analysis id: "
                + analysisResponse.uuid());
        return new ResponseEntity<>(analysisResponse, HttpStatus.CREATED);
    }

    @PatchMapping(value = "/{uuid}")
    public ResponseEntity<AnalysisDTO> updateAnalysis(Authentication authentication,
            @RequestBody AnalysisDTO analysisRequest, @PathVariable("uuid") String uuid) {
        var user = activeUserService.getActiveUser(authentication);
        var logger = new Logger(user.username(), "(PATCH) /analyses/" + uuid);
        logger.info("Request for analysis update with id: " + uuid + ".  Request Body: "
                + JsonConverters.convertObjectToJsonString(analysisRequest));
        var analysisResponse = analysisService.updateAnalysis(user, uuid, analysisRequest, logger);
        logger.info("Analysis updated. Id: " + uuid);
        return new ResponseEntity<>(analysisResponse, HttpStatus.OK);
    }

    @RequestMapping(value = "/{uuid}", method = RequestMethod.DELETE)
    public ResponseEntity<String> deleteAnalysis(Authentication authentication, @PathVariable("uuid") String uuid) {
        var user = activeUserService.getActiveUser(authentication);
        var logger = new Logger(user.username(), "(DELETE) /analyses/" + uuid);
        logger.info("Request for analysis deletion with id: " + uuid);
        analysisService.deleteAnalysis(user, uuid, logger);
        logger.info("Analysis deleted. Id: " + uuid);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping(value = "/preview")
    public ResponseEntity<AnalysisDTO> previewAnalysis(Authentication authentication,
            @RequestBody AnalysisExecutionDTO analysisExecutionDTO) {
        var logger = new Logger(activeUserService.getActiveUser(authentication).username(),
                "(POST) /analyses/preview");
        logger.debug("Request for analysis preview. RequestBody: "
                + JsonConverters.convertObjectToJsonString(analysisExecutionDTO));

        var analysisResponse = analysisService.previewAnalysis(authentication, analysisExecutionDTO, logger);

        logger.info("Analysis preview finished. Status: " + analysisResponse.status());
        return new ResponseEntity<>(analysisResponse, HttpStatus.OK);
    }

    @PostMapping(value = "/runs")
    public ResponseEntity<AnalysisDTO> runAnalysis(Authentication authentication,
            @RequestBody AnalysisExecutionDTO analysisExecutionDTO) {
        var user = activeUserService.getActiveUser(authentication);
        var logger = new Logger(user.username(), "(POST) /analyses/runs");
        logger.debug("Request for analysis run. RequestBody: "
                + JsonConverters.convertObjectToJsonString(analysisExecutionDTO));

        var analysisResponse = analysisService.runAnalysis(authentication, user, analysisExecutionDTO,
                logger);

        logger.info("Analysis run finished. Id: " + analysisResponse.uuid()
                + " Status: " + analysisResponse.status());
        return new ResponseEntity<>(analysisResponse, HttpStatus.OK);
    }
}
