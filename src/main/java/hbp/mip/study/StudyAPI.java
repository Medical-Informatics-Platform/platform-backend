package hbp.mip.study;

import hbp.mip.user.ActiveUserService;
import hbp.mip.utils.JsonConverters;
import hbp.mip.utils.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * Studies ("analysis groups") and the groups inside them, for the active user only.
 *
 * Routes sit under the /services servlet context, so the public paths are
 * /services/studies/....
 *
 * Statuses: 200 for reads and for every mutation that leaves a study behind — the updated study is
 * the body, so the caller never has to guess at ordering or partitioning — 201 for a new study or group,
 * 204 only when the study itself is gone, 400 for a blank or malformed name/id, 404 when the study or
 * group is not the caller's, 409 for a duplicate name, 401 when the run cannot be read.
 */
@RestController
@RequestMapping(value = "/studies", produces = { APPLICATION_JSON_VALUE })
public class StudyAPI {

    private final StudyService studyService;
    private final ActiveUserService activeUserService;

    public StudyAPI(StudyService studyService,
            ActiveUserService activeUserService) {
        this.studyService = studyService;
        this.activeUserService = activeUserService;
    }

    @GetMapping
    public ResponseEntity<StudiesDTO> getStudies(Authentication authentication) {
        var logger = logger(authentication, "(GET) /studies");
        logger.info("Request for the studies of the active user.");
        var studies = studyService.getStudies(authentication, logger);
        logger.info("Studies returned: " + studies.studies().size());
        return new ResponseEntity<>(studies, HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<StudyDTO> createStudy(Authentication authentication,
            @RequestBody CreateStudyDTO createAnalysisGroupDTO) {
        var logger = logger(authentication, "(POST) /studies");
        logger.debug("Request for study creation. RequestBody: "
                + JsonConverters.convertObjectToJsonString(createAnalysisGroupDTO));
        var study = studyService.createStudy(authentication, createAnalysisGroupDTO, logger);
        logger.info("Study created with id: " + study.id());
        return new ResponseEntity<>(study, HttpStatus.CREATED);
    }

    @GetMapping(value = "/{studyId}")
    public ResponseEntity<StudyDTO> getStudy(Authentication authentication,
            @PathVariable("studyId") String studyId) {
        var logger = logger(authentication, "(GET) /studies/" + studyId);
        logger.info("Request for study with id: " + studyId);
        var study = studyService.getStudy(authentication, studyId, logger);
        logger.info("Study returned.");
        return new ResponseEntity<>(study, HttpStatus.OK);
    }

    @PatchMapping(value = "/{studyId}")
    public ResponseEntity<StudyDTO> renameStudy(Authentication authentication,
            @PathVariable("studyId") String studyId,
            @RequestBody RenameStudyDTO renameAnalysisGroupDTO) {
        var logger = logger(authentication, "(PATCH) /studies/" + studyId);
        logger.debug("Request for study rename. RequestBody: "
                + JsonConverters.convertObjectToJsonString(renameAnalysisGroupDTO));
        var study = studyService.renameStudy(authentication, studyId, renameAnalysisGroupDTO, logger);
        logger.info("Study renamed. Id: " + studyId);
        return new ResponseEntity<>(study, HttpStatus.OK);
    }

    @DeleteMapping(value = "/{studyId}")
    public ResponseEntity<Void> deleteStudy(Authentication authentication,
            @PathVariable("studyId") String studyId) {
        var logger = logger(authentication, "(DELETE) /studies/" + studyId);
        logger.info("Request for study deletion with id: " + studyId);
        studyService.deleteStudy(authentication, studyId, logger);
        logger.info("Study deleted. Id: " + studyId);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /** Adding a run the study already holds answers 200 with the study, not 409. */
    @PostMapping(value = "/{studyId}/members")
    public ResponseEntity<StudyDTO> addAnalysis(Authentication authentication,
            @PathVariable("studyId") String studyId,
            @RequestBody AddStudyMemberDTO addStudiesMemberDTO) {
        var logger = logger(authentication, "(POST) /studies/" + studyId + "/members");
        logger.debug("Request for analysis addition to a study. RequestBody: "
                + JsonConverters.convertObjectToJsonString(addStudiesMemberDTO));
        var study = studyService.addAnalysis(authentication, studyId, addStudiesMemberDTO,
                logger);
        logger.info("Analysis added to the study.");
        return new ResponseEntity<>(study, HttpStatus.OK);
    }

    /** Answers with the study rather than 204: losing a member changes the member list and a group. */
    @DeleteMapping(value = "/{studyId}/members/{analysisUuid}")
    public ResponseEntity<StudyDTO> removeAnalysis(Authentication authentication,
            @PathVariable("studyId") String studyId,
            @PathVariable("analysisUuid") String analysisUuid) {
        var logger = logger(authentication, "(DELETE) /studies/" + studyId + "/members/" + analysisUuid);
        logger.info("Request to remove analysis " + analysisUuid + " from study " + studyId);
        var study = studyService.removeAnalysis(authentication, studyId, analysisUuid, logger);
        logger.info("Analysis removed from the study.");
        return new ResponseEntity<>(study, HttpStatus.OK);
    }

    @PostMapping(value = "/{studyId}/groups")
    public ResponseEntity<StudyDTO> createGroup(Authentication authentication,
            @PathVariable("studyId") String studyId,
            @RequestBody CreateAnalysisGroupDTO createAnalysisGroupDTO) {
        var logger = logger(authentication, "(POST) /studies/" + studyId + "/groups");
        logger.debug("Request for analysis group creation. RequestBody: "
                + JsonConverters.convertObjectToJsonString(createAnalysisGroupDTO));
        var study = studyService.createGroup(authentication, studyId, createAnalysisGroupDTO, logger);
        logger.info("Analysis group created in study: " + studyId);
        return new ResponseEntity<>(study, HttpStatus.CREATED);
    }

    @PatchMapping(value = "/{studyId}/groups/{groupId}")
    public ResponseEntity<StudyDTO> renameGroup(Authentication authentication,
            @PathVariable("studyId") String studyId,
            @PathVariable("groupId") String groupId,
            @RequestBody RenameAnalysisGroupDTO renameAnalysisGroupDTO) {
        var logger = logger(authentication, "(PATCH) /studies/" + studyId + "/groups/" + groupId);
        logger.debug("Request for analysis group rename. RequestBody: "
                + JsonConverters.convertObjectToJsonString(renameAnalysisGroupDTO));
        var study = studyService.renameGroup(authentication, studyId, groupId, renameAnalysisGroupDTO, logger);
        logger.info("Analysis group renamed. Id: " + groupId);
        return new ResponseEntity<>(study, HttpStatus.OK);
    }

    /** Answers with the study rather than 204: the retired group moved its runs into Ungrouped. */
    @DeleteMapping(value = "/{studyId}/groups/{groupId}")
    public ResponseEntity<StudyDTO> deleteGroup(Authentication authentication,
            @PathVariable("studyId") String studyId,
            @PathVariable("groupId") String groupId) {
        var logger = logger(authentication, "(DELETE) /studies/" + studyId + "/groups/" + groupId);
        logger.info("Request for analysis group deletion with id: " + groupId);
        var study = studyService.deleteGroup(authentication, studyId, groupId, logger);
        logger.info("Analysis group deleted. Its runs were left in the study, ungrouped.");
        return new ResponseEntity<>(study, HttpStatus.OK);
    }

    /**
     * Moves a run into a group — or, with a null groupId, out of its group and back to ungrouped. The run
     * stays in the study either way.
     */
    @PatchMapping(value = "/{studyId}/members/{analysisUuid}/group")
    public ResponseEntity<StudyDTO> updateGroupMembership(Authentication authentication,
            @PathVariable("studyId") String studyId,
            @PathVariable("analysisUuid") String analysisUuid,
            @RequestBody UpdateAnalysisGroupMembershipDTO updateAnalysisGroupMembershipDTO) {
        var logger = logger(authentication,
                "(PATCH) /studies/" + studyId + "/members/" + analysisUuid + "/group");
        logger.debug("Request to change the group of an analysis. RequestBody: "
                + JsonConverters.convertObjectToJsonString(updateAnalysisGroupMembershipDTO));
        var study = studyService.updateGroupMembership(authentication, studyId, analysisUuid,
                updateAnalysisGroupMembershipDTO, logger);
        logger.info("Set membership updated.");
        return new ResponseEntity<>(study, HttpStatus.OK);
    }

    private Logger logger(Authentication authentication, String endpoint) {
        return new Logger(activeUserService.getActiveUser(authentication).username(), endpoint);
    }
}
