package hbp.mip.folder;

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
 * Folders ("analysis sets") and the sets inside them, for the active user only.
 *
 * Routes sit under the /services servlet context, so the public paths are
 * /services/experiment-folders/....
 *
 * Statuses: 200 for reads and for every mutation that leaves a folder behind — the updated folder is
 * the body, so the caller never has to guess at ordering or partitioning — 201 for a new folder or set,
 * 204 only when the folder itself is gone, 400 for a blank or malformed name/id, 404 when the folder or
 * set is not the caller's, 409 for a duplicate name, 401 when the run cannot be read.
 */
@RestController
@RequestMapping(value = "/experiment-folders", produces = { APPLICATION_JSON_VALUE })
public class ExperimentFolderAPI {

    private final ExperimentFolderService experimentFolderService;
    private final ActiveUserService activeUserService;

    public ExperimentFolderAPI(ExperimentFolderService experimentFolderService,
            ActiveUserService activeUserService) {
        this.experimentFolderService = experimentFolderService;
        this.activeUserService = activeUserService;
    }

    @GetMapping
    public ResponseEntity<ExperimentFoldersDTO> getFolders(Authentication authentication) {
        var logger = logger(authentication, "(GET) /experiment-folders");
        logger.info("Request for the experiment folders of the active user.");
        var folders = experimentFolderService.getFolders(authentication, logger);
        logger.info("Experiment folders returned: " + folders.folders().size());
        return new ResponseEntity<>(folders, HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<ExperimentFolderDTO> createFolder(Authentication authentication,
            @RequestBody CreateExperimentFolderDTO createExperimentFolderDTO) {
        var logger = logger(authentication, "(POST) /experiment-folders");
        logger.info("Request for experiment folder creation. RequestBody: "
                + JsonConverters.convertObjectToJsonString(createExperimentFolderDTO));
        var folder = experimentFolderService.createFolder(authentication, createExperimentFolderDTO, logger);
        logger.info("Experiment folder created with id: " + folder.id());
        return new ResponseEntity<>(folder, HttpStatus.CREATED);
    }

    @GetMapping(value = "/{folderId}")
    public ResponseEntity<ExperimentFolderDTO> getFolder(Authentication authentication,
            @PathVariable("folderId") String folderId) {
        var logger = logger(authentication, "(GET) /experiment-folders/" + folderId);
        logger.info("Request for experiment folder with id: " + folderId);
        var folder = experimentFolderService.getFolder(authentication, folderId, logger);
        logger.info("Experiment folder returned.");
        return new ResponseEntity<>(folder, HttpStatus.OK);
    }

    @PatchMapping(value = "/{folderId}")
    public ResponseEntity<ExperimentFolderDTO> renameFolder(Authentication authentication,
            @PathVariable("folderId") String folderId,
            @RequestBody RenameExperimentFolderDTO renameExperimentFolderDTO) {
        var logger = logger(authentication, "(PATCH) /experiment-folders/" + folderId);
        logger.info("Request for experiment folder rename. RequestBody: "
                + JsonConverters.convertObjectToJsonString(renameExperimentFolderDTO));
        var folder = experimentFolderService.renameFolder(authentication, folderId, renameExperimentFolderDTO, logger);
        logger.info("Experiment folder renamed. Id: " + folderId);
        return new ResponseEntity<>(folder, HttpStatus.OK);
    }

    @DeleteMapping(value = "/{folderId}")
    public ResponseEntity<Void> deleteFolder(Authentication authentication,
            @PathVariable("folderId") String folderId) {
        var logger = logger(authentication, "(DELETE) /experiment-folders/" + folderId);
        logger.info("Request for experiment folder deletion with id: " + folderId);
        experimentFolderService.deleteFolder(authentication, folderId, logger);
        logger.info("Experiment folder deleted. Id: " + folderId);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /** Adding a run the folder already holds answers 200 with the folder, not 409. */
    @PostMapping(value = "/{folderId}/members")
    public ResponseEntity<ExperimentFolderDTO> addExperiment(Authentication authentication,
            @PathVariable("folderId") String folderId,
            @RequestBody AddExperimentFoldersMemberDTO addExperimentFoldersMemberDTO) {
        var logger = logger(authentication, "(POST) /experiment-folders/" + folderId + "/members");
        logger.info("Request for experiment addition to a folder. RequestBody: "
                + JsonConverters.convertObjectToJsonString(addExperimentFoldersMemberDTO));
        var folder = experimentFolderService.addExperiment(authentication, folderId, addExperimentFoldersMemberDTO,
                logger);
        logger.info("Experiment added to the folder.");
        return new ResponseEntity<>(folder, HttpStatus.OK);
    }

    /** Answers with the folder rather than 204: losing a member changes the member list and a set. */
    @DeleteMapping(value = "/{folderId}/members/{experimentUuid}")
    public ResponseEntity<ExperimentFolderDTO> removeExperiment(Authentication authentication,
            @PathVariable("folderId") String folderId,
            @PathVariable("experimentUuid") String experimentUuid) {
        var logger = logger(authentication, "(DELETE) /experiment-folders/" + folderId + "/members/" + experimentUuid);
        logger.info("Request to remove experiment " + experimentUuid + " from folder " + folderId);
        var folder = experimentFolderService.removeExperiment(authentication, folderId, experimentUuid, logger);
        logger.info("Experiment removed from the folder.");
        return new ResponseEntity<>(folder, HttpStatus.OK);
    }

    @PostMapping(value = "/{folderId}/sets")
    public ResponseEntity<ExperimentFolderDTO> createSet(Authentication authentication,
            @PathVariable("folderId") String folderId,
            @RequestBody CreateExperimentSetDTO createExperimentSetDTO) {
        var logger = logger(authentication, "(POST) /experiment-folders/" + folderId + "/sets");
        logger.info("Request for experiment set creation. RequestBody: "
                + JsonConverters.convertObjectToJsonString(createExperimentSetDTO));
        var folder = experimentFolderService.createSet(authentication, folderId, createExperimentSetDTO, logger);
        logger.info("Experiment set created in folder: " + folderId);
        return new ResponseEntity<>(folder, HttpStatus.CREATED);
    }

    @PatchMapping(value = "/{folderId}/sets/{setId}")
    public ResponseEntity<ExperimentFolderDTO> renameSet(Authentication authentication,
            @PathVariable("folderId") String folderId,
            @PathVariable("setId") String setId,
            @RequestBody RenameExperimentSetDTO renameExperimentSetDTO) {
        var logger = logger(authentication, "(PATCH) /experiment-folders/" + folderId + "/sets/" + setId);
        logger.info("Request for experiment set rename. RequestBody: "
                + JsonConverters.convertObjectToJsonString(renameExperimentSetDTO));
        var folder = experimentFolderService.renameSet(authentication, folderId, setId, renameExperimentSetDTO, logger);
        logger.info("Experiment set renamed. Id: " + setId);
        return new ResponseEntity<>(folder, HttpStatus.OK);
    }

    /** Answers with the folder rather than 204: the retired set moved its runs into Ungrouped. */
    @DeleteMapping(value = "/{folderId}/sets/{setId}")
    public ResponseEntity<ExperimentFolderDTO> deleteSet(Authentication authentication,
            @PathVariable("folderId") String folderId,
            @PathVariable("setId") String setId) {
        var logger = logger(authentication, "(DELETE) /experiment-folders/" + folderId + "/sets/" + setId);
        logger.info("Request for experiment set deletion with id: " + setId);
        var folder = experimentFolderService.deleteSet(authentication, folderId, setId, logger);
        logger.info("Experiment set deleted. Its runs were left in the folder, ungrouped.");
        return new ResponseEntity<>(folder, HttpStatus.OK);
    }

    /**
     * Moves a run into a set — or, with a null setId, out of its set and back to ungrouped. The run
     * stays in the folder either way.
     */
    @PatchMapping(value = "/{folderId}/members/{experimentUuid}/set")
    public ResponseEntity<ExperimentFolderDTO> updateSetMembership(Authentication authentication,
            @PathVariable("folderId") String folderId,
            @PathVariable("experimentUuid") String experimentUuid,
            @RequestBody UpdateExperimentSetMembershipDTO updateExperimentSetMembershipDTO) {
        var logger = logger(authentication,
                "(PATCH) /experiment-folders/" + folderId + "/members/" + experimentUuid + "/set");
        logger.info("Request to change the set of an experiment. RequestBody: "
                + JsonConverters.convertObjectToJsonString(updateExperimentSetMembershipDTO));
        var folder = experimentFolderService.updateSetMembership(authentication, folderId, experimentUuid,
                updateExperimentSetMembershipDTO, logger);
        logger.info("Set membership updated.");
        return new ResponseEntity<>(folder, HttpStatus.OK);
    }

    private Logger logger(Authentication authentication, String endpoint) {
        return new Logger(activeUserService.getActiveUser(authentication).username(), endpoint);
    }
}
