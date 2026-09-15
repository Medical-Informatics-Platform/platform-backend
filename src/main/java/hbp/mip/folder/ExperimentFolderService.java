package hbp.mip.folder;

import hbp.mip.experiment.ExperimentDAO;
import hbp.mip.experiment.ExperimentService;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDAO;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.ConflictException;
import hbp.mip.utils.Exceptions.ExperimentFolderNotFoundException;
import hbp.mip.utils.Exceptions.ExperimentSetNotFoundException;
import hbp.mip.utils.Logger;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.SQLException;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Owns experiment folders and the sets inside them.
 *
 * Two rules hold everywhere and are the reason this class exists at all:
 *
 * 1. Everything is scoped to the active user. A folder id that is not the caller's is a 404, never a
 * 403, so the API never confirms that somebody else's id exists.
 * 2. A folder holds experiment ids, never experiment copies. Membership is the only thing persisted
 * here, so a renamed or re-shared run cannot go stale inside a folder.
 *
 * Name handling mirrors the frontend rules the folder chips already enforce (collapse whitespace,
 * trim, 60 chars, case-insensitive uniqueness) so moving the store behind this API does not change
 * what a user can type.
 */
@Service
public class ExperimentFolderService {

    static final int MAX_NAME_LENGTH = 60;

    private final ActiveUserService activeUserService;
    private final ExperimentFolderRepository folderRepository;
    private final ExperimentService experimentService;

    public ExperimentFolderService(ActiveUserService activeUserService,
            ExperimentFolderRepository folderRepository,
            ExperimentService experimentService) {
        this.activeUserService = activeUserService;
        this.folderRepository = folderRepository;
        this.experimentService = experimentService;
    }

    // ------------------------------------------------------------------ folders

    @Transactional(readOnly = true)
    public ExperimentFoldersDTO getFolders(Authentication authentication, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        List<ExperimentFolderDAO> folders = folderRepository.findOwnedFolders(user.username());
        logger.debug("Owned experiment folders found: " + folders.size());
        return ExperimentFoldersDTO.from(folders);
    }

    @Transactional(readOnly = true)
    public ExperimentFolderDTO getFolder(Authentication authentication, String folderId, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        return ExperimentFolderDTO.from(ownedFolder(folderId, user.username(), logger));
    }

    @Transactional
    public ExperimentFolderDTO createFolder(Authentication authentication, CreateExperimentFolderDTO request,
            Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        String name = requireName(request == null ? null : request.name(), "Folder name", logger);

        List<ExperimentFolderDAO> ownedFolders = folderRepository.findOwnedFolders(user.username());
        rejectDuplicateFolderName(name, ownedFolders, null, logger);

        ExperimentFolderDAO folder = new ExperimentFolderDAO(new UserDAO(user), name,
                nextPosition(ownedFolders.stream().map(ExperimentFolderDAO::getSortOrder).toList()));

        // "Put this run in a new folder" is one gesture in the row menu, so it is one request: a second
        // call that fails would otherwise leave an empty folder the user never asked for.
        String requestedExperiment = request == null ? null : request.experimentUuid();
        if (!isBlank(requestedExperiment)) {
            memberFor(folder, experimentService.assertExperimentAccessible(authentication, requestedExperiment, logger),
                    logger);
        }

        ExperimentFolderDAO saved = save(folder, "An experiment folder with that name already exists.", logger);
        logger.info("Experiment folder created with id: " + saved.getId());
        return ExperimentFolderDTO.from(saved);
    }

    @Transactional
    public ExperimentFolderDTO renameFolder(Authentication authentication, String folderId,
            RenameExperimentFolderDTO request, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        ExperimentFolderDAO folder = ownedFolder(folderId, user.username(), logger);

        String name = requireName(request == null ? null : request.name(), "Folder name", logger);
        rejectDuplicateFolderName(name, folderRepository.findOwnedFolders(user.username()), folder, logger);

        folder.setName(name);

        ExperimentFolderDAO saved = save(folder, "An experiment folder with that name already exists.", logger);
        logger.info("Experiment folder renamed. Id: " + folder.getId());
        return ExperimentFolderDTO.from(saved);
    }

    /** Deleting a folder retires the grouping only. The runs themselves are untouched. */
    @Transactional
    public void deleteFolder(Authentication authentication, String folderId, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        ExperimentFolderDAO folder = ownedFolder(folderId, user.username(), logger);

        folderRepository.delete(folder);
        logger.info("Experiment folder deleted. Id: " + folder.getId());
    }

    // ------------------------------------------------------------------ members

    /**
     * Adding a run the folder already holds returns the folder unchanged: the row menu can toggle blindly.
     *
     * The folder row is locked first, so a second add of the same run waits, then sees the membership and
     * returns the folder; the member unique constraint is a backstop, not the path that decides this.
     */
    @Transactional
    public ExperimentFolderDTO addExperiment(Authentication authentication, String folderId,
            AddExperimentFoldersMemberDTO request, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        ExperimentFolderDAO folder = ownedFolderForUpdate(folderId, user.username(), logger);

        String experimentUuid = request == null ? null : request.experimentUuid();
        if (isBlank(experimentUuid)) {
            String errorMessage = "experimentUuid must be provided.";
            logger.warn(errorMessage);
            throw new BadRequestException(errorMessage);
        }
        ExperimentDAO experiment = experimentService.assertExperimentAccessible(authentication, experimentUuid.trim(),
                logger);

        if (memberOf(folder, experiment.getUuid()) != null) {
            logger.info("Experiment already belongs to the folder. Id: " + experiment.getUuid());
            return ExperimentFolderDTO.from(folder);
        }

        memberFor(folder, experiment, logger);

        ExperimentFolderDAO saved = save(folder, "That experiment already belongs to this folder.", logger);
        logger.info("Experiment added to folder. Experiment id: " + experiment.getUuid());
        return ExperimentFolderDTO.from(saved);
    }

    /** Leaving the folder ends the membership outright: a set cannot keep a run the folder lost. */
    @Transactional
    public ExperimentFolderDTO removeExperiment(Authentication authentication, String folderId, String experimentUuid,
            Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        ExperimentFolderDAO folder = ownedFolderForUpdate(folderId, user.username(), logger);

        UUID experimentId = parseUuid(experimentUuid, "experimentUuid", logger);
        ExperimentFolderMemberDAO member = memberOf(folder, experimentId);
        if (member == null) {
            logger.info("Experiment was not a member of the folder. Id: " + experimentUuid);
            return ExperimentFolderDTO.from(folder);
        }

        folder.getMembers().remove(member);
        ExperimentFolderDAO saved = save(folder, "That experiment already belongs to this folder.", logger);
        logger.info("Experiment removed from folder. Experiment id: " + experimentUuid);
        return ExperimentFolderDTO.from(saved);
    }

    // ------------------------------------------------------------------ sets

    @Transactional
    public ExperimentFolderDTO createSet(Authentication authentication, String folderId,
            CreateExperimentSetDTO request, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        ExperimentFolderDAO folder = ownedFolderForUpdate(folderId, user.username(), logger);

        String name = requireName(request == null ? null : request.name(), "Set name", logger);
        rejectDuplicateSetName(name, folder, null, logger);

        ExperimentSetDAO set = new ExperimentSetDAO(folder, name,
                nextPosition(folder.getSets().stream().map(ExperimentSetDAO::getSortOrder).toList()));
        folder.getSets().add(set);

        String requestedExperiment = request == null ? null : request.experimentUuid();
        if (!isBlank(requestedExperiment)) {
            ExperimentDAO experiment = experimentService.assertExperimentAccessible(authentication, requestedExperiment, logger);
            joinSet(folder, memberFor(folder, experiment, logger), set);
        }

        ExperimentFolderDAO saved = save(folder, "An experiment set with that name already exists in this folder.", logger);
        logger.info("Experiment set created with id: " + set.getId());
        return ExperimentFolderDTO.from(saved);
    }

    @Transactional
    public ExperimentFolderDTO renameSet(Authentication authentication, String folderId, String setId,
            RenameExperimentSetDTO request, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        ExperimentFolderDAO folder = ownedFolder(folderId, user.username(), logger);
        ExperimentSetDAO set = ownedSet(folder, setId, logger);

        String name = requireName(request == null ? null : request.name(), "Set name", logger);
        rejectDuplicateSetName(name, folder, set, logger);

        set.setName(name);

        ExperimentFolderDAO saved = save(folder, "An experiment set with that name already exists in this folder.", logger);
        logger.info("Experiment set renamed. Id: " + set.getId());
        return ExperimentFolderDTO.from(saved);
    }

    /** Deleting a set retires the name, never the runs: its members fall back to ungrouped. */
    @Transactional
    public ExperimentFolderDTO deleteSet(Authentication authentication, String folderId, String setId,
            Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        ExperimentFolderDAO folder = ownedFolderForUpdate(folderId, user.username(), logger);
        ExperimentSetDAO set = ownedSet(folder, setId, logger);

        // The database would settle this with ON DELETE SET NULL, but the flushed order between the
        // set removal and the member updates is not ours to bet on: null them here so the in-memory
        // state and the row agree either way.
        folder.getMembers().stream()
                .filter(member -> isInSet(member, set))
                .forEach(this::ungroup);

        folder.getSets().remove(set);
        ExperimentFolderDAO saved = save(folder, "An experiment set with that name already exists in this folder.", logger);
        logger.info("Experiment set deleted. Runs were left in the folder, ungrouped. Set id: " + setId);
        return ExperimentFolderDTO.from(saved);
    }

    /**
     * The strict partition: moving a run in files it nowhere else, so the previous set gives it up by
     * itself — one row per (folder, experiment) means there is no second row to clean.
     *
     * A null or blank setId is the way out of a set that is not "leave the folder": the run stays in
     * the folder and becomes ungrouped.
     */
    @Transactional
    public ExperimentFolderDTO updateSetMembership(Authentication authentication, String folderId, String experimentUuid,
            UpdateExperimentSetMembershipDTO request, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        ExperimentFolderDAO folder = ownedFolderForUpdate(folderId, user.username(), logger);

        UUID experimentId = parseUuid(experimentUuid, "experimentUuid", logger);
        ExperimentFolderMemberDAO existingMember = memberOf(folder, experimentId);

        String requestedSetId = request == null ? null : request.setId();
        if (isBlank(requestedSetId)) {
            if (existingMember == null || (existingMember.getExperimentSet() == null
                    && existingMember.getSetPosition() == null)) {
                logger.info("Experiment is already ungrouped in the folder. Id: " + experimentUuid);
                return ExperimentFolderDTO.from(folder);
            }

            ungroup(existingMember);
            ExperimentFolderDAO ungrouped = save(folder, "That experiment already belongs to this folder.", logger);
            logger.info("Experiment left its set and stayed in the folder. Id: " + experimentUuid);
            return ExperimentFolderDTO.from(ungrouped);
        }

        ExperimentSetDAO target = ownedSet(folder, requestedSetId, logger);
        ExperimentFolderMemberDAO member = existingMember != null
                ? existingMember
                : memberFor(folder, experimentService.assertExperimentAccessible(authentication, experimentUuid, logger), logger);

        if (isInSet(member, target)) {
            logger.info("Experiment is already in the requested set. Id: " + experimentUuid);
            return ExperimentFolderDTO.from(folder);
        }

        joinSet(folder, member, target);
        ExperimentFolderDAO saved = save(folder, "That experiment already belongs to this folder.", logger);
        logger.info("Experiment moved to set " + target.getId() + ". Experiment id: " + experimentUuid);
        return ExperimentFolderDTO.from(saved);
    }

    // ------------------------------------------------------------------ shared rules

    /**
     * A folder the caller may touch, or nothing. A folder that exists under another owner and a folder
     * that does not exist answer the same 404, so the API never confirms somebody else's id.
     */
    private ExperimentFolderDAO ownedFolder(String folderId, String username, Logger logger) {
        return ownedFolder(folderRepository.findById(parseUuid(folderId, "folderId", logger)), folderId, username,
                logger);
    }

    /**
     * The same folder, write-locked for the rest of the transaction. Membership writes take this before
     * they look at {@code members}: two concurrent add/move calls on one folder then queue on the row
     * lock, so the second sees the first's membership and no duplicate row is ever attempted.
     *
     * The lock itself needs the transaction the service methods already declare.
     */
    private ExperimentFolderDAO ownedFolderForUpdate(String folderId, String username, Logger logger) {
        return ownedFolder(folderRepository.findByIdForUpdate(parseUuid(folderId, "folderId", logger)), folderId,
                username, logger);
    }

    private ExperimentFolderDAO ownedFolder(Optional<ExperimentFolderDAO> candidate, String folderId, String username,
            Logger logger) {
        ExperimentFolderDAO folder = candidate
                .filter(candidateFolder -> candidateFolder.getOwner() != null
                        && username.equals(candidateFolder.getOwner().getUsername()))
                .orElse(null);

        if (folder == null) {
            var errorMessage = "Experiment folder with id : " + folderId + " was not found for the active user.";
            logger.warn(errorMessage);
            throw new ExperimentFolderNotFoundException(errorMessage);
        }

        return folder;
    }

    /**
     * Writes and flushes in one go, then translates the database's own uniqueness backstop into the
     * 409 the caller already got from the pre-check. Two tabs creating the same folder name both pass
     * the service check; whichever insert loses must hear "conflict", not "internal server error".
     * Only unique violations are translated — a NOT NULL or FK failure is still our bug and stays a 500.
     */
    private ExperimentFolderDAO save(ExperimentFolderDAO folder, String duplicateMessage, Logger logger) {
        try {
            return folderRepository.saveAndFlush(folder);
        } catch (DataIntegrityViolationException failure) {
            if (!isUniqueViolation(failure)) {
                throw failure;
            }
            logger.warn(duplicateMessage);
            throw new ConflictException(duplicateMessage);
        }
    }

    /** PostgreSQL reports unique violations as SQLSTATE 23505; anything else (NOT NULL, FK) stays a 500. */
    private boolean isUniqueViolation(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException sql) {
                return "23505".equals(sql.getSQLState());
            }
        }
        return false;
    }

    private ExperimentFolderMemberDAO memberOf(ExperimentFolderDAO folder, UUID experimentUuid) {
        return folder.getMembers().stream()
                .filter(member -> member.getExperiment() != null
                        && experimentUuid.equals(member.getExperiment().getUuid()))
                .findFirst()
                .orElse(null);
    }

    private ExperimentSetDAO ownedSet(ExperimentFolderDAO folder, String setId, Logger logger) {
        UUID parsed = parseUuid(setId, "setId", logger);
        ExperimentSetDAO set = folder.getSets().stream()
                .filter(candidate -> parsed.equals(candidate.getId()))
                .findFirst()
                .orElse(null);
        if (set == null) {
            var errorMessage = "Experiment set with id : " + setId + " was not found in folder : " + folder.getId();
            logger.warn(errorMessage);
            throw new ExperimentSetNotFoundException(errorMessage);
        }
        return set;
    }

    /** A set only ever holds folder members, so moving in joins the folder first when it has to. */
    private ExperimentFolderMemberDAO memberFor(ExperimentFolderDAO folder, ExperimentDAO experiment, Logger logger) {
        ExperimentFolderMemberDAO member = memberOf(folder, experiment.getUuid());
        if (member == null) {
            member = new ExperimentFolderMemberDAO(folder, experiment,
                    nextPosition(folderPositions(folder)));
            folder.getMembers().add(member);
            logger.debug("Folder membership created while placing the run in a set.");
        }
        return member;
    }

    private void joinSet(ExperimentFolderDAO folder, ExperimentFolderMemberDAO member, ExperimentSetDAO target) {
        member.setExperimentSet(target);

        // The run being moved is excluded from the max: it cannot count the position it is leaving.
        member.setSetPosition(nextPosition(folder.getMembers().stream()
                .filter(other -> !Objects.equals(other, member))
                .filter(other -> isInSet(other, target))
                .map(ExperimentFolderMemberDAO::getSetPosition)
                .toList()));
    }

    private List<Integer> folderPositions(ExperimentFolderDAO folder) {
        return folder.getMembers().stream()
                .map(ExperimentFolderMemberDAO::getFolderPosition)
                .toList();
    }

    /** Id comparison, not equals: one side may still be an uninitialized association proxy. */
    private boolean isInSet(ExperimentFolderMemberDAO member, ExperimentSetDAO set) {
        return member.getExperimentSet() != null
                && set.getId() != null
                && set.getId().equals(member.getExperimentSet().getId());
    }

    private void ungroup(ExperimentFolderMemberDAO member) {
        member.setExperimentSet(null);
        member.setSetPosition(null);
    }

    /** New entries land last, in whichever axis is being appended to: first is 1, then max + 1. */
    private Integer nextPosition(Collection<Integer> positions) {
        return positions.stream()
                .filter(Objects::nonNull)
                .max(Comparator.naturalOrder())
                .map(last -> last + 1)
                .orElse(1);
    }

    private String requireName(String rawName, String field, Logger logger) {
        String name = normalizeName(rawName);
        if (name.isEmpty()) {
            String errorMessage = field + " must not be blank.";
            logger.warn(errorMessage);
            throw new BadRequestException(errorMessage);
        }
        return name;
    }

    /** Whitespace runs collapse to one space, the ends are trimmed, and 60 chars is all that fits. */
    private String normalizeName(String rawName) {
        if (rawName == null) {
            return "";
        }
        String cleaned = rawName.replaceAll("\\s+", " ").trim();
        return cleaned.length() <= MAX_NAME_LENGTH ? cleaned : cleaned.substring(0, MAX_NAME_LENGTH);
    }

    /** Comparison key only — the stored name keeps the casing the user typed. */
    private String nameKey(String name) {
        return normalizeName(name).toLowerCase(Locale.ROOT);
    }

    private void rejectDuplicateFolderName(String name, List<ExperimentFolderDAO> ownedFolders,
            ExperimentFolderDAO renamed, Logger logger) {
        boolean taken = ownedFolders.stream()
                .filter(folder -> renamed == null || !folder.getId().equals(renamed.getId()))
                .anyMatch(folder -> nameKey(folder.getName()).equals(nameKey(name)));

        if (taken) {
            String errorMessage = "An experiment folder named '" + name + "' already exists.";
            logger.warn(errorMessage);
            throw new ConflictException(errorMessage);
        }
    }

    /** Sets are their own namespace: a set may share its folder's name, but not a sibling's. */
    private void rejectDuplicateSetName(String name, ExperimentFolderDAO folder, ExperimentSetDAO renamed,
            Logger logger) {
        boolean taken = folder.getSets().stream()
                .filter(set -> renamed == null || !set.getId().equals(renamed.getId()))
                .anyMatch(set -> nameKey(set.getName()).equals(nameKey(name)));

        if (taken) {
            String errorMessage = "An experiment set named '" + name + "' already exists in this folder.";
            logger.warn(errorMessage);
            throw new ConflictException(errorMessage);
        }
    }

    private UUID parseUuid(String value, String field, Logger logger) {
        if (isBlank(value)) {
            String errorMessage = field + " must be provided.";
            logger.warn(errorMessage);
            throw new BadRequestException(errorMessage);
        }
        try {
            return UUID.fromString(value.trim());
        } catch (IllegalArgumentException e) {
            logger.error("Conversion of string to UUID failed: " + e.getMessage());
            throw new BadRequestException("Invalid " + field + ": " + value);
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
