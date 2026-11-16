package hbp.mip.study;

import hbp.mip.analysis.AnalysisDAO;
import hbp.mip.analysis.AnalysisService;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDAO;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.ConflictException;
import hbp.mip.utils.Exceptions.StudyNotFoundException;
import hbp.mip.utils.Exceptions.AnalysisGroupNotFoundException;
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
 * Owns studies and the groups inside them.
 *
 * Two rules hold everywhere and are the reason this class exists at all:
 *
 * 1. Everything is scoped to the active user. A study id that is not the caller's is a 404, never a
 * 403, so the API never confirms that somebody else's id exists.
 * 2. A study holds analysis ids, never analysis copies. Membership is the only thing persisted
 * here, so a renamed or re-shared run cannot go stale inside a study.
 *
 * Name handling mirrors the frontend rules the study chips already enforce (collapse whitespace,
 * trim, 60 chars, case-insensitive uniqueness) so moving the store behind this API does not change
 * what a user can type.
 */
@Service
public class StudyService {

    static final int MAX_NAME_LENGTH = 60;

    private final ActiveUserService activeUserService;
    private final StudyRepository studyRepository;
    private final AnalysisService analysisService;

    public StudyService(ActiveUserService activeUserService,
            StudyRepository studyRepository,
            AnalysisService analysisService) {
        this.activeUserService = activeUserService;
        this.studyRepository = studyRepository;
        this.analysisService = analysisService;
    }

    // ------------------------------------------------------------------ studies

    @Transactional(readOnly = true)
    public StudiesDTO getStudies(Authentication authentication, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        List<StudyDAO> studies = studyRepository.findOwnedStudies(user.username());
        logger.debug("Owned studies found: " + studies.size());
        return StudiesDTO.from(studies);
    }

    @Transactional(readOnly = true)
    public StudyDTO getStudy(Authentication authentication, String studyId, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        return StudyDTO.from(ownedStudy(studyId, user.username(), logger));
    }

    @Transactional
    public StudyDTO createStudy(Authentication authentication, CreateStudyDTO request,
            Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        String name = requireName(request == null ? null : request.name(), "Study name", logger);

        List<StudyDAO> ownedStudies = studyRepository.findOwnedStudies(user.username());
        rejectDuplicateStudyName(name, ownedStudies, null, logger);

        StudyDAO study = new StudyDAO(new UserDAO(user), name,
                nextPosition(ownedStudies.stream().map(StudyDAO::getSortOrder).toList()));

        // "Put this run in a new study" is one gesture in the row menu, so it is one request: a second
        // call that fails would otherwise leave an empty study the user never asked for.
        String requestedAnalysis = request == null ? null : request.analysisId();
        if (!isBlank(requestedAnalysis)) {
            memberFor(study, analysisService.assertAnalysisAccessible(authentication, requestedAnalysis, logger),
                    logger);
        }

        StudyDAO saved = save(study, "A study with that name already exists.", logger);
        logger.info("Study created with id: " + saved.getId());
        return StudyDTO.from(saved);
    }

    @Transactional
    public StudyDTO renameStudy(Authentication authentication, String studyId,
            RenameStudyDTO request, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        StudyDAO study = ownedStudy(studyId, user.username(), logger);

        String name = requireName(request == null ? null : request.name(), "Study name", logger);
        rejectDuplicateStudyName(name, studyRepository.findOwnedStudies(user.username()), study, logger);

        study.setName(name);

        StudyDAO saved = save(study, "A study with that name already exists.", logger);
        logger.info("Study renamed. Id: " + study.getId());
        return StudyDTO.from(saved);
    }

    /** Deleting a study retires the grouping only. The runs themselves are untouched. */
    @Transactional
    public void deleteStudy(Authentication authentication, String studyId, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        StudyDAO study = ownedStudy(studyId, user.username(), logger);

        studyRepository.delete(study);
        logger.info("Study deleted. Id: " + study.getId());
    }

    // ------------------------------------------------------------------ members

    /**
     * Adding a run the study already holds returns the study unchanged: the row menu can toggle blindly.
     *
     * The study row is locked first, so a second add of the same run waits, then sees the membership and
     * returns the study; the member unique constraint is a backstop, not the path that decides this.
     */
    @Transactional
    public StudyDTO addAnalysis(Authentication authentication, String studyId,
            AddStudyMemberDTO request, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        StudyDAO study = ownedStudyForUpdate(studyId, user.username(), logger);

        String analysisId = request == null ? null : request.analysisId();
        if (isBlank(analysisId)) {
            String errorMessage = "analysisId must be provided.";
            logger.warn(errorMessage);
            throw new BadRequestException(errorMessage);
        }
        AnalysisDAO analysis = analysisService.assertAnalysisAccessible(authentication, analysisId.trim(),
                logger);

        if (memberOf(study, analysis.getUuid()) != null) {
            logger.info("Analysis already belongs to the study. Id: " + analysis.getUuid());
            return StudyDTO.from(study);
        }

        memberFor(study, analysis, logger);

        StudyDAO saved = save(study, "That analysis already belongs to this study.", logger);
        logger.info("Analysis added to study. Analysis id: " + analysis.getUuid());
        return StudyDTO.from(saved);
    }

    /** Leaving the study ends the membership outright: a group cannot keep a run the study lost. */
    @Transactional
    public StudyDTO removeAnalysis(Authentication authentication, String studyId, String analysisId,
            Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        StudyDAO study = ownedStudyForUpdate(studyId, user.username(), logger);

        UUID parsedAnalysisId = parseUuid(analysisId, "analysisId", logger);
        StudyMemberDAO member = memberOf(study, parsedAnalysisId);
        if (member == null) {
            logger.info("Analysis was not a member of the study. Id: " + analysisId);
            return StudyDTO.from(study);
        }

        study.getMembers().remove(member);
        StudyDAO saved = save(study, "That analysis already belongs to this study.", logger);
        logger.info("Analysis removed from study. Analysis id: " + analysisId);
        return StudyDTO.from(saved);
    }

    // ------------------------------------------------------------------ groups

    @Transactional
    public StudyDTO createGroup(Authentication authentication, String studyId,
            CreateAnalysisGroupDTO request, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        StudyDAO study = ownedStudyForUpdate(studyId, user.username(), logger);

        String name = requireName(request == null ? null : request.name(), "Group name", logger);
        rejectDuplicateGroupName(name, study, null, logger);

        AnalysisGroupDAO group = new AnalysisGroupDAO(study, name,
                nextPosition(study.getGroups().stream().map(AnalysisGroupDAO::getSortOrder).toList()));
        study.getGroups().add(group);

        String requestedAnalysis = request == null ? null : request.analysisId();
        if (!isBlank(requestedAnalysis)) {
            AnalysisDAO analysis = analysisService.assertAnalysisAccessible(authentication, requestedAnalysis, logger);
            joinGroup(study, memberFor(study, analysis, logger), group);
        }

        StudyDAO saved = save(study, "An analysis group with that name already exists in this study.", logger);
        logger.info("Analysis group created with id: " + group.getId());
        return StudyDTO.from(saved);
    }

    @Transactional
    public StudyDTO renameGroup(Authentication authentication, String studyId, String groupId,
            RenameAnalysisGroupDTO request, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        StudyDAO study = ownedStudy(studyId, user.username(), logger);
        AnalysisGroupDAO group = ownedGroup(study, groupId, logger);

        String name = requireName(request == null ? null : request.name(), "Group name", logger);
        rejectDuplicateGroupName(name, study, group, logger);

        group.setName(name);

        StudyDAO saved = save(study, "An analysis group with that name already exists in this study.", logger);
        logger.info("Analysis group renamed. Id: " + group.getId());
        return StudyDTO.from(saved);
    }

    /** Deleting a group retires the name, never the runs: its members fall back to ungrouped. */
    @Transactional
    public StudyDTO deleteGroup(Authentication authentication, String studyId, String groupId,
            Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        StudyDAO study = ownedStudyForUpdate(studyId, user.username(), logger);
        AnalysisGroupDAO group = ownedGroup(study, groupId, logger);

        // The database would settle this with ON DELETE SET NULL, but the flushed order between the
        // group removal and the member updates is not ours to bet on: null them here so the in-memory
        // state and the row agree either way.
        study.getMembers().stream()
                .filter(member -> member.isIn(group))
                .forEach(this::ungroup);

        study.getGroups().remove(group);
        StudyDAO saved = save(study, "An analysis group with that name already exists in this study.", logger);
        logger.info("Analysis group deleted. Runs were left in the study, ungrouped. Group id: " + groupId);
        return StudyDTO.from(saved);
    }

    /**
     * The strict partition: moving a run in files it nowhere else, so the previous group gives it up by
     * itself — one row per (study, analysis) means there is no second row to clean.
     *
     * A null or blank groupId is the way out of a group that is not "leave the study": the run stays in
     * the study and becomes ungrouped.
     */
    @Transactional
    public StudyDTO updateGroupMembership(Authentication authentication, String studyId, String analysisId,
            UpdateAnalysisGroupMembershipDTO request, Logger logger) {
        var user = activeUserService.getActiveUser(authentication);
        StudyDAO study = ownedStudyForUpdate(studyId, user.username(), logger);

        UUID parsedAnalysisId = parseUuid(analysisId, "analysisId", logger);
        StudyMemberDAO existingMember = memberOf(study, parsedAnalysisId);

        String requestedGroupId = request == null ? null : request.groupId();
        if (isBlank(requestedGroupId)) {
            if (existingMember == null || (existingMember.getAnalysisGroup() == null
                    && existingMember.getGroupPosition() == null)) {
                logger.info("Analysis is already ungrouped in the study. Id: " + analysisId);
                return StudyDTO.from(study);
            }

            ungroup(existingMember);
            StudyDAO ungrouped = save(study, "That analysis already belongs to this study.", logger);
            logger.info("Analysis left its group and stayed in the study. Id: " + analysisId);
            return StudyDTO.from(ungrouped);
        }

        AnalysisGroupDAO target = ownedGroup(study, requestedGroupId, logger);
        StudyMemberDAO member = existingMember != null
                ? existingMember
                : memberFor(study, analysisService.assertAnalysisAccessible(authentication, analysisId, logger), logger);

        if (member.isIn(target)) {
            logger.info("Analysis is already in the requested group. Id: " + analysisId);
            return StudyDTO.from(study);
        }

        joinGroup(study, member, target);
        StudyDAO saved = save(study, "That analysis already belongs to this study.", logger);
        logger.info("Analysis moved to group " + target.getId() + ". Analysis id: " + analysisId);
        return StudyDTO.from(saved);
    }

    // ------------------------------------------------------------------ shared rules

    /**
     * A study the caller may touch, or nothing. A study that exists under another owner and a study
     * that does not exist answer the same 404, so the API never confirms somebody else's id.
     */
    private StudyDAO ownedStudy(String studyId, String username, Logger logger) {
        return ownedStudy(studyRepository.findById(parseUuid(studyId, "studyId", logger)), studyId, username,
                logger);
    }

    /**
     * The same study, write-locked for the rest of the transaction. Membership writes take this before
     * they look at {@code members}: two concurrent add/move calls on one study then queue on the row
     * lock, so the second sees the first's membership and no duplicate row is ever attempted.
     *
     * The lock itself needs the transaction the service methods already declare.
     */
    private StudyDAO ownedStudyForUpdate(String studyId, String username, Logger logger) {
        return ownedStudy(studyRepository.findByIdForUpdate(parseUuid(studyId, "studyId", logger)), studyId,
                username, logger);
    }

    private StudyDAO ownedStudy(Optional<StudyDAO> candidate, String studyId, String username,
            Logger logger) {
        StudyDAO study = candidate
                .filter(candidateStudy -> candidateStudy.getOwner() != null
                        && username.equals(candidateStudy.getOwner().getUsername()))
                .orElse(null);

        if (study == null) {
            var errorMessage = "Study with id : " + studyId + " was not found for the active user.";
            logger.warn(errorMessage);
            throw new StudyNotFoundException(errorMessage);
        }

        return study;
    }

    /**
     * Writes and flushes in one go, then translates the database's own uniqueness backstop into the
     * 409 the caller already got from the pre-check. Two tabs creating the same study name both pass
     * the service check; whichever insert loses must hear "conflict", not "internal server error".
     * Only unique violations are translated — a NOT NULL or FK failure is still our bug and stays a 500.
     */
    private StudyDAO save(StudyDAO study, String duplicateMessage, Logger logger) {
        try {
            return studyRepository.saveAndFlush(study);
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

    private StudyMemberDAO memberOf(StudyDAO study, UUID analysisId) {
        return study.getMembers().stream()
                .filter(member -> member.getAnalysis() != null
                        && analysisId.equals(member.getAnalysis().getUuid()))
                .findFirst()
                .orElse(null);
    }

    private AnalysisGroupDAO ownedGroup(StudyDAO study, String groupId, Logger logger) {
        UUID parsed = parseUuid(groupId, "groupId", logger);
        AnalysisGroupDAO group = study.getGroups().stream()
                .filter(candidate -> parsed.equals(candidate.getId()))
                .findFirst()
                .orElse(null);
        if (group == null) {
            var errorMessage = "Analysis group with id : " + groupId + " was not found in study : " + study.getId();
            logger.warn(errorMessage);
            throw new AnalysisGroupNotFoundException(errorMessage);
        }
        return group;
    }

    /** A group only ever holds study members, so moving in joins the study first when it has to. */
    private StudyMemberDAO memberFor(StudyDAO study, AnalysisDAO analysis, Logger logger) {
        StudyMemberDAO member = memberOf(study, analysis.getUuid());
        if (member == null) {
            member = new StudyMemberDAO(study, analysis,
                    nextPosition(studyPositions(study)));
            study.getMembers().add(member);
            logger.debug("Study membership created while placing the run in a group.");
        }
        return member;
    }

    private void joinGroup(StudyDAO study, StudyMemberDAO member, AnalysisGroupDAO target) {
        member.setAnalysisGroup(target);

        // The run being moved is excluded from the max: it cannot count the position it is leaving.
        member.setGroupPosition(nextPosition(study.getMembers().stream()
                .filter(other -> !Objects.equals(other, member))
                .filter(other -> other.isIn(target))
                .map(StudyMemberDAO::getGroupPosition)
                .toList()));
    }

    private List<Integer> studyPositions(StudyDAO study) {
        return study.getMembers().stream()
                .map(StudyMemberDAO::getStudyPosition)
                .toList();
    }

    private void ungroup(StudyMemberDAO member) {
        member.setAnalysisGroup(null);
        member.setGroupPosition(null);
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

    private void rejectDuplicateStudyName(String name, List<StudyDAO> ownedStudies,
            StudyDAO renamed, Logger logger) {
        boolean taken = ownedStudies.stream()
                .filter(study -> renamed == null || !study.getId().equals(renamed.getId()))
                .anyMatch(study -> nameKey(study.getName()).equals(nameKey(name)));

        if (taken) {
            String errorMessage = "A study named '" + name + "' already exists.";
            logger.warn(errorMessage);
            throw new ConflictException(errorMessage);
        }
    }

    /** Groups are their own namespace: a group may share its study's name, but not a sibling's. */
    private void rejectDuplicateGroupName(String name, StudyDAO study, AnalysisGroupDAO renamed,
            Logger logger) {
        boolean taken = study.getGroups().stream()
                .filter(group -> renamed == null || !group.getId().equals(renamed.getId()))
                .anyMatch(group -> nameKey(group.getName()).equals(nameKey(name)));

        if (taken) {
            String errorMessage = "An analysis group named '" + name + "' already exists in this study.";
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
