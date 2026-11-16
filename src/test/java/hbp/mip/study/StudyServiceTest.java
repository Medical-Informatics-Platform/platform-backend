package hbp.mip.study;

import hbp.mip.analysis.AnalysisDAO;
import hbp.mip.analysis.AnalysisService;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDAO;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.ConflictException;
import hbp.mip.utils.Exceptions.AnalysisNotFoundException;
import hbp.mip.utils.Exceptions.UnauthorizedException;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.Authentication;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StudyServiceTest {

    private static final String USERNAME = "user";

    @Mock
    private ActiveUserService activeUserService;

    @Mock
    private StudyRepository studyRepository;

    @Mock
    private AnalysisService analysisService;

    @Mock
    private Authentication authentication;

    private StudyService service;

    private final UserDTO user = new UserDTO(USERNAME, "User", "user@example.org", "subject", true);
    private final Logger logger = new Logger(USERNAME, "test");

    @BeforeEach
    void setUp() {
        service = new StudyService(activeUserService, studyRepository, analysisService);

        lenient().when(activeUserService.getActiveUser(authentication)).thenReturn(user);
        lenient().when(studyRepository.saveAndFlush(any(StudyDAO.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    // ------------------------------------------------------------------ studies

    @Test
    void createStudy_collapsesWhitespaceAndPlacesItLast() {
        givenOwnedStudies(study("Existing", 7));

        var created = service.createStudy(authentication, new CreateStudyDTO("  My   Analysis   Set  ", null),
                logger);

        ArgumentCaptor<StudyDAO> saved = ArgumentCaptor.forClass(StudyDAO.class);
        verify(studyRepository).saveAndFlush(saved.capture());
        assertThat(created.name()).isEqualTo("My Analysis Set");
        assertThat(saved.getValue().getSortOrder()).isEqualTo(8);
        assertThat(created.analysisIds()).isEmpty();
        assertThat(created.groups()).isEmpty();
    }

    @Test
    void createStudy_capsTheNameAtTheLengthTheFrontendAllows() {
        givenOwnedStudies();

        var created = service.createStudy(authentication,
                new CreateStudyDTO("  " + "a".repeat(80) + "  ", null), logger);

        assertThat(created.name()).hasSize(StudyService.MAX_NAME_LENGTH);
    }

    @Test
    void createStudy_rejectsANameThatIsOnlyWhitespace() {
        assertThatThrownBy(() -> service.createStudy(authentication, new CreateStudyDTO("   \t\n ", null), logger))
                .isInstanceOf(BadRequestException.class);

        verify(studyRepository, never()).saveAndFlush(any(StudyDAO.class));
    }

    @Test
    void createStudy_rejectsANameAlreadyTakenIgnoringCase() {
        givenOwnedStudies(study("My Analysis Set", 1));

        assertThatThrownBy(() -> service.createStudy(authentication,
                new CreateStudyDTO("  my   analysis  group ", null), logger))
                .isInstanceOf(ConflictException.class);

        verify(studyRepository, never()).saveAndFlush(any(StudyDAO.class));
    }

    @Test
    void renameStudy_rejectsSomebodyElsesStudyAsNotFound() {
        UUID studyId = UUID.randomUUID();
        givenStudy(studyId, "My Set", "somebody-else");

        assertThatThrownBy(() -> service.renameStudy(authentication, studyId.toString(),
                new RenameStudyDTO("Taken By Me"), logger))
                .isInstanceOf(AnalysisNotFoundException.class);
    }

    @Test
    void renameStudy_keepsItsOwnNameAsNoConflict() {
        UUID studyId = UUID.randomUUID();
        StudyDAO owned = givenStudy(studyId, "My Set", USERNAME);
        givenOwnedStudies(owned);

        var renamed = service.renameStudy(authentication, studyId.toString(),
                new RenameStudyDTO("  my  group "), logger);

        assertThat(renamed.name()).isEqualTo("my group");
    }

    @Test
    void getStudy_readsOnlyTheStudiesOfTheActiveUser() {
        // The repository query is already owner scoped; findById is the one that must not leak either.
        UUID mine = UUID.randomUUID();
        givenStudy(mine, "Mine", USERNAME);

        assertThat(service.getStudy(authentication, mine.toString(), logger).name()).isEqualTo("Mine");
    }

    @Test
    void getStudy_hidesAStudyOwnedByAnotherUserBehindNotFound() {
        UUID foreign = UUID.randomUUID();
        givenStudy(foreign, "Theirs", "somebody-else");

        assertThatThrownBy(() -> service.getStudy(authentication, foreign.toString(), logger))
                .isInstanceOf(AnalysisNotFoundException.class);
    }

    @Test
    void getStudy_rejectsAnIdThatIsNotAnId() {
        assertThatThrownBy(() -> service.getStudy(authentication, "not-a-uuid", logger))
                .isInstanceOf(BadRequestException.class);
    }

    // ------------------------------------------------------------------ members

    @Test
    void addAnalysis_checksTheRunIsReadableAndAppendsItLast() {
        UUID studyId = UUID.randomUUID();
        givenStudy(studyId, "My Set", USERNAME);
        AnalysisDAO analysis = analysis();
        givenReadableAnalysis(analysis);

        var updated = service.addAnalysis(authentication, studyId.toString(),
                new AddStudyMemberDTO(analysis.getUuid().toString()), logger);

        verify(analysisService).assertAnalysisAccessible(eq(authentication), eq(analysis.getUuid().toString()),
                any(Logger.class));
        assertThat(updated.analysisIds()).containsExactly(analysis.getUuid().toString());

        ArgumentCaptor<StudyDAO> saved = ArgumentCaptor.forClass(StudyDAO.class);
        verify(studyRepository).saveAndFlush(saved.capture());
        assertThat(saved.getValue().getMembers()).singleElement()
                .satisfies(member -> assertThat(member.getStudyPosition()).isEqualTo(1));
    }

    @Test
    void addAnalysis_isIdempotentForARunTheStudyAlreadyHolds() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        AnalysisDAO analysis = analysis();
        givenReadableAnalysis(analysis);
        study.getMembers().add(new StudyMemberDAO(study, analysis, 1));

        var again = service.addAnalysis(authentication, studyId.toString(),
                new AddStudyMemberDTO(analysis.getUuid().toString()), logger);

        assertThat(again.analysisIds()).containsExactly(analysis.getUuid().toString());
        assertThat(study.getMembers()).hasSize(1);
        verify(studyRepository, never()).saveAndFlush(any(StudyDAO.class));
    }

    @Test
    void addAnalysis_refusesARunTheUserMayNotRead() {
        UUID studyId = UUID.randomUUID();
        givenStudy(studyId, "My Set", USERNAME);
        AnalysisDAO hidden = analysis();
        when(analysisService.assertAnalysisAccessible(eq(authentication), eq(hidden.getUuid().toString()),
                any(Logger.class)))
                .thenThrow(new UnauthorizedException("You don't have access to that analysis."));

        assertThatThrownBy(() -> service.addAnalysis(authentication, studyId.toString(),
                new AddStudyMemberDTO(hidden.getUuid().toString()), logger))
                .isInstanceOf(UnauthorizedException.class);

        verify(studyRepository, never()).saveAndFlush(any(StudyDAO.class));
    }

    @Test
    void addAnalysis_requiresAnAnalysisId() {
        UUID studyId = UUID.randomUUID();
        givenStudy(studyId, "My Set", USERNAME);

        assertThatThrownBy(() -> service.addAnalysis(authentication, studyId.toString(),
                new AddStudyMemberDTO("  "), logger))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void removeAnalysis_dropsTheRunFromTheStudyAndItsSets() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        AnalysisGroupDAO group = new AnalysisGroupDAO(study, "Baseline", 1);
        study.getGroups().add(group);
        AnalysisDAO first = analysis();
        AnalysisDAO second = analysis();
        StudyMemberDAO firstMember = new StudyMemberDAO(study, first, 1);
        firstMember.setAnalysisGroup(group);
        firstMember.setGroupPosition(1);
        study.getMembers().add(firstMember);
        study.getMembers().add(new StudyMemberDAO(study, second, 2));

        var after = service.removeAnalysis(authentication, studyId.toString(), first.getUuid().toString(), logger);
        assertThat(after.analysisIds()).containsExactly(second.getUuid().toString());
        assertThat(after.groups()).singleElement().satisfies(candidate ->
                assertThat(candidate.analysisIds()).isEmpty());
    }

    @Test
    void removeAnalysis_isHarmlessWhenTheRunIsNotInStudy() {
        UUID studyId = UUID.randomUUID();
        givenStudy(studyId, "My Set", USERNAME);

        service.removeAnalysis(authentication, studyId.toString(), analysis().getUuid().toString(), logger);

        verify(studyRepository, never()).saveAndFlush(any(StudyDAO.class));
    }

    // ------------------------------------------------------------------ groups

    @Test
    void createGroup_appendsTheSetAndCanSeedItWithAMember() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        study.getGroups().add(new AnalysisGroupDAO(study, "Baseline", 4));
        AnalysisDAO analysis = analysis();
        givenReadableAnalysis(analysis);

        var updated = service.createGroup(authentication, studyId.toString(),
                new CreateAnalysisGroupDTO("  Drug  arm   A ", analysis.getUuid().toString()), logger);

        assertThat(updated.groups()).extracting(AnalysisGroupDTO::name).containsExactly("Baseline", "Drug arm A");
        assertThat(updated.groups().get(1).analysisIds()).containsExactly(analysis.getUuid().toString());
        assertThat(study.getMembers()).singleElement().satisfies(member -> {
            assertThat(member.getStudyPosition()).isEqualTo(1);
            assertThat(member.getGroupPosition()).isEqualTo(1);
        });
    }

    @Test
    void createGroup_rejectsASetNameAlreadyTakenIgnoringCase() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        study.getGroups().add(new AnalysisGroupDAO(study, "Drug arm A", 1));

        assertThatThrownBy(() -> service.createGroup(authentication, studyId.toString(),
                new CreateAnalysisGroupDTO("  drug   ARM  a ", null), logger))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void createGroup_mayShareTheNameOfItsOwnStudy() {
        UUID studyId = UUID.randomUUID();
        givenStudy(studyId, "My Set", USERNAME);

        var updated = service.createGroup(authentication, studyId.toString(),
                new CreateAnalysisGroupDTO("my   group", null), logger);

        assertThat(updated.groups()).singleElement().satisfies(group -> assertThat(group.name()).isEqualTo("my group"));
    }

    @Test
    void updateGroupMembership_movesTheRunOutOfThePreviousSet() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        AnalysisGroupDAO baseline = new AnalysisGroupDAO(study, "Baseline", 1);
        AnalysisGroupDAO armA = new AnalysisGroupDAO(study, "Drug arm A", 2);
        study.getGroups().add(baseline);
        study.getGroups().add(armA);
        AnalysisDAO moved = analysis();
        StudyMemberDAO member = new StudyMemberDAO(study, moved, 1);
        member.setAnalysisGroup(baseline);
        member.setGroupPosition(3);
        study.getMembers().add(member);

        var updated = service.updateGroupMembership(authentication, studyId.toString(), moved.getUuid().toString(),
                new UpdateAnalysisGroupMembershipDTO(armA.getId().toString()), logger);

        assertThat(updated.groups()).filteredOn(group -> group.name().equals("Baseline"))
                .singleElement().satisfies(group -> assertThat(group.analysisIds()).isEmpty());
        assertThat(updated.groups()).filteredOn(group -> group.name().equals("Drug arm A"))
                .singleElement().satisfies(group -> assertThat(group.analysisIds())
                        .containsExactly(moved.getUuid().toString()));
        assertThat(member.getAnalysisGroup()).isSameAs(armA);
        assertThat(member.getGroupPosition()).isEqualTo(1);
    }

    @Test
    void updateGroupMembership_createsTheMembershipWhenTheRunIsNotInStudyYet() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        AnalysisGroupDAO armA = new AnalysisGroupDAO(study, "Drug arm A", 1);
        study.getGroups().add(armA);
        AnalysisDAO analysis = analysis();
        givenReadableAnalysis(analysis);

        var updated = service.updateGroupMembership(authentication, studyId.toString(), analysis.getUuid().toString(),
                new UpdateAnalysisGroupMembershipDTO(armA.getId().toString()), logger);

        verify(analysisService).assertAnalysisAccessible(eq(authentication), eq(analysis.getUuid().toString()),
                any(Logger.class));
        assertThat(updated.analysisIds()).containsExactly(analysis.getUuid().toString());
        assertThat(updated.groups()).singleElement().satisfies(group ->
                assertThat(group.analysisIds()).containsExactly(analysis.getUuid().toString()));
    }

    @Test
    void updateGroupMembership_withoutASetLeavesTheRunInTheStudyUngrouped() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        AnalysisGroupDAO armA = new AnalysisGroupDAO(study, "Drug arm A", 1);
        study.getGroups().add(armA);
        AnalysisDAO analysis = analysis();
        StudyMemberDAO member = new StudyMemberDAO(study, analysis, 1);
        member.setAnalysisGroup(armA);
        member.setGroupPosition(1);
        study.getMembers().add(member);

        var updated = service.updateGroupMembership(authentication, studyId.toString(), analysis.getUuid().toString(),
                new UpdateAnalysisGroupMembershipDTO(null), logger);

        assertThat(updated.analysisIds()).containsExactly(analysis.getUuid().toString());
        assertThat(updated.groups()).singleElement().satisfies(group -> assertThat(group.analysisIds()).isEmpty());
        assertThat(member.getAnalysisGroup()).isNull();
        assertThat(member.getGroupPosition()).isNull();
    }

    @Test
    void updateGroupMembership_rejectsASetOfAnotherStudy() {
        UUID studyId = UUID.randomUUID();
        givenStudy(studyId, "My Set", USERNAME);

        assertThatThrownBy(() -> service.updateGroupMembership(authentication, studyId.toString(),
                analysis().getUuid().toString(), new UpdateAnalysisGroupMembershipDTO(UUID.randomUUID().toString()),
                logger))
                .isInstanceOf(AnalysisNotFoundException.class);
    }

    @Test
    void renameGroup_renamesOnlyItsOwnSet() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        AnalysisGroupDAO armA = new AnalysisGroupDAO(study, "Drug arm A", 1);
        study.getGroups().add(armA);

        var updated = service.renameGroup(authentication, studyId.toString(), armA.getId().toString(),
                new RenameAnalysisGroupDTO("  Drug   arm  B "), logger);

        assertThat(updated.groups()).singleElement().satisfies(group -> assertThat(group.name()).isEqualTo("Drug arm B"));
    }

    @Test
    void renameGroup_rejectsANameAnotherSetAlreadyHas() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        study.getGroups().add(new AnalysisGroupDAO(study, "Drug arm A", 1));
        AnalysisGroupDAO armB = new AnalysisGroupDAO(study, "Drug arm B", 2);
        study.getGroups().add(armB);

        assertThatThrownBy(() -> service.renameGroup(authentication, studyId.toString(), armB.getId().toString(),
                new RenameAnalysisGroupDTO("drug arm a"), logger))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void deleteGroup_leavesItsRunsInTheStudyUngrouped() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        AnalysisGroupDAO armA = new AnalysisGroupDAO(study, "Drug arm A", 1);
        study.getGroups().add(armA);
        AnalysisDAO first = analysis();
        AnalysisDAO second = analysis();
        for (AnalysisDAO run : List.of(first, second)) {
            StudyMemberDAO member = new StudyMemberDAO(study, run, 1);
            member.setAnalysisGroup(armA);
            member.setGroupPosition(1);
            study.getMembers().add(member);
        }

        var after = service.deleteGroup(authentication, studyId.toString(), armA.getId().toString(), logger);
        assertThat(after.groups()).isEmpty();
        assertThat(after.analysisIds()).containsExactly(first.getUuid().toString(), second.getUuid().toString());
        assertThat(study.getMembers()).allSatisfy(member -> {
            assertThat(member.getAnalysisGroup()).isNull();
            assertThat(member.getGroupPosition()).isNull();
        });
    }

    @Test
    void deleteStudy_removesTheStudyWithoutTouchingTheRuns() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        study.getMembers().add(new StudyMemberDAO(study, analysis(), 1));

        service.deleteStudy(authentication, studyId.toString(), logger);

        ArgumentCaptor<StudyDAO> deleted = ArgumentCaptor.forClass(StudyDAO.class);

        verify(studyRepository).delete(deleted.capture());
        assertThat(deleted.getValue().getId()).isEqualTo(studyId);
    }

    // ------------------------------------------------------------------ ordering

    @Test
    void positionsKeepGrowingFromWhateverTheStudyAlreadyHolds() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        AnalysisGroupDAO armA = new AnalysisGroupDAO(study, "Drug arm A", 5);
        study.getGroups().add(armA);
        AnalysisDAO first = analysis();
        AnalysisDAO second = analysis();
        AnalysisDAO third = analysis();
        givenReadableAnalysis(first, second, third);
        StudyMemberDAO firstMember = new StudyMemberDAO(study, first, 4);
        firstMember.setAnalysisGroup(armA);
        firstMember.setGroupPosition(2);
        study.getMembers().add(firstMember);

        service.addAnalysis(authentication, studyId.toString(),
                new AddStudyMemberDTO(second.getUuid().toString()), logger);
        service.updateGroupMembership(authentication, studyId.toString(), third.getUuid().toString(),
                new UpdateAnalysisGroupMembershipDTO(armA.getId().toString()), logger);

        assertThat(study.getMembers()).extracting(StudyMemberDAO::getStudyPosition)
                .containsExactly(4, 5, 6);
        assertThat(study.getMembers()).filteredOn(member -> first.getUuid().equals(member.getAnalysis().getUuid()))
                .singleElement().satisfies(member -> assertThat(member.getGroupPosition()).isEqualTo(2));
        assertThat(StudyDTO.from(study).analysisIds())
                .containsExactly(first.getUuid().toString(), second.getUuid().toString(),
                        third.getUuid().toString());
    }

    @Test
    void getStudies_returnsEveryStudyOfTheActiveUserInOrder() {
        StudyDAO first = study("First", 1);
        StudyDAO second = study("Second", 2);
        givenOwnedStudies(first, second);

        var studies = service.getStudies(authentication, logger);

        assertThat(studies.studies()).extracting(StudyDTO::name).containsExactly("First", "Second");
    }

    @Test
    void getStudies_answersAnEmptyListInsteadOfANotFound() {
        givenOwnedStudies();

        assertThat(service.getStudies(authentication, logger).studies()).isEmpty();
    }

    // ------------------------------------------------------------------ create study with its first run

    @Test
    void createStudy_canSeedItWithTheRunTheGestureStartedFrom() {
        givenOwnedStudies();
        AnalysisDAO analysis = analysis();
        givenReadableAnalysis(analysis);

        var created = service.createStudy(authentication,
                new CreateStudyDTO("New study", analysis.getUuid().toString()), logger);

        verify(analysisService).assertAnalysisAccessible(eq(authentication), eq(analysis.getUuid().toString()),
                any(Logger.class));
        assertThat(created.analysisIds()).containsExactly(analysis.getUuid().toString());

        ArgumentCaptor<StudyDAO> saved = ArgumentCaptor.forClass(StudyDAO.class);
        verify(studyRepository).saveAndFlush(saved.capture());
        assertThat(saved.getValue().getMembers()).singleElement().satisfies(member -> {
            assertThat(member.getStudyPosition()).isEqualTo(1);
            assertThat(member.getAnalysisGroup()).isNull();
        });
    }

    @Test
    void createStudy_writesNothingWhenTheSeedRunIsNotReadable() {
        givenOwnedStudies();
        AnalysisDAO hidden = analysis();
        when(analysisService.assertAnalysisAccessible(eq(authentication), eq(hidden.getUuid().toString()),
                any(Logger.class))).thenThrow(new UnauthorizedException("You don't have access to that analysis."));

        assertThatThrownBy(() -> service.createStudy(authentication,
                new CreateStudyDTO("New study", hidden.getUuid().toString()), logger))
                .isInstanceOf(UnauthorizedException.class);

        verify(studyRepository, never()).saveAndFlush(any(StudyDAO.class));
    }

    // ------------------------------------------------------------------ lost uniqueness races

    @Test
    void aLostNameRaceInDatabaseAnswersConflictNotInternalError() {
        givenOwnedStudies();
        when(studyRepository.saveAndFlush(any(StudyDAO.class)))
                .thenThrow(new DataIntegrityViolationException("could not execute statement",
                        new SQLException("duplicate key value violates unique constraint", "23505")));

        assertThatThrownBy(() -> service.createStudy(authentication,
                new CreateStudyDTO("Nobody saw the other tab", null), logger))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void aLostSetNameRaceInDatabaseAnswersConflictNotInternalError() {
        UUID studyId = UUID.randomUUID();
        givenStudy(studyId, "My Set", USERNAME);
        when(studyRepository.saveAndFlush(any(StudyDAO.class)))
                .thenThrow(new DataIntegrityViolationException("Batch entry rejected",
                        new SQLException("duplicate key", "23505")));

        assertThatThrownBy(() -> service.createGroup(authentication, studyId.toString(),
                new CreateAnalysisGroupDTO("Arm A", null), logger))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void anIntegrityFailureThatIsNotUniquenessIsNotRelabelledAsConflict() {
        givenOwnedStudies();
        when(studyRepository.saveAndFlush(any(StudyDAO.class)))
                .thenThrow(new DataIntegrityViolationException("could not execute statement",
                        new SQLException("null value in column \"name\" violates not-null constraint", "23502")));

        assertThatThrownBy(() -> service.createStudy(authentication,
                new CreateStudyDTO("Broken", null), logger))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    // ------------------------------------------------------------------ per-study write locking

    @Test
    void memberAndSetWritesTakeTheStudyRowLock() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        AnalysisGroupDAO group = new AnalysisGroupDAO(study, "Arm A", 1);
        study.getGroups().add(group);
        AnalysisDAO first = analysis();
        AnalysisDAO second = analysis();
        givenReadableAnalysis(first, second);

        service.addAnalysis(authentication, studyId.toString(),
                new AddStudyMemberDTO(first.getUuid().toString()), logger);
        service.updateGroupMembership(authentication, studyId.toString(), first.getUuid().toString(),
                new UpdateAnalysisGroupMembershipDTO(group.getId().toString()), logger);
        service.updateGroupMembership(authentication, studyId.toString(), first.getUuid().toString(),
                new UpdateAnalysisGroupMembershipDTO(null), logger);
        service.createGroup(authentication, studyId.toString(),
                new CreateAnalysisGroupDTO("Arm B", second.getUuid().toString()), logger);
        service.removeAnalysis(authentication, studyId.toString(), second.getUuid().toString(), logger);
        service.deleteGroup(authentication, studyId.toString(), group.getId().toString(), logger);

        verify(studyRepository, times(6)).findByIdForUpdate(studyId);
        verify(studyRepository, never()).findById(studyId);
    }

    @Test
    void readsDoNotTakeTheWriteLock() {
        UUID studyId = UUID.randomUUID();
        givenStudy(studyId, "My Set", USERNAME);

        service.getStudy(authentication, studyId.toString(), logger);

        verify(studyRepository).findById(studyId);
        verify(studyRepository, never()).findByIdForUpdate(studyId);
    }

    /**
     * The lock is what makes the pre-check see a competing writer: membership added before this call
     * (whatever committed first) is honoured and the study is returned unchanged.
     */
    @Test
    void addAnalysis_underTheLockSeesAMembershipThatAlreadyCommitted() {
        UUID studyId = UUID.randomUUID();
        StudyDAO study = givenStudy(studyId, "My Set", USERNAME);
        AnalysisDAO analysis = analysis();
        givenReadableAnalysis(analysis);
        study.getMembers().add(new StudyMemberDAO(study, analysis, 1));

        var updated = service.addAnalysis(authentication, studyId.toString(),
                new AddStudyMemberDTO(analysis.getUuid().toString()), logger);

        verify(studyRepository).findByIdForUpdate(studyId);
        assertThat(updated.analysisIds()).containsExactly(analysis.getUuid().toString());
        verify(studyRepository, never()).saveAndFlush(any(StudyDAO.class));
    }

    // ------------------------------------------------------------------ helpers

    private void givenOwnedStudies(StudyDAO... studies) {
        when(studyRepository.findOwnedStudies(USERNAME)).thenReturn(List.of(studies));
    }

    private StudyDAO givenStudy(UUID studyId, String name, String ownerUsername) {
        StudyDAO study = new StudyDAO(
                new UserDAO(ownerUsername, "User", "user@example.org", "subject"), name, 1);
        study.groupId(studyId);
        // Reads resolve through findById, member/group writes through the locked findByIdForUpdate; a test
        // exercises one of them, so both stubs are lenient.
        lenient().when(studyRepository.findById(studyId)).thenReturn(Optional.of(study));
        lenient().when(studyRepository.findByIdForUpdate(studyId)).thenReturn(Optional.of(study));
        return study;
    }

    private void givenReadableAnalysis(AnalysisDAO... analyses) {
        for (AnalysisDAO analysis : analyses) {
            lenient().when(analysisService.assertAnalysisAccessible(eq(authentication),
                    eq(analysis.getUuid().toString()), any(Logger.class))).thenReturn(analysis);
        }
    }

    private StudyDAO study(String name, int sortOrder) {
        return new StudyDAO(userOwner(), name, sortOrder);
    }

    private UserDAO userOwner() {
        return new UserDAO(USERNAME, "User", "user@example.org", "subject");
    }

    private AnalysisDAO analysis() {
        AnalysisDAO analysis = new AnalysisDAO();
        analysis.setUuid(UUID.randomUUID());
        analysis.setName("run");
        return analysis;
    }
}
