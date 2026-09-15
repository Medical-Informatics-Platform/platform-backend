package hbp.mip.folder;

import hbp.mip.experiment.ExperimentDAO;
import hbp.mip.experiment.ExperimentService;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDAO;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.ConflictException;
import hbp.mip.utils.Exceptions.ExperimentFolderNotFoundException;
import hbp.mip.utils.Exceptions.ExperimentSetNotFoundException;
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
class ExperimentFolderServiceTest {

    private static final String USERNAME = "user";

    @Mock
    private ActiveUserService activeUserService;

    @Mock
    private ExperimentFolderRepository folderRepository;

    @Mock
    private ExperimentService experimentService;

    @Mock
    private Authentication authentication;

    private ExperimentFolderService service;

    private final UserDTO user = new UserDTO(USERNAME, "User", "user@example.org", "subject", true);
    private final Logger logger = new Logger(USERNAME, "test");

    @BeforeEach
    void setUp() {
        service = new ExperimentFolderService(activeUserService, folderRepository, experimentService);

        lenient().when(activeUserService.getActiveUser(authentication)).thenReturn(user);
        lenient().when(folderRepository.saveAndFlush(any(ExperimentFolderDAO.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    // ------------------------------------------------------------------ folders

    @Test
    void createFolder_collapsesWhitespaceAndPlacesItLast() {
        givenOwnedFolders(folder("Existing", 7));

        var created = service.createFolder(authentication, new CreateExperimentFolderDTO("  My   Analysis   Set  ", null),
                logger);

        ArgumentCaptor<ExperimentFolderDAO> saved = ArgumentCaptor.forClass(ExperimentFolderDAO.class);
        verify(folderRepository).saveAndFlush(saved.capture());
        assertThat(created.name()).isEqualTo("My Analysis Set");
        assertThat(saved.getValue().getSortOrder()).isEqualTo(8);
        assertThat(created.experimentIds()).isEmpty();
        assertThat(created.sets()).isEmpty();
    }

    @Test
    void createFolder_capsTheNameAtTheLengthTheFrontendAllows() {
        givenOwnedFolders();

        var created = service.createFolder(authentication,
                new CreateExperimentFolderDTO("  " + "a".repeat(80) + "  ", null), logger);

        assertThat(created.name()).hasSize(ExperimentFolderService.MAX_NAME_LENGTH);
    }

    @Test
    void createFolder_rejectsANameThatIsOnlyWhitespace() {
        assertThatThrownBy(() -> service.createFolder(authentication, new CreateExperimentFolderDTO("   \t\n ", null), logger))
                .isInstanceOf(BadRequestException.class);

        verify(folderRepository, never()).saveAndFlush(any(ExperimentFolderDAO.class));
    }

    @Test
    void createFolder_rejectsANameAlreadyTakenIgnoringCase() {
        givenOwnedFolders(folder("My Analysis Set", 1));

        assertThatThrownBy(() -> service.createFolder(authentication,
                new CreateExperimentFolderDTO("  my   analysis  set ", null), logger))
                .isInstanceOf(ConflictException.class);

        verify(folderRepository, never()).saveAndFlush(any(ExperimentFolderDAO.class));
    }

    @Test
    void renameFolder_rejectsSomebodyElsesFolderAsNotFound() {
        UUID folderId = UUID.randomUUID();
        givenFolder(folderId, "My Set", "somebody-else");

        assertThatThrownBy(() -> service.renameFolder(authentication, folderId.toString(),
                new RenameExperimentFolderDTO("Taken By Me"), logger))
                .isInstanceOf(ExperimentFolderNotFoundException.class);
    }

    @Test
    void renameFolder_keepsItsOwnNameAsNoConflict() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO owned = givenFolder(folderId, "My Set", USERNAME);
        givenOwnedFolders(owned);

        var renamed = service.renameFolder(authentication, folderId.toString(),
                new RenameExperimentFolderDTO("  my  set "), logger);

        assertThat(renamed.name()).isEqualTo("my set");
    }

    @Test
    void getFolder_readsOnlyTheFoldersOfTheActiveUser() {
        // The repository query is already owner scoped; findById is the one that must not leak either.
        UUID mine = UUID.randomUUID();
        givenFolder(mine, "Mine", USERNAME);

        assertThat(service.getFolder(authentication, mine.toString(), logger).name()).isEqualTo("Mine");
    }

    @Test
    void getFolder_hidesAFolderOwnedByAnotherUserBehindNotFound() {
        UUID foreign = UUID.randomUUID();
        givenFolder(foreign, "Theirs", "somebody-else");

        assertThatThrownBy(() -> service.getFolder(authentication, foreign.toString(), logger))
                .isInstanceOf(ExperimentFolderNotFoundException.class);
    }

    @Test
    void getFolder_rejectsAnIdThatIsNotAnId() {
        assertThatThrownBy(() -> service.getFolder(authentication, "not-a-uuid", logger))
                .isInstanceOf(BadRequestException.class);
    }

    // ------------------------------------------------------------------ members

    @Test
    void addExperiment_checksTheRunIsReadableAndAppendsItLast() {
        UUID folderId = UUID.randomUUID();
        givenFolder(folderId, "My Set", USERNAME);
        ExperimentDAO experiment = experiment();
        givenReadableExperiment(experiment);

        var updated = service.addExperiment(authentication, folderId.toString(),
                new AddExperimentFoldersMemberDTO(experiment.getUuid().toString()), logger);

        verify(experimentService).assertExperimentAccessible(eq(authentication), eq(experiment.getUuid().toString()),
                any(Logger.class));
        assertThat(updated.experimentIds()).containsExactly(experiment.getUuid().toString());

        ArgumentCaptor<ExperimentFolderDAO> saved = ArgumentCaptor.forClass(ExperimentFolderDAO.class);
        verify(folderRepository).saveAndFlush(saved.capture());
        assertThat(saved.getValue().getMembers()).singleElement()
                .satisfies(member -> assertThat(member.getFolderPosition()).isEqualTo(1));
    }

    @Test
    void addExperiment_isIdempotentForARunTheFolderAlreadyHolds() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        ExperimentDAO experiment = experiment();
        givenReadableExperiment(experiment);
        folder.getMembers().add(new ExperimentFolderMemberDAO(folder, experiment, 1));

        var again = service.addExperiment(authentication, folderId.toString(),
                new AddExperimentFoldersMemberDTO(experiment.getUuid().toString()), logger);

        assertThat(again.experimentIds()).containsExactly(experiment.getUuid().toString());
        assertThat(folder.getMembers()).hasSize(1);
        verify(folderRepository, never()).saveAndFlush(any(ExperimentFolderDAO.class));
    }

    @Test
    void addExperiment_refusesARunTheUserMayNotRead() {
        UUID folderId = UUID.randomUUID();
        givenFolder(folderId, "My Set", USERNAME);
        ExperimentDAO hidden = experiment();
        when(experimentService.assertExperimentAccessible(eq(authentication), eq(hidden.getUuid().toString()),
                any(Logger.class)))
                .thenThrow(new UnauthorizedException("You don't have access to that experiment."));

        assertThatThrownBy(() -> service.addExperiment(authentication, folderId.toString(),
                new AddExperimentFoldersMemberDTO(hidden.getUuid().toString()), logger))
                .isInstanceOf(UnauthorizedException.class);

        verify(folderRepository, never()).saveAndFlush(any(ExperimentFolderDAO.class));
    }

    @Test
    void addExperiment_requiresAnExperimentId() {
        UUID folderId = UUID.randomUUID();
        givenFolder(folderId, "My Set", USERNAME);

        assertThatThrownBy(() -> service.addExperiment(authentication, folderId.toString(),
                new AddExperimentFoldersMemberDTO("  "), logger))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void removeExperiment_dropsTheRunFromTheFolderAndItsSets() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        ExperimentSetDAO set = new ExperimentSetDAO(folder, "Baseline", 1);
        folder.getSets().add(set);
        ExperimentDAO first = experiment();
        ExperimentDAO second = experiment();
        ExperimentFolderMemberDAO firstMember = new ExperimentFolderMemberDAO(folder, first, 1);
        firstMember.setExperimentSet(set);
        firstMember.setSetPosition(1);
        folder.getMembers().add(firstMember);
        folder.getMembers().add(new ExperimentFolderMemberDAO(folder, second, 2));

        var after = service.removeExperiment(authentication, folderId.toString(), first.getUuid().toString(), logger);
        assertThat(after.experimentIds()).containsExactly(second.getUuid().toString());
        assertThat(after.sets()).singleElement().satisfies(candidate ->
                assertThat(candidate.experimentIds()).isEmpty());
    }

    @Test
    void removeExperiment_isHarmlessWhenTheRunIsNotInFolder() {
        UUID folderId = UUID.randomUUID();
        givenFolder(folderId, "My Set", USERNAME);

        service.removeExperiment(authentication, folderId.toString(), experiment().getUuid().toString(), logger);

        verify(folderRepository, never()).saveAndFlush(any(ExperimentFolderDAO.class));
    }

    // ------------------------------------------------------------------ sets

    @Test
    void createSet_appendsTheSetAndCanSeedItWithAMember() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        folder.getSets().add(new ExperimentSetDAO(folder, "Baseline", 4));
        ExperimentDAO experiment = experiment();
        givenReadableExperiment(experiment);

        var updated = service.createSet(authentication, folderId.toString(),
                new CreateExperimentSetDTO("  Drug  arm   A ", experiment.getUuid().toString()), logger);

        assertThat(updated.sets()).extracting(ExperimentSetDTO::name).containsExactly("Baseline", "Drug arm A");
        assertThat(updated.sets().get(1).experimentIds()).containsExactly(experiment.getUuid().toString());
        assertThat(folder.getMembers()).singleElement().satisfies(member -> {
            assertThat(member.getFolderPosition()).isEqualTo(1);
            assertThat(member.getSetPosition()).isEqualTo(1);
        });
    }

    @Test
    void createSet_rejectsASetNameAlreadyTakenIgnoringCase() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        folder.getSets().add(new ExperimentSetDAO(folder, "Drug arm A", 1));

        assertThatThrownBy(() -> service.createSet(authentication, folderId.toString(),
                new CreateExperimentSetDTO("  drug   ARM  a ", null), logger))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void createSet_mayShareTheNameOfItsOwnFolder() {
        UUID folderId = UUID.randomUUID();
        givenFolder(folderId, "My Set", USERNAME);

        var updated = service.createSet(authentication, folderId.toString(),
                new CreateExperimentSetDTO("my   set", null), logger);

        assertThat(updated.sets()).singleElement().satisfies(set -> assertThat(set.name()).isEqualTo("my set"));
    }

    @Test
    void updateSetMembership_movesTheRunOutOfThePreviousSet() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        ExperimentSetDAO baseline = new ExperimentSetDAO(folder, "Baseline", 1);
        ExperimentSetDAO armA = new ExperimentSetDAO(folder, "Drug arm A", 2);
        folder.getSets().add(baseline);
        folder.getSets().add(armA);
        ExperimentDAO moved = experiment();
        ExperimentFolderMemberDAO member = new ExperimentFolderMemberDAO(folder, moved, 1);
        member.setExperimentSet(baseline);
        member.setSetPosition(3);
        folder.getMembers().add(member);

        var updated = service.updateSetMembership(authentication, folderId.toString(), moved.getUuid().toString(),
                new UpdateExperimentSetMembershipDTO(armA.getId().toString()), logger);

        assertThat(updated.sets()).filteredOn(set -> set.name().equals("Baseline"))
                .singleElement().satisfies(set -> assertThat(set.experimentIds()).isEmpty());
        assertThat(updated.sets()).filteredOn(set -> set.name().equals("Drug arm A"))
                .singleElement().satisfies(set -> assertThat(set.experimentIds())
                        .containsExactly(moved.getUuid().toString()));
        assertThat(member.getExperimentSet()).isSameAs(armA);
        assertThat(member.getSetPosition()).isEqualTo(1);
    }

    @Test
    void updateSetMembership_createsTheMembershipWhenTheRunIsNotInFolderYet() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        ExperimentSetDAO armA = new ExperimentSetDAO(folder, "Drug arm A", 1);
        folder.getSets().add(armA);
        ExperimentDAO experiment = experiment();
        givenReadableExperiment(experiment);

        var updated = service.updateSetMembership(authentication, folderId.toString(), experiment.getUuid().toString(),
                new UpdateExperimentSetMembershipDTO(armA.getId().toString()), logger);

        verify(experimentService).assertExperimentAccessible(eq(authentication), eq(experiment.getUuid().toString()),
                any(Logger.class));
        assertThat(updated.experimentIds()).containsExactly(experiment.getUuid().toString());
        assertThat(updated.sets()).singleElement().satisfies(set ->
                assertThat(set.experimentIds()).containsExactly(experiment.getUuid().toString()));
    }

    @Test
    void updateSetMembership_withoutASetLeavesTheRunInTheFolderUngrouped() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        ExperimentSetDAO armA = new ExperimentSetDAO(folder, "Drug arm A", 1);
        folder.getSets().add(armA);
        ExperimentDAO experiment = experiment();
        ExperimentFolderMemberDAO member = new ExperimentFolderMemberDAO(folder, experiment, 1);
        member.setExperimentSet(armA);
        member.setSetPosition(1);
        folder.getMembers().add(member);

        var updated = service.updateSetMembership(authentication, folderId.toString(), experiment.getUuid().toString(),
                new UpdateExperimentSetMembershipDTO(null), logger);

        assertThat(updated.experimentIds()).containsExactly(experiment.getUuid().toString());
        assertThat(updated.sets()).singleElement().satisfies(set -> assertThat(set.experimentIds()).isEmpty());
        assertThat(member.getExperimentSet()).isNull();
        assertThat(member.getSetPosition()).isNull();
    }

    @Test
    void updateSetMembership_rejectsASetOfAnotherFolder() {
        UUID folderId = UUID.randomUUID();
        givenFolder(folderId, "My Set", USERNAME);

        assertThatThrownBy(() -> service.updateSetMembership(authentication, folderId.toString(),
                experiment().getUuid().toString(), new UpdateExperimentSetMembershipDTO(UUID.randomUUID().toString()),
                logger))
                .isInstanceOf(ExperimentSetNotFoundException.class);
    }

    @Test
    void renameSet_renamesOnlyItsOwnSet() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        ExperimentSetDAO armA = new ExperimentSetDAO(folder, "Drug arm A", 1);
        folder.getSets().add(armA);

        var updated = service.renameSet(authentication, folderId.toString(), armA.getId().toString(),
                new RenameExperimentSetDTO("  Drug   arm  B "), logger);

        assertThat(updated.sets()).singleElement().satisfies(set -> assertThat(set.name()).isEqualTo("Drug arm B"));
    }

    @Test
    void renameSet_rejectsANameAnotherSetAlreadyHas() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        folder.getSets().add(new ExperimentSetDAO(folder, "Drug arm A", 1));
        ExperimentSetDAO armB = new ExperimentSetDAO(folder, "Drug arm B", 2);
        folder.getSets().add(armB);

        assertThatThrownBy(() -> service.renameSet(authentication, folderId.toString(), armB.getId().toString(),
                new RenameExperimentSetDTO("drug arm a"), logger))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void deleteSet_leavesItsRunsInTheFolderUngrouped() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        ExperimentSetDAO armA = new ExperimentSetDAO(folder, "Drug arm A", 1);
        folder.getSets().add(armA);
        ExperimentDAO first = experiment();
        ExperimentDAO second = experiment();
        for (ExperimentDAO run : List.of(first, second)) {
            ExperimentFolderMemberDAO member = new ExperimentFolderMemberDAO(folder, run, 1);
            member.setExperimentSet(armA);
            member.setSetPosition(1);
            folder.getMembers().add(member);
        }

        var after = service.deleteSet(authentication, folderId.toString(), armA.getId().toString(), logger);
        assertThat(after.sets()).isEmpty();
        assertThat(after.experimentIds()).containsExactly(first.getUuid().toString(), second.getUuid().toString());
        assertThat(folder.getMembers()).allSatisfy(member -> {
            assertThat(member.getExperimentSet()).isNull();
            assertThat(member.getSetPosition()).isNull();
        });
    }

    @Test
    void deleteFolder_removesTheFolderWithoutTouchingTheRuns() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        folder.getMembers().add(new ExperimentFolderMemberDAO(folder, experiment(), 1));

        service.deleteFolder(authentication, folderId.toString(), logger);

        ArgumentCaptor<ExperimentFolderDAO> deleted = ArgumentCaptor.forClass(ExperimentFolderDAO.class);

        verify(folderRepository).delete(deleted.capture());
        assertThat(deleted.getValue().getId()).isEqualTo(folderId);
    }

    // ------------------------------------------------------------------ ordering

    @Test
    void positionsKeepGrowingFromWhateverTheFolderAlreadyHolds() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        ExperimentSetDAO armA = new ExperimentSetDAO(folder, "Drug arm A", 5);
        folder.getSets().add(armA);
        ExperimentDAO first = experiment();
        ExperimentDAO second = experiment();
        ExperimentDAO third = experiment();
        givenReadableExperiment(first, second, third);
        ExperimentFolderMemberDAO firstMember = new ExperimentFolderMemberDAO(folder, first, 4);
        firstMember.setExperimentSet(armA);
        firstMember.setSetPosition(2);
        folder.getMembers().add(firstMember);

        service.addExperiment(authentication, folderId.toString(),
                new AddExperimentFoldersMemberDTO(second.getUuid().toString()), logger);
        service.updateSetMembership(authentication, folderId.toString(), third.getUuid().toString(),
                new UpdateExperimentSetMembershipDTO(armA.getId().toString()), logger);

        assertThat(folder.getMembers()).extracting(ExperimentFolderMemberDAO::getFolderPosition)
                .containsExactly(4, 5, 6);
        assertThat(folder.getMembers()).filteredOn(member -> first.getUuid().equals(member.getExperiment().getUuid()))
                .singleElement().satisfies(member -> assertThat(member.getSetPosition()).isEqualTo(2));
        assertThat(ExperimentFolderDTO.from(folder).experimentIds())
                .containsExactly(first.getUuid().toString(), second.getUuid().toString(),
                        third.getUuid().toString());
    }

    @Test
    void getFolders_returnsEveryFolderOfTheActiveUserInOrder() {
        ExperimentFolderDAO first = folder("First", 1);
        ExperimentFolderDAO second = folder("Second", 2);
        givenOwnedFolders(first, second);

        var folders = service.getFolders(authentication, logger);

        assertThat(folders.folders()).extracting(ExperimentFolderDTO::name).containsExactly("First", "Second");
    }

    @Test
    void getFolders_answersAnEmptyListInsteadOfANotFound() {
        givenOwnedFolders();

        assertThat(service.getFolders(authentication, logger).folders()).isEmpty();
    }

    // ------------------------------------------------------------------ create folder with its first run

    @Test
    void createFolder_canSeedItWithTheRunTheGestureStartedFrom() {
        givenOwnedFolders();
        ExperimentDAO experiment = experiment();
        givenReadableExperiment(experiment);

        var created = service.createFolder(authentication,
                new CreateExperimentFolderDTO("New folder", experiment.getUuid().toString()), logger);

        verify(experimentService).assertExperimentAccessible(eq(authentication), eq(experiment.getUuid().toString()),
                any(Logger.class));
        assertThat(created.experimentIds()).containsExactly(experiment.getUuid().toString());

        ArgumentCaptor<ExperimentFolderDAO> saved = ArgumentCaptor.forClass(ExperimentFolderDAO.class);
        verify(folderRepository).saveAndFlush(saved.capture());
        assertThat(saved.getValue().getMembers()).singleElement().satisfies(member -> {
            assertThat(member.getFolderPosition()).isEqualTo(1);
            assertThat(member.getExperimentSet()).isNull();
        });
    }

    @Test
    void createFolder_writesNothingWhenTheSeedRunIsNotReadable() {
        givenOwnedFolders();
        ExperimentDAO hidden = experiment();
        when(experimentService.assertExperimentAccessible(eq(authentication), eq(hidden.getUuid().toString()),
                any(Logger.class))).thenThrow(new UnauthorizedException("You don't have access to that experiment."));

        assertThatThrownBy(() -> service.createFolder(authentication,
                new CreateExperimentFolderDTO("New folder", hidden.getUuid().toString()), logger))
                .isInstanceOf(UnauthorizedException.class);

        verify(folderRepository, never()).saveAndFlush(any(ExperimentFolderDAO.class));
    }

    // ------------------------------------------------------------------ lost uniqueness races

    @Test
    void aLostNameRaceInDatabaseAnswersConflictNotInternalError() {
        givenOwnedFolders();
        when(folderRepository.saveAndFlush(any(ExperimentFolderDAO.class)))
                .thenThrow(new DataIntegrityViolationException("could not execute statement",
                        new SQLException("duplicate key value violates unique constraint", "23505")));

        assertThatThrownBy(() -> service.createFolder(authentication,
                new CreateExperimentFolderDTO("Nobody saw the other tab", null), logger))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void aLostSetNameRaceInDatabaseAnswersConflictNotInternalError() {
        UUID folderId = UUID.randomUUID();
        givenFolder(folderId, "My Set", USERNAME);
        when(folderRepository.saveAndFlush(any(ExperimentFolderDAO.class)))
                .thenThrow(new DataIntegrityViolationException("Batch entry rejected",
                        new SQLException("duplicate key", "23505")));

        assertThatThrownBy(() -> service.createSet(authentication, folderId.toString(),
                new CreateExperimentSetDTO("Arm A", null), logger))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    void anIntegrityFailureThatIsNotUniquenessIsNotRelabelledAsConflict() {
        givenOwnedFolders();
        when(folderRepository.saveAndFlush(any(ExperimentFolderDAO.class)))
                .thenThrow(new DataIntegrityViolationException("could not execute statement",
                        new SQLException("null value in column \"name\" violates not-null constraint", "23502")));

        assertThatThrownBy(() -> service.createFolder(authentication,
                new CreateExperimentFolderDTO("Broken", null), logger))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    // ------------------------------------------------------------------ per-folder write locking

    @Test
    void memberAndSetWritesTakeTheFolderRowLock() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        ExperimentSetDAO set = new ExperimentSetDAO(folder, "Arm A", 1);
        folder.getSets().add(set);
        ExperimentDAO first = experiment();
        ExperimentDAO second = experiment();
        givenReadableExperiment(first, second);

        service.addExperiment(authentication, folderId.toString(),
                new AddExperimentFoldersMemberDTO(first.getUuid().toString()), logger);
        service.updateSetMembership(authentication, folderId.toString(), first.getUuid().toString(),
                new UpdateExperimentSetMembershipDTO(set.getId().toString()), logger);
        service.updateSetMembership(authentication, folderId.toString(), first.getUuid().toString(),
                new UpdateExperimentSetMembershipDTO(null), logger);
        service.createSet(authentication, folderId.toString(),
                new CreateExperimentSetDTO("Arm B", second.getUuid().toString()), logger);
        service.removeExperiment(authentication, folderId.toString(), second.getUuid().toString(), logger);
        service.deleteSet(authentication, folderId.toString(), set.getId().toString(), logger);

        verify(folderRepository, times(6)).findByIdForUpdate(folderId);
        verify(folderRepository, never()).findById(folderId);
    }

    @Test
    void readsDoNotTakeTheWriteLock() {
        UUID folderId = UUID.randomUUID();
        givenFolder(folderId, "My Set", USERNAME);

        service.getFolder(authentication, folderId.toString(), logger);

        verify(folderRepository).findById(folderId);
        verify(folderRepository, never()).findByIdForUpdate(folderId);
    }

    /**
     * The lock is what makes the pre-check see a competing writer: membership added before this call
     * (whatever committed first) is honoured and the folder is returned unchanged.
     */
    @Test
    void addExperiment_underTheLockSeesAMembershipThatAlreadyCommitted() {
        UUID folderId = UUID.randomUUID();
        ExperimentFolderDAO folder = givenFolder(folderId, "My Set", USERNAME);
        ExperimentDAO experiment = experiment();
        givenReadableExperiment(experiment);
        folder.getMembers().add(new ExperimentFolderMemberDAO(folder, experiment, 1));

        var updated = service.addExperiment(authentication, folderId.toString(),
                new AddExperimentFoldersMemberDTO(experiment.getUuid().toString()), logger);

        verify(folderRepository).findByIdForUpdate(folderId);
        assertThat(updated.experimentIds()).containsExactly(experiment.getUuid().toString());
        verify(folderRepository, never()).saveAndFlush(any(ExperimentFolderDAO.class));
    }

    // ------------------------------------------------------------------ helpers

    private void givenOwnedFolders(ExperimentFolderDAO... folders) {
        when(folderRepository.findOwnedFolders(USERNAME)).thenReturn(List.of(folders));
    }

    private ExperimentFolderDAO givenFolder(UUID folderId, String name, String ownerUsername) {
        ExperimentFolderDAO folder = new ExperimentFolderDAO(
                new UserDAO(ownerUsername, "User", "user@example.org", "subject"), name, 1);
        folder.setId(folderId);
        // Reads resolve through findById, member/set writes through the locked findByIdForUpdate; a test
        // exercises one of them, so both stubs are lenient.
        lenient().when(folderRepository.findById(folderId)).thenReturn(Optional.of(folder));
        lenient().when(folderRepository.findByIdForUpdate(folderId)).thenReturn(Optional.of(folder));
        return folder;
    }

    private void givenReadableExperiment(ExperimentDAO... experiments) {
        for (ExperimentDAO experiment : experiments) {
            lenient().when(experimentService.assertExperimentAccessible(eq(authentication),
                    eq(experiment.getUuid().toString()), any(Logger.class))).thenReturn(experiment);
        }
    }

    private ExperimentFolderDAO folder(String name, int sortOrder) {
        return new ExperimentFolderDAO(userOwner(), name, sortOrder);
    }

    private UserDAO userOwner() {
        return new UserDAO(USERNAME, "User", "user@example.org", "subject");
    }

    private ExperimentDAO experiment() {
        ExperimentDAO experiment = new ExperimentDAO();
        experiment.setUuid(UUID.randomUUID());
        experiment.setName("run");
        return experiment;
    }
}
