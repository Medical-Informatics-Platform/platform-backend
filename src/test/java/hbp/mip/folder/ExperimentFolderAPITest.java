package hbp.mip.folder;

import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.ControllerExceptionHandler;
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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The contract, as a test. Body field names, response field names, and the status each failure answers
 * with are what the frontend codes against, and none of them are covered by service unit tests: those
 * call the service directly and never see Jackson or {@code ControllerExceptionHandler}.
 *
 * Standalone MockMvc on purpose — no security context, no datasource. The active user is the request
 * principal, which is also how the real request reaches the controller.
 */
@ExtendWith(MockitoExtension.class)
class ExperimentFolderAPITest {

    private static final String FOLDER_ID = "11111111-1111-1111-1111-111111111111";
    private static final String SET_ID = "22222222-2222-2222-2222-222222222222";
    private static final String RUN_ID = "33333333-3333-3333-3333-333333333333";

    @Mock
    private ExperimentFolderService service;

    @Mock
    private ActiveUserService activeUserService;

    private final Authentication principal = new UsernamePasswordAuthenticationToken("user", null);

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders
                .standaloneSetup(new ExperimentFolderAPI(service, activeUserService))
                .setControllerAdvice(new ControllerExceptionHandler())
                .build();

        lenient().when(activeUserService.getActiveUser(any()))
                .thenReturn(new UserDTO("user", "User", "user@example.org", "subject", true));
    }

    // ------------------------------------------------------------------ happy path

    @Test
    void listsTheActiveUsersFolders() throws Exception {
        when(service.getFolders(any(), any(Logger.class)))
                .thenReturn(new ExperimentFoldersDTO(List.of(folderDto())));

        mvc.perform(get("/experiment-folders").principal(principal))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.folders[0].id").value(FOLDER_ID))
                .andExpect(jsonPath("$.folders[0].name").value("My analysis set"))
                .andExpect(jsonPath("$.folders[0].experimentIds[0]").value(RUN_ID))
                .andExpect(jsonPath("$.folders[0].sets[0].id").value(SET_ID))
                .andExpect(jsonPath("$.folders[0].sets[0].experimentIds[0]").value(RUN_ID));
    }

    @Test
    void createsAFolderFromNameOnlyAndAnswersCreated() throws Exception {
        when(service.createFolder(any(), any(CreateExperimentFolderDTO.class), any(Logger.class)))
                .thenReturn(new ExperimentFolderDTO(FOLDER_ID, "My analysis set", List.of(), List.of()));

        mvc.perform(post("/experiment-folders").contentType("application/json").content("{\"name\":\"My analysis set\"}").principal(principal))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(FOLDER_ID))
                .andExpect(jsonPath("$.experimentIds").isArray())
                .andExpect(jsonPath("$.sets").isArray());
    }

    @Test
    void createFolderCarriesTheFirstRunUnderTheContractFieldName() throws Exception {
        when(service.createFolder(any(), any(CreateExperimentFolderDTO.class), any(Logger.class)))
                .thenReturn(folderDto());

        mvc.perform(post("/experiment-folders").contentType("application/json")
                .content("{\"name\":\"My analysis set\",\"experimentUuid\":\"" + RUN_ID + "\"}").principal(principal))
                .andExpect(status().isCreated());

        ArgumentCaptor<CreateExperimentFolderDTO> body = ArgumentCaptor.forClass(CreateExperimentFolderDTO.class);
        verify(service).createFolder(eq(principal), body.capture(), any(Logger.class));
        assertThat(body.getValue().name()).isEqualTo("My analysis set");
        assertThat(body.getValue().experimentUuid()).isEqualTo(RUN_ID);
    }

    @Test
    void addMemberCarriesTheRunUnderTheContractFieldName() throws Exception {
        when(service.addExperiment(any(), eq(FOLDER_ID), any(AddExperimentFoldersMemberDTO.class), any(Logger.class)))
                .thenReturn(folderDto());

        mvc.perform(post("/experiment-folders/" + FOLDER_ID + "/members").contentType("application/json")
                .content("{\"experimentUuid\":\"" + RUN_ID + "\"}").principal(principal))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(FOLDER_ID));

        ArgumentCaptor<AddExperimentFoldersMemberDTO> body = ArgumentCaptor.forClass(AddExperimentFoldersMemberDTO.class);
        verify(service).addExperiment(eq(principal), eq(FOLDER_ID), body.capture(), any(Logger.class));
        assertThat(body.getValue().experimentUuid()).isEqualTo(RUN_ID);
    }

    @Test
    void setMembershipCarriesTheSetUnderTheContractFieldName() throws Exception {
        when(service.updateSetMembership(any(), eq(FOLDER_ID), eq(RUN_ID), any(UpdateExperimentSetMembershipDTO.class),
                any(Logger.class))).thenReturn(folderDto());

        mvc.perform(patch("/experiment-folders/" + FOLDER_ID + "/members/" + RUN_ID + "/set")
                .contentType("application/json").content("{\"setId\":\"" + SET_ID + "\"}").principal(principal))
                .andExpect(status().isOk());

        ArgumentCaptor<UpdateExperimentSetMembershipDTO> body =
                ArgumentCaptor.forClass(UpdateExperimentSetMembershipDTO.class);
        verify(service).updateSetMembership(eq(principal), eq(FOLDER_ID), eq(RUN_ID), body.capture(), any(Logger.class));
        assertThat(body.getValue().setId()).isEqualTo(SET_ID);
    }

    @Test
    void setMembershipWithoutASetReachesTheServiceAsUngroup() throws Exception {
        when(service.updateSetMembership(any(), eq(FOLDER_ID), eq(RUN_ID), any(UpdateExperimentSetMembershipDTO.class),
                any(Logger.class))).thenReturn(folderDto());

        mvc.perform(patch("/experiment-folders/" + FOLDER_ID + "/members/" + RUN_ID + "/set")
                .contentType("application/json").content("{\"setId\":null}").principal(principal))
                .andExpect(status().isOk());

        ArgumentCaptor<UpdateExperimentSetMembershipDTO> body =
                ArgumentCaptor.forClass(UpdateExperimentSetMembershipDTO.class);
        verify(service).updateSetMembership(eq(principal), eq(FOLDER_ID), eq(RUN_ID), body.capture(), any(Logger.class));
        assertThat(body.getValue().setId()).isNull();
    }

    @Test
    void createSetCarriesItsOptionalSeedRun() throws Exception {
        when(service.createSet(any(), eq(FOLDER_ID), any(CreateExperimentSetDTO.class), any(Logger.class)))
                .thenReturn(folderDto());

        mvc.perform(post("/experiment-folders/" + FOLDER_ID + "/sets").contentType("application/json")
                .content("{\"name\":\"Drug arm A\",\"experimentUuid\":\"" + RUN_ID + "\"}").principal(principal))
                .andExpect(status().isCreated());

        ArgumentCaptor<CreateExperimentSetDTO> body = ArgumentCaptor.forClass(CreateExperimentSetDTO.class);
        verify(service).createSet(eq(principal), eq(FOLDER_ID), body.capture(), any(Logger.class));
        assertThat(body.getValue().name()).isEqualTo("Drug arm A");
        assertThat(body.getValue().experimentUuid()).isEqualTo(RUN_ID);
    }

    @Test
    void renamesAFolderAndASet() throws Exception {
        when(service.renameFolder(any(), eq(FOLDER_ID), any(RenameExperimentFolderDTO.class), any(Logger.class)))
                .thenReturn(folderDto());
        when(service.renameSet(any(), eq(FOLDER_ID), eq(SET_ID), any(RenameExperimentSetDTO.class), any(Logger.class)))
                .thenReturn(folderDto());

        mvc.perform(patch("/experiment-folders/" + FOLDER_ID).contentType("application/json")
                .content("{\"name\":\"Renamed\"}").principal(principal)).andExpect(status().isOk());
        mvc.perform(patch("/experiment-folders/" + FOLDER_ID + "/sets/" + SET_ID).contentType("application/json")
                .content("{\"name\":\"Renamed set\"}").principal(principal)).andExpect(status().isOk());
    }

    // ------------------------------------------------------------------ deletes

    @Test
    void deletingTheFolderLeavesNothingToReturn() throws Exception {
        mvc.perform(delete("/experiment-folders/" + FOLDER_ID).principal(principal))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));
    }

    /** Losing a member or a set changes what is left, so those two answer with the remaining folder. */
    @Test
    void deletingAMemberOrASetAnswersWithTheUpdatedFolder() throws Exception {
        when(service.removeExperiment(any(), eq(FOLDER_ID), eq(RUN_ID), any(Logger.class))).thenReturn(folderDto());
        when(service.deleteSet(any(), eq(FOLDER_ID), eq(SET_ID), any(Logger.class))).thenReturn(folderDto());

        mvc.perform(delete("/experiment-folders/" + FOLDER_ID + "/members/" + RUN_ID).principal(principal))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(FOLDER_ID))
                .andExpect(jsonPath("$.sets[0].id").value(SET_ID));

        mvc.perform(delete("/experiment-folders/" + FOLDER_ID + "/sets/" + SET_ID).principal(principal))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.experimentIds[0]").value(RUN_ID));
    }

    // ------------------------------------------------------------------ failures

    @Test
    void blankNameIsABadRequest() throws Exception {
        when(service.createFolder(any(), any(CreateExperimentFolderDTO.class), any(Logger.class)))
                .thenThrow(new BadRequestException("Folder name must not be blank."));

        mvc.perform(post("/experiment-folders").contentType("application/json").content("{\"name\":\"   \"}").principal(principal))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.statusCode").value(400))
                .andExpect(jsonPath("$.message").value("Folder name must not be blank."));
    }

    @Test
    void malformedIdIsABadRequest() throws Exception {
        when(service.getFolder(any(), eq("not-a-uuid"), any(Logger.class)))
                .thenThrow(new BadRequestException("Invalid folderId: not-a-uuid"));

        mvc.perform(get("/experiment-folders/not-a-uuid").principal(principal))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.statusCode").value(400));
    }

    @Test
    void duplicateNamesAreAConflict() throws Exception {
        when(service.createFolder(any(), any(CreateExperimentFolderDTO.class), any(Logger.class)))
                .thenThrow(new ConflictException("An experiment folder named 'My analysis set' already exists."));
        when(service.createSet(any(), eq(FOLDER_ID), any(CreateExperimentSetDTO.class), any(Logger.class)))
                .thenThrow(new ConflictException("An experiment set named 'Drug arm A' already exists in this folder."));

        mvc.perform(post("/experiment-folders").contentType("application/json").content("{\"name\":\"My analysis set\"}").principal(principal))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.statusCode").value(409));
        mvc.perform(post("/experiment-folders/" + FOLDER_ID + "/sets").contentType("application/json")
                .content("{\"name\":\"Drug arm A\"}").principal(principal))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.statusCode").value(409));
    }

    @Test
    void foreignFoldersAndForeignSetsAreBothNotFound() throws Exception {
        when(service.getFolder(any(), eq(FOLDER_ID), any(Logger.class)))
                .thenThrow(new ExperimentFolderNotFoundException("Experiment folder with id : " + FOLDER_ID
                        + " was not found for the active user."));
        when(service.renameSet(any(), eq(FOLDER_ID), eq(SET_ID), any(RenameExperimentSetDTO.class), any(Logger.class)))
                .thenThrow(new ExperimentSetNotFoundException("Experiment set with id : " + SET_ID
                        + " was not found in folder : " + FOLDER_ID));

        mvc.perform(get("/experiment-folders/" + FOLDER_ID).principal(principal))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.statusCode").value(404));
        mvc.perform(patch("/experiment-folders/" + FOLDER_ID + "/sets/" + SET_ID).contentType("application/json")
                .content("{\"name\":\"whatever\"}").principal(principal))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.statusCode").value(404));
    }

    /** A run the caller may not read must not become a folder membership, and must not say 404 either. */
    @Test
    void unreadableRunIsUnauthorized() throws Exception {
        when(service.addExperiment(any(), eq(FOLDER_ID), any(AddExperimentFoldersMemberDTO.class), any(Logger.class)))
                .thenThrow(new UnauthorizedException("You don't have access to that experiment."));

        mvc.perform(post("/experiment-folders/" + FOLDER_ID + "/members").contentType("application/json")
                .content("{\"experimentUuid\":\"" + RUN_ID + "\"}").principal(principal))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.statusCode").value(401));
    }

    private ExperimentFolderDTO folderDto() {
        return new ExperimentFolderDTO(FOLDER_ID, "My analysis set", List.of(RUN_ID),
                List.of(new ExperimentSetDTO(SET_ID, "Drug arm A", List.of(RUN_ID))));
    }
}
