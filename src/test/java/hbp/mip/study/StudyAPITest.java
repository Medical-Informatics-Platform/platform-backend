package hbp.mip.study;

import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.ControllerExceptionHandler;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.ConflictException;
import hbp.mip.utils.Exceptions.StudyNotFoundException;
import hbp.mip.utils.Exceptions.AnalysisGroupNotFoundException;
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
class StudyAPITest {

    private static final String STUDY_ID = "11111111-1111-1111-1111-111111111111";
    private static final String GROUP_ID = "22222222-2222-2222-2222-222222222222";
    private static final String RUN_ID = "33333333-3333-3333-3333-333333333333";

    @Mock
    private StudyService service;

    @Mock
    private ActiveUserService activeUserService;

    private final Authentication principal = new UsernamePasswordAuthenticationToken("user", null);

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders
                .standaloneSetup(new StudyAPI(service, activeUserService))
                .setControllerAdvice(new ControllerExceptionHandler())
                .build();

        lenient().when(activeUserService.getActiveUser(any()))
                .thenReturn(new UserDTO("user", "User", "user@example.org", "subject", true));
    }

    // ------------------------------------------------------------------ happy path

    @Test
    void obsoleteRoutesAreUnavailable() throws Exception {
        mvc.perform(get("/experiment-folders").principal(principal)).andExpect(status().isNotFound());
        mvc.perform(post("/studies/" + STUDY_ID + "/sets").principal(principal)
                        .contentType("application/json").content("{\"name\":\"Old route\"}"))
                .andExpect(status().isNotFound());
        mvc.perform(patch("/studies/" + STUDY_ID + "/members/" + RUN_ID + "/set").principal(principal)
                        .contentType("application/json").content("{}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void listsTheActiveUsersStudies() throws Exception {
        when(service.getStudies(any(), any(Logger.class)))
                .thenReturn(new StudiesDTO(List.of(studyDto())));

        mvc.perform(get("/studies").principal(principal))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.studies[0].id").value(STUDY_ID))
                .andExpect(jsonPath("$.studies[0].name").value("My analysis group"))
                .andExpect(jsonPath("$.studies[0].analysisIds[0]").value(RUN_ID))
                .andExpect(jsonPath("$.studies[0].groups[0].id").value(GROUP_ID))
                .andExpect(jsonPath("$.studies[0].groups[0].analysisIds[0]").value(RUN_ID));
    }

    @Test
    void createsAStudyFromNameOnlyAndAnswersCreated() throws Exception {
        when(service.createStudy(any(), any(CreateStudyDTO.class), any(Logger.class)))
                .thenReturn(new StudyDTO(STUDY_ID, "My analysis group", List.of(), List.of()));

        mvc.perform(post("/studies").contentType("application/json").content("{\"name\":\"My analysis group\"}").principal(principal))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(STUDY_ID))
                .andExpect(jsonPath("$.analysisIds").isArray())
                .andExpect(jsonPath("$.groups").isArray());
    }

    @Test
    void createStudyCarriesTheFirstRunUnderTheContractFieldName() throws Exception {
        when(service.createStudy(any(), any(CreateStudyDTO.class), any(Logger.class)))
                .thenReturn(studyDto());

        mvc.perform(post("/studies").contentType("application/json")
                .content("{\"name\":\"My analysis group\",\"analysisId\":\"" + RUN_ID + "\"}").principal(principal))
                .andExpect(status().isCreated());

        ArgumentCaptor<CreateStudyDTO> body = ArgumentCaptor.forClass(CreateStudyDTO.class);
        verify(service).createStudy(eq(principal), body.capture(), any(Logger.class));
        assertThat(body.getValue().name()).isEqualTo("My analysis group");
        assertThat(body.getValue().analysisId()).isEqualTo(RUN_ID);
    }

    @Test
    void addMemberCarriesTheRunUnderTheContractFieldName() throws Exception {
        when(service.addAnalysis(any(), eq(STUDY_ID), any(AddStudyMemberDTO.class), any(Logger.class)))
                .thenReturn(studyDto());

        mvc.perform(post("/studies/" + STUDY_ID + "/members").contentType("application/json")
                .content("{\"analysisId\":\"" + RUN_ID + "\"}").principal(principal))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(STUDY_ID));

        ArgumentCaptor<AddStudyMemberDTO> body = ArgumentCaptor.forClass(AddStudyMemberDTO.class);
        verify(service).addAnalysis(eq(principal), eq(STUDY_ID), body.capture(), any(Logger.class));
        assertThat(body.getValue().analysisId()).isEqualTo(RUN_ID);
    }

    @Test
    void groupMembershipCarriesTheGroupUnderTheContractFieldName() throws Exception {
        when(service.updateGroupMembership(any(), eq(STUDY_ID), eq(RUN_ID), any(UpdateAnalysisGroupMembershipDTO.class),
                any(Logger.class))).thenReturn(studyDto());

        mvc.perform(patch("/studies/" + STUDY_ID + "/members/" + RUN_ID + "/group")
                .contentType("application/json").content("{\"groupId\":\"" + GROUP_ID + "\"}").principal(principal))
                .andExpect(status().isOk());

        ArgumentCaptor<UpdateAnalysisGroupMembershipDTO> body =
                ArgumentCaptor.forClass(UpdateAnalysisGroupMembershipDTO.class);
        verify(service).updateGroupMembership(eq(principal), eq(STUDY_ID), eq(RUN_ID), body.capture(), any(Logger.class));
        assertThat(body.getValue().groupId()).isEqualTo(GROUP_ID);
    }

    @Test
    void groupMembershipWithoutAGroupReachesTheServiceAsUngroup() throws Exception {
        when(service.updateGroupMembership(any(), eq(STUDY_ID), eq(RUN_ID), any(UpdateAnalysisGroupMembershipDTO.class),
                any(Logger.class))).thenReturn(studyDto());

        mvc.perform(patch("/studies/" + STUDY_ID + "/members/" + RUN_ID + "/group")
                .contentType("application/json").content("{\"groupId\":null}").principal(principal))
                .andExpect(status().isOk());

        ArgumentCaptor<UpdateAnalysisGroupMembershipDTO> body =
                ArgumentCaptor.forClass(UpdateAnalysisGroupMembershipDTO.class);
        verify(service).updateGroupMembership(eq(principal), eq(STUDY_ID), eq(RUN_ID), body.capture(), any(Logger.class));
        assertThat(body.getValue().groupId()).isNull();
    }

    @Test
    void createGroupCarriesItsOptionalSeedRun() throws Exception {
        when(service.createGroup(any(), eq(STUDY_ID), any(CreateAnalysisGroupDTO.class), any(Logger.class)))
                .thenReturn(studyDto());

        mvc.perform(post("/studies/" + STUDY_ID + "/groups").contentType("application/json")
                .content("{\"name\":\"Drug arm A\",\"analysisId\":\"" + RUN_ID + "\"}").principal(principal))
                .andExpect(status().isCreated());

        ArgumentCaptor<CreateAnalysisGroupDTO> body = ArgumentCaptor.forClass(CreateAnalysisGroupDTO.class);
        verify(service).createGroup(eq(principal), eq(STUDY_ID), body.capture(), any(Logger.class));
        assertThat(body.getValue().name()).isEqualTo("Drug arm A");
        assertThat(body.getValue().analysisId()).isEqualTo(RUN_ID);
    }

    @Test
    void renamesAStudyAndAGroup() throws Exception {
        when(service.renameStudy(any(), eq(STUDY_ID), any(RenameStudyDTO.class), any(Logger.class)))
                .thenReturn(studyDto());
        when(service.renameGroup(any(), eq(STUDY_ID), eq(GROUP_ID), any(RenameAnalysisGroupDTO.class), any(Logger.class)))
                .thenReturn(studyDto());

        mvc.perform(patch("/studies/" + STUDY_ID).contentType("application/json")
                .content("{\"name\":\"Renamed\"}").principal(principal)).andExpect(status().isOk());
        mvc.perform(patch("/studies/" + STUDY_ID + "/groups/" + GROUP_ID).contentType("application/json")
                .content("{\"name\":\"Renamed group\"}").principal(principal)).andExpect(status().isOk());
    }

    // ------------------------------------------------------------------ deletes

    @Test
    void deletingTheStudyLeavesNothingToReturn() throws Exception {
        mvc.perform(delete("/studies/" + STUDY_ID).principal(principal))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));
    }

    /** Losing a member or a group changes what is left, so those two answer with the remaining study. */
    @Test
    void deletingAMemberOrAGroupAnswersWithTheUpdatedStudy() throws Exception {
        when(service.removeAnalysis(any(), eq(STUDY_ID), eq(RUN_ID), any(Logger.class))).thenReturn(studyDto());
        when(service.deleteGroup(any(), eq(STUDY_ID), eq(GROUP_ID), any(Logger.class))).thenReturn(studyDto());

        mvc.perform(delete("/studies/" + STUDY_ID + "/members/" + RUN_ID).principal(principal))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(STUDY_ID))
                .andExpect(jsonPath("$.groups[0].id").value(GROUP_ID));

        mvc.perform(delete("/studies/" + STUDY_ID + "/groups/" + GROUP_ID).principal(principal))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.analysisIds[0]").value(RUN_ID));
    }

    // ------------------------------------------------------------------ failures

    @Test
    void blankNameIsABadRequest() throws Exception {
        when(service.createStudy(any(), any(CreateStudyDTO.class), any(Logger.class)))
                .thenThrow(new BadRequestException("Study name must not be blank."));

        mvc.perform(post("/studies").contentType("application/json").content("{\"name\":\"   \"}").principal(principal))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.statusCode").value(400))
                .andExpect(jsonPath("$.message").value("Study name must not be blank."));
    }

    @Test
    void malformedIdIsABadRequest() throws Exception {
        when(service.getStudy(any(), eq("not-a-uuid"), any(Logger.class)))
                .thenThrow(new BadRequestException("Invalid studyId: not-a-uuid"));

        mvc.perform(get("/studies/not-a-uuid").principal(principal))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.statusCode").value(400));
    }

    @Test
    void duplicateNamesAreAConflict() throws Exception {
        when(service.createStudy(any(), any(CreateStudyDTO.class), any(Logger.class)))
                .thenThrow(new ConflictException("A study named 'My analysis group' already exists."));
        when(service.createGroup(any(), eq(STUDY_ID), any(CreateAnalysisGroupDTO.class), any(Logger.class)))
                .thenThrow(new ConflictException("An analysis group named 'Drug arm A' already exists in this study."));

        mvc.perform(post("/studies").contentType("application/json").content("{\"name\":\"My analysis group\"}").principal(principal))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.statusCode").value(409));
        mvc.perform(post("/studies/" + STUDY_ID + "/groups").contentType("application/json")
                .content("{\"name\":\"Drug arm A\"}").principal(principal))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.statusCode").value(409));
    }

    @Test
    void foreignStudiesAndForeignGroupsAreBothNotFound() throws Exception {
        when(service.getStudy(any(), eq(STUDY_ID), any(Logger.class)))
                .thenThrow(new StudyNotFoundException("Study with id : " + STUDY_ID
                        + " was not found for the active user."));
        when(service.renameGroup(any(), eq(STUDY_ID), eq(GROUP_ID), any(RenameAnalysisGroupDTO.class), any(Logger.class)))
                .thenThrow(new AnalysisGroupNotFoundException("Analysis group with id : " + GROUP_ID
                        + " was not found in study : " + STUDY_ID));

        mvc.perform(get("/studies/" + STUDY_ID).principal(principal))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.statusCode").value(404));
        mvc.perform(patch("/studies/" + STUDY_ID + "/groups/" + GROUP_ID).contentType("application/json")
                .content("{\"name\":\"whatever\"}").principal(principal))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.statusCode").value(404));
    }

    /** A run the caller may not read must not become a study membership, and must not say 404 either. */
    @Test
    void unreadableRunIsForbidden() throws Exception {
        when(service.addAnalysis(any(), eq(STUDY_ID), any(AddStudyMemberDTO.class), any(Logger.class)))
                .thenThrow(new UnauthorizedException("You don't have access to that analysis."));

        mvc.perform(post("/studies/" + STUDY_ID + "/members").contentType("application/json")
                .content("{\"analysisId\":\"" + RUN_ID + "\"}").principal(principal))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.statusCode").value(403));
    }

    private StudyDTO studyDto() {
        return new StudyDTO(STUDY_ID, "My analysis group", List.of(RUN_ID),
                List.of(new AnalysisGroupDTO(GROUP_ID, "Drug arm A", List.of(RUN_ID))));
    }
}
