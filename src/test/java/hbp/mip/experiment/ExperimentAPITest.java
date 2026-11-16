package hbp.mip.experiment;

import hbp.mip.algorithm.AnalysisRequestDTO;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.ControllerExceptionHandler;
import hbp.mip.utils.Exceptions.BadRequestException;
import hbp.mip.utils.Exceptions.NoContent;
import hbp.mip.utils.Logger;
import hbp.mip.utils.RawJson;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
class ExperimentAPITest {
    private static final UUID ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
    private static final UserDTO USER = new UserDTO("user", "User", "user@example.org", "subject", true);
    private static final String EXECUTION = """
            {"name":"My analysis","analysis":{"inputdata":{"data_model":"dm:1","datasets":["ds1"],
            "variables":["age"]},"algorithm":{"name":"histogram","x":["age"],"parameters":{}}}}
            """;

    @Mock private ExperimentService service;
    @Mock private ActiveUserService activeUserService;
    private final Authentication principal = new UsernamePasswordAuthenticationToken("user", null);
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new ExperimentAPI(service, activeUserService))
                .setControllerAdvice(new ControllerExceptionHandler()).build();
        lenient().when(activeUserService.getActiveUser(any())).thenReturn(USER);
    }

    @Test
    void listIncludesCollectionPaginationAndTotals() throws Exception {
        when(service.getExperiments(any(), isNull(), isNull(), isNull(), isNull(), eq(true), eq(false),
                eq(false), eq(0), eq(10), eq("created"), eq(true), any()))
                .thenReturn(new ExperimentsDTO(List.of(response()), 0, 3, 21L));
        mvc.perform(get("/experiments").principal(principal))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.experiments[0].uuid").value(ID.toString()))
                .andExpect(jsonPath("$.experiments[0].analysis.algorithm.name").value("histogram"))
                .andExpect(jsonPath("$.currentPage").value(0))
                .andExpect(jsonPath("$.totalPages").value(3))
                .andExpect(jsonPath("$.totalExperiments").value(21));
    }

    @Test
    void emptyListRemainsNoContent() throws Exception {
        when(service.getExperiments(any(), any(), any(), any(), any(), anyBoolean(), anyBoolean(),
                anyBoolean(), anyInt(), anyInt(), anyString(), anyBoolean(), any())).thenThrow(new NoContent("Empty"));
        mvc.perform(get("/experiments").principal(principal)).andExpect(status().isNoContent());
    }

    @Test
    void previewMapsTheWholeExecutionRequestAndReturnsRawResults() throws Exception {
        when(service.previewExperiment(any(), any(), any())).thenReturn(response());
        mvc.perform(post("/experiments/preview").principal(principal).contentType("application/json").content(EXECUTION))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.analysis.inputdata.variables[0]").value("age"))
                .andExpect(jsonPath("$.result.n_obs").value(217))
                .andExpect(jsonPath("$.result.p").value(org.hamcrest.Matchers.nullValue()))
                .andExpect(jsonPath("$.status").value("success"));
        var execution = ArgumentCaptor.forClass(ExperimentExecutionDTO.class);
        verify(service).previewExperiment(eq(principal), execution.capture(), any(Logger.class));
        assertThat(execution.getValue().analysis().algorithm().name()).isEqualTo("histogram");
    }

    @Test
    void runReturnsTheRunIdAndSaveAcceptsOnlyItsReferenceAndName() throws Exception {
        when(service.runExperiment(any(), eq(USER), any(), any())).thenReturn(response());
        mvc.perform(post("/experiments/runs").principal(principal).contentType("application/json").content(EXECUTION))
                .andExpect(status().isOk()).andExpect(jsonPath("$.uuid").value(ID.toString()));
        when(service.saveExperimentRun(eq(USER), eq(ID.toString()), eq("Saved"), any())).thenReturn(response());
        mvc.perform(post("/experiments").principal(principal).contentType("application/json")
                        .content("{\"runId\":\"" + ID + "\",\"name\":\"Saved\"}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.uuid").value(ID.toString()));
        verify(service).saveExperimentRun(eq(USER), eq(ID.toString()), eq("Saved"), any());
    }

    @Test
    void detailPatchAndDeleteKeepTheirStatusCodes() throws Exception {
        when(service.getExperiment(any(), eq(ID.toString()), any())).thenReturn(response());
        mvc.perform(get("/experiments/" + ID).principal(principal))
                .andExpect(status().isOk()).andExpect(jsonPath("$.analysis.algorithm.name").value("histogram"));
        when(service.updateExperiment(eq(USER), eq(ID.toString()), any(), any())).thenReturn(response());
        mvc.perform(patch("/experiments/" + ID).principal(principal).contentType("application/json")
                        .content("{\"name\":\"Renamed\",\"shared\":true}"))
                .andExpect(status().isOk());
        mvc.perform(delete("/experiments/" + ID).principal(principal)).andExpect(status().isOk());
        verify(service).deleteExperiment(eq(USER), eq(ID.toString()), any());
    }

    @Test
    void validationFailureIsABadRequest() throws Exception {
        when(service.previewExperiment(any(), any(), any())).thenThrow(new BadRequestException("Missing required analysis."));
        mvc.perform(post("/experiments/preview").principal(principal).contentType("application/json").content("{}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.statusCode").value(400));
    }

    private static ExperimentDTO response() {
        var analysis = new AnalysisRequestDTO(null,
                new AnalysisRequestDTO.AnalysisInputDataDTO("dm:1", List.of("ds1"), null, null, List.of("age")),
                null, new AnalysisRequestDTO.AnalysisAlgorithmDTO("histogram", List.of("age"), null, null), null);
        return new ExperimentDTO(ID, "My analysis", USER, null, null, null, true, false,
                new RawJson("{\"n_obs\":217,\"p\":null}"), ExperimentDAO.Status.success, analysis, "9.0.0");
    }
}
