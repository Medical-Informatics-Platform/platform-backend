package hbp.mip.datamodel;

import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.ControllerExceptionHandler;
import hbp.mip.utils.Exceptions.NoAuthorizedDataModelsException;
import hbp.mip.utils.Exceptions.NoDataModelsAvailableException;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class DataModelErrorContractTest {
    private final DataModelService service = mock(DataModelService.class);
    private final ActiveUserService users = mock(ActiveUserService.class);
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        when(users.getActiveUser(any()))
                .thenReturn(new UserDTO("user", "User", "user@example.org", "subject", true));
        mvc = MockMvcBuilders.standaloneSetup(new DataModelAPI(users, service))
                .setControllerAdvice(new ControllerExceptionHandler()).build();
    }

    @Test
    void noAvailableDataModelsIs404() throws Exception {
        String message = "No data models are available for this federation.";
        when(service.getDataModels(any(), any(Logger.class)))
                .thenThrow(new NoDataModelsAvailableException(message));
        mvc.perform(get("/data-models"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.statusCode").value(404))
                .andExpect(jsonPath("$.message").value(message));
    }

    @Test
    void noAuthorizedDataModelsIs403() throws Exception {
        String message = "You do not have access to any data models in this federation.";
        when(service.getDataModels(any(), any(Logger.class)))
                .thenThrow(new NoAuthorizedDataModelsException(message));
        mvc.perform(get("/data-models"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.statusCode").value(403))
                .andExpect(jsonPath("$.message").value(message));
    }
}
