package hbp.mip.datamodel;

import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDTO;
import hbp.mip.utils.ClaimUtils;
import hbp.mip.utils.ControllerExceptionHandler;
import hbp.mip.utils.Exceptions.NoAuthorizedDataModelsException;
import hbp.mip.utils.Exceptions.NoDataModelsAvailableException;
import hbp.mip.utils.HTTPUtil;
import hbp.mip.utils.Logger;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class DataModelListingTest {
    private final ClaimUtils claims = mock(ClaimUtils.class);
    private final DataModelService service = new DataModelService(claims);
    private final TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", null);
    private final Logger logger = new Logger("user", "test");

    @Test
    void emptyFederationUsesDataModelTerminologyAndRemainsNotFound() throws Exception {
        withMetadata("{}", () -> {
            assertThatThrownBy(() -> service.getDataModels(authentication, logger))
                    .isInstanceOf(NoDataModelsAvailableException.class).hasMessageContaining("data models");
            mvc().perform(get("/data-models").principal(authentication)).andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.statusCode").value(404));
            verifyNoInteractions(claims);
        });
    }

    @Test
    void inaccessibleModelsRemainForbiddenAndAnonymousModeStillListsThem() throws Exception {
        when(claims.getAuthorizedDataModels(any(), eq(authentication), anyList())).thenReturn(List.of());
        withMetadata("""
                {"dm:1":{"properties":{"cdes":[{"code":"dm","version":"1","datasets":[{"code":"ds1"}]}]}}}
                """, () -> {
            assertThatThrownBy(() -> service.getDataModels(authentication, logger))
                    .isInstanceOf(NoAuthorizedDataModelsException.class).hasMessageContaining("data models");
            mvc().perform(get("/data-models").principal(authentication)).andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.statusCode").value(403));
            clearInvocations(claims);
            ReflectionTestUtils.setField(service, "authenticationIsEnabled", false);
            assertThat(service.getDataModels(authentication, logger)).singleElement()
                    .satisfies(model -> assertThat(model.code()).isEqualTo("dm"));
            verifyNoInteractions(claims);
        });
    }

    private org.springframework.test.web.servlet.MockMvc mvc() {
        var users = mock(ActiveUserService.class);
        when(users.getActiveUser(any())).thenReturn(new UserDTO("user", "User", "user@example.org", "subject", true));
        return MockMvcBuilders.standaloneSetup(new DataModelAPI(users, service))
                .setControllerAdvice(new ControllerExceptionHandler()).build();
    }

    private void withMetadata(String attributes, ThrowingAction action) throws Exception {
        ReflectionTestUtils.setField(service, "authenticationIsEnabled", true);
        ReflectionTestUtils.setField(service, "exaflowApiToken", "");
        ReflectionTestUtils.setField(service, "exaflowAttributesUrl", "attributes");
        ReflectionTestUtils.setField(service, "exaflowDatasetsVariables", "variables");
        ReflectionTestUtils.setField(service, "exaflowCDEsMetadataUrl", "cdes");
        try (var http = mockStatic(HTTPUtil.class)) {
            http.when(() -> HTTPUtil.sendGet(anyString(), anyString(), any(StringBuilder.class)))
                    .thenAnswer(call -> {
                        call.<StringBuilder>getArgument(2).append("attributes".equals(call.getArgument(0)) ? attributes : "{}");
                        return null;
                    });
            action.run();
        }
    }

    private interface ThrowingAction {
        void run() throws Exception;
    }
}
