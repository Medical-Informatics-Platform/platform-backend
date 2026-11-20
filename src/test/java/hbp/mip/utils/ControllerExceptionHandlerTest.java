package hbp.mip.utils;

import hbp.mip.algorithm.ExaflowAmqpClient;
import hbp.mip.utils.Exceptions.GatewayTimeoutException;
import hbp.mip.utils.Exceptions.InternalServerError;
import hbp.mip.utils.Exceptions.ServiceUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ControllerExceptionHandlerTest {

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new ProbeController())
                .setControllerAdvice(new ControllerExceptionHandler())
                .build();
    }

    @Test
    void unavailable_is503WithTheCuratedMessage() throws Exception {
        mvc.perform(get("/unavailable"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.statusCode").value(503))
                .andExpect(jsonPath("$.message").value(ExaflowAmqpClient.UNAVAILABLE));
    }

    @Test
    void timedOut_is504WithTheCuratedMessage() throws Exception {
        mvc.perform(get("/timed-out"))
                .andExpect(status().isGatewayTimeout())
                .andExpect(jsonPath("$.statusCode").value(504))
                .andExpect(jsonPath("$.message").value(ExaflowAmqpClient.TIMED_OUT));
    }

    @Test
    void unexpectedFailure_stays500WithoutTheExceptionText() throws Exception {
        mvc.perform(get("/internal"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.statusCode").value(500))
                .andExpect(jsonPath("$.message").value("An internal error occurred."))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("secret schema"))));
    }

    @Controller
    static class ProbeController {
        @GetMapping("/unavailable")
        public void unavailable() {
            throw new ServiceUnavailableException(ExaflowAmqpClient.UNAVAILABLE);
        }

        @GetMapping("/timed-out")
        public void timedOut() {
            throw new GatewayTimeoutException(ExaflowAmqpClient.TIMED_OUT);
        }

        @GetMapping("/internal")
        public void internal() {
            throw new InternalServerError("secret schema users");
        }
    }
}
