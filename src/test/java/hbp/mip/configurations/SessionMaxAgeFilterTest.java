package hbp.mip.configurations;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionMaxAgeFilterTest {

    @Test
    void sessionOlderThanTheMaximumEnds() throws Exception {
        MockHttpSession session = new MockHttpSession();

        run(session, Duration.ofMillis(-1));

        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void youngerSessionContinues() throws Exception {
        MockHttpSession session = new MockHttpSession();

        run(session, Duration.ofHours(8));

        assertThat(session.isInvalid()).isFalse();
    }

    @Test
    void sessionAnotherRequestJustInvalidatedStillLetsTheRequestContinue() throws Exception {
        HttpSession session = mock(HttpSession.class);
        when(session.getCreationTime()).thenThrow(new IllegalStateException("already invalidated"));

        assertThat(run(session, Duration.ofHours(8)).getRequest()).isNotNull();
    }

    private static MockFilterChain run(HttpSession session, Duration maxAge) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        MockFilterChain chain = new MockFilterChain();
        new SessionMaxAgeFilter(maxAge).doFilter(request, new MockHttpServletResponse(), chain);
        return chain;
    }
}
