package hbp.mip.configurations;

import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/** After login the browser goes to frontend.base-url plus a path; the request can never choose the site. */
class LoginRedirectTest {

    private static final String ATTRIBUTE = SpaRedirectAuthenticationSuccessHandler.REDIRECT_PATH_ATTRIBUTE;

    @Test
    void absoluteFrontendRedirectKeepsOnlyItsPath() throws Exception {
        assertThat(targetFor("https://evil.example/steal?x=1", "https://portal.example"))
                .isEqualTo("https://portal.example/steal?x=1");
    }

    @Test
    void refererKeepsOnlyItsPath() throws Exception {
        MockHttpServletRequest request = loginRequest();
        request.addHeader("Referer", "https://evil.example/page");

        assertThat(redirect(request, "https://portal.example")).isEqualTo("https://portal.example/page");
    }

    @Test
    void protocolRelativePathsStayOnThisSite() throws Exception {
        assertThat(targetFor("//evil.example/x", "")).isEqualTo("/services/evil.example/x");
        assertThat(targetFor("/\\evil.example/x", "")).isEqualTo("/services/evil.example/x");
    }

    @Test
    void ordinaryPathIsKept() throws Exception {
        assertThat(targetFor("/experiments?id=1#top", "https://portal.example/"))
                .isEqualTo("https://portal.example/experiments?id=1#top");
    }

    private static String targetFor(String frontendRedirect, String baseUrl) throws ServletException, IOException {
        MockHttpServletRequest request = loginRequest();
        request.setParameter("frontend_redirect", frontendRedirect);
        return redirect(request, baseUrl);
    }

    private static MockHttpServletRequest loginRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/services/oauth2/authorization/keycloak");
        request.setContextPath("/services");
        return request;
    }

    private static String redirect(MockHttpServletRequest request, String baseUrl) throws ServletException, IOException {
        new FrontendRedirectCaptureFilter().doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        assertThat(request.getSession().getAttribute(ATTRIBUTE)).isNotNull();

        MockHttpServletResponse response = new MockHttpServletResponse();
        new SpaRedirectAuthenticationSuccessHandler(baseUrl).onAuthenticationSuccess(request, response, null);
        return response.getRedirectedUrl();
    }
}
