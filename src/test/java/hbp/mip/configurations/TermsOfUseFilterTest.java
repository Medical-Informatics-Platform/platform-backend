package hbp.mip.configurations;

import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDAO;
import hbp.mip.user.UserRepository;
import hbp.mip.utils.Exceptions.TermsOfUseNotAcceptedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The terms-of-use gate, exercised as the security chain runs it: the authentication is already in the
 * SecurityContext, and the filter either lets the request through or hands a TermsOfUseNotAcceptedException
 * to the MVC exception resolver (ControllerExceptionHandler in production; the rendered body is covered by
 * TermsOfUseSecurityChainTest, which also covers blocked and agreed session and Bearer users). The real
 * ActiveUserService is used so the username is extracted from the Bearer principal as in production.
 */
@ExtendWith(MockitoExtension.class)
class TermsOfUseFilterTest {

    private static final String CONTEXT_PATH = "/services";

    @Mock
    private UserRepository userRepository;

    private final List<Exception> resolved = new ArrayList<>();
    private boolean resolverRenders = true;

    private TermsOfUseFilter filter;

    @BeforeEach
    void setUp() {
        HandlerExceptionResolver resolver = (request, response, handler, ex) -> {
            resolved.add(ex);
            if (!resolverRenders) {
                return null;
            }
            response.setStatus(403);
            return new ModelAndView();
        };
        filter = new TermsOfUseFilter(new ActiveUserService(userRepository), resolver, SecurityConfiguration.PUBLIC_PATHS);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    // ------------------------------------------------------------------ blocked

    @Test
    void bearerUserNotYetInTheDatabaseIsBlockedAndNotCreated() throws Exception {
        when(userRepository.findByUsername("bob")).thenReturn(null);
        authenticate(bearer("bob"));

        assertBlocked(run("GET", "/data-models"));
        verify(userRepository, never()).save(any());
    }

    @Test
    void onlyReadingTheActiveUserIsExempt() throws Exception {
        storedUser("alice", false);
        authenticate(bearer("alice"));

        assertBlocked(run("POST", "/activeUser"));
    }

    @Test
    void exemptionIsByExactPathNotByPrefix() throws Exception {
        storedUser("alice", false);
        authenticate(bearer("alice"));

        assertBlocked(run("GET", "/activeUserX"));
    }

    @Test
    void fallsBackToAPlain403WhenTheResolverCannotRender() throws Exception {
        resolverRenders = false;
        storedUser("alice", false);
        authenticate(bearer("alice"));

        MockHttpServletResponse response = run("GET", "/experiments");

        assertBlocked(response);
        assertThat(response.getErrorMessage()).isEqualTo(TermsOfUseNotAcceptedException.MESSAGE);
    }

    // ------------------------------------------------------------------ exempt

    // agreeNDA passes the gate for every client; ActiveUserService.agreeToNDA accepts portal sessions only.
    @ParameterizedTest
    @CsvSource({
            "GET, /activeUser",
            "POST, /activeUser/agreeNDA",
            "GET, /actuator",
            "GET, /actuator/health",
            "GET, /v3/api-docs",
            "GET, /v3/api-docs/swagger-config",
            "GET, /swagger-ui/index.html",
            "GET, /swagger-ui.html",
            "GET, /login/oauth2/code/keycloak",
            "GET, /oauth2/authorization/keycloak"})
    void termsFlowAndPublicEndpointsAreExempt(String method, String path) throws Exception {
        authenticate(bearer("alice"));

        assertPassed(run(method, path));
        verify(userRepository, never()).findByUsername(any());
    }

    // ------------------------------------------------------------------ helpers

    private MockHttpServletResponse run(String method, String path) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, CONTEXT_PATH + path);
        request.setContextPath(CONTEXT_PATH);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, response, chain);
        // MockFilterChain records the request only when the filter let it through.
        if (chain.getRequest() != null) {
            response.setHeader("X-Passed", "true");
        }
        return response;
    }

    private void assertBlocked(MockHttpServletResponse response) {
        assertThat(response.getHeader("X-Passed")).isNull();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(resolved).singleElement().isInstanceOf(TermsOfUseNotAcceptedException.class);
    }

    private void assertPassed(MockHttpServletResponse response) {
        assertThat(response.getHeader("X-Passed")).isEqualTo("true");
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(resolved).isEmpty();
    }

    private void storedUser(String username, boolean agreeNDA) {
        UserDAO user = new UserDAO(username, username, username + "@example.org", "subject-" + username);
        user.setAgreeNDA(agreeNDA);
        when(userRepository.findByUsername(username)).thenReturn(user);
    }

    private static void authenticate(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private static Authentication bearer(String username) {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject("subject-" + username)
                .claim("preferred_username", username)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
        return new JwtAuthenticationToken(jwt, List.of());
    }
}
