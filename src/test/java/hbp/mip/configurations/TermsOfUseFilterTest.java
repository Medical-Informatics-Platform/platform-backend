package hbp.mip.configurations;

import hbp.mip.user.ActiveUserService;
import hbp.mip.user.UserDAO;
import hbp.mip.user.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The terms-of-use gate, exercised as the security chain runs it: the authentication is already in the
 * SecurityContext, and the filter either lets the request through or answers 403 itself. The real
 * ActiveUserService is used so the username is extracted from session and Bearer principals as in production.
 */
@ExtendWith(MockitoExtension.class)
class TermsOfUseFilterTest {

    private static final String CONTEXT_PATH = "/services";

    @Mock
    private UserRepository userRepository;

    private TermsOfUseFilter filter;

    @BeforeEach
    void setUp() {
        filter = new TermsOfUseFilter(new ActiveUserService(userRepository));
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    // ------------------------------------------------------------------ blocked

    @Test
    void bearerUserWhoHasNotAgreedIsBlocked() throws Exception {
        storedUser("alice", false);
        authenticate(bearer("alice"));

        MockHttpServletResponse response = run("GET", "/experiments");

        assertBlocked(response);
    }

    @Test
    void sessionUserWhoHasNotAgreedIsBlocked() throws Exception {
        storedUser("alice", false);
        authenticate(session("alice"));

        MockHttpServletResponse response = run("POST", "/experiments/runs");

        assertBlocked(response);
    }

    @Test
    void bearerUserNotYetInTheDatabaseIsBlockedAndNotCreated() throws Exception {
        when(userRepository.findByUsername("bob")).thenReturn(null);
        authenticate(bearer("bob"));

        MockHttpServletResponse response = run("GET", "/data-models");

        assertBlocked(response);
        verify(userRepository, never()).save(any());
    }

    // ------------------------------------------------------------------ allowed

    @Test
    void bearerUserWhoAgreedPasses() throws Exception {
        storedUser("alice", true);
        authenticate(bearer("alice"));

        MockHttpServletResponse response = run("GET", "/experiments");

        assertPassed(response);
    }

    @Test
    void sessionUserWhoAgreedPasses() throws Exception {
        storedUser("alice", true);
        authenticate(session("alice"));

        MockHttpServletResponse response = run("GET", "/specifications/algorithms");

        assertPassed(response);
    }

    @Test
    void anonymousRequestsAreLeftToSpringSecurity() throws Exception {
        authenticate(new AnonymousAuthenticationToken("key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

        MockHttpServletResponse response = run("GET", "/experiments");

        assertPassed(response);
        verify(userRepository, never()).findByUsername(any());
    }

    // ------------------------------------------------------------------ exempt

    @ParameterizedTest
    @ValueSource(strings = {
            "/activeUser",
            "/activeUser/agreeNDA",
            "/activeUser/token",
            "/logout",
            "/login/oauth2/code/keycloak",
            "/oauth2/authorization/keycloak",
            "/actuator/health",
            "/v3/api-docs",
            "/v3/api-docs/swagger-config",
            "/swagger-ui/index.html",
            "/swagger-ui.html"})
    void termsFlowAndPublicEndpointsAreExempt(String path) throws Exception {
        authenticate(bearer("alice"));

        MockHttpServletResponse response = run("GET", path);

        assertPassed(response);
        verify(userRepository, never()).findByUsername(any());
    }

    @Test
    void exemptionIsByExactPathNotByPrefix() throws Exception {
        storedUser("alice", false);
        authenticate(bearer("alice"));

        assertBlocked(run("GET", "/activeUserX"));
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

    private static void assertBlocked(MockHttpServletResponse response) throws Exception {
        assertThat(response.getHeader("X-Passed")).isNull();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getContentAsString()).contains(TermsOfUseFilter.MESSAGE);
    }

    private static void assertPassed(MockHttpServletResponse response) {
        assertThat(response.getHeader("X-Passed")).isEqualTo("true");
        assertThat(response.getStatus()).isEqualTo(200);
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

    private static Authentication session(String username) {
        OidcIdToken idToken = new OidcIdToken("id-token", Instant.now(), Instant.now().plusSeconds(300),
                Map.of("sub", "subject-" + username, "preferred_username", username));
        DefaultOidcUser user = new DefaultOidcUser(List.of(), idToken, "preferred_username");
        return new OAuth2AuthenticationToken(user, List.of(), "keycloak");
    }
}
