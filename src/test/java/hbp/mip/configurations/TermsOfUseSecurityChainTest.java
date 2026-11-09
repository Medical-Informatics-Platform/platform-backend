package hbp.mip.configurations;

import hbp.mip.user.ActiveUserAPI;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.AuthConfigAPI;
import hbp.mip.user.UserDAO;
import hbp.mip.user.UserRepository;
import hbp.mip.utils.ControllerExceptionHandler;
import hbp.mip.utils.Exceptions.TermsOfUseNotAcceptedException;
import hbp.mip.utils.Exceptions.UserIdentityConflictException;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import jakarta.servlet.http.Cookie;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The terms-of-use gate through the real SecurityConfiguration filter chain, so moving the filter to a point
 * where the session or Bearer authentication is not yet known fails here. The real ActiveUserAPI and
 * ControllerExceptionHandler render the responses; /experiments is a stand-in. No datasource, Keycloak or
 * Exaflow. A Bearer token's value is {@code <username>[.<azp>[.<typ>[.<sub>]]]}; azp defaults to the platform
 * client, typ to Bearer and sub to the username.
 */
@SpringJUnitWebConfig(TermsOfUseSecurityChainTest.Config.class)
@TestPropertySource(properties = {"authentication.enabled=1", "authentication.cli_client_id=mip-cli",
        "authentication.session_max_age=8h",
        "spring.security.oauth2.client.registration.keycloak.client-id=client",
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://idp.example.org/realms/MIP"})
class TermsOfUseSecurityChainTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private FailureEvents failures;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        reset(userRepository);
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .addFilters(context.getBean("springSecurityFilterChain", Filter.class))
                .build();
    }

    @Test
    void bearerUserWhoHasNotAgreedIsBlocked() throws Exception {
        storedUser("alice", false);

        mvc.perform(withBearer(get("/services/experiments"), "alice"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.statusCode").value(403))
                .andExpect(jsonPath("$.message").value(TermsOfUseNotAcceptedException.MESSAGE))
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.description").value("uri=/services/experiments"));
    }

    @Test
    void bearerUserWhoAgreedReachesTheController() throws Exception {
        storedUser("alice", true);

        mvc.perform(withBearer(get("/services/experiments"), "alice"))
                .andExpect(status().isOk())
                .andExpect(content().string("experiments"));
    }

    @Test
    void bearerTokenOfAnotherClientIsRejected() throws Exception {
        storedUser("alice", true);

        // e.g. another federation's portal token, whatever its aud says.
        mvc.perform(withBearer(get("/services/experiments"), "alice.other-federation"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectedBearerTokenPublishesAFailureEventWithoutTheToken() throws Exception {
        failures.events.clear();

        mvc.perform(withBearer(get("/services/experiments"), "alice.other-federation"))
                .andExpect(status().isUnauthorized());

        assertThat(failures.events).singleElement()
                .satisfies(event -> assertThat(event.getException().getClass().getSimpleName())
                        .doesNotContain("alice"));
    }

    // B1's premise: every Bearer (and DPoP) authentication publishes a success event, so the per-request
    // login log line with its client is produced for API clients too, and no operator decision is needed.
    @Test
    void everyBearerAuthenticationPublishesASuccessEvent() throws Exception {
        storedUser("alice", true);
        failures.successes.clear();

        mvc.perform(withBearer(get("/services/experiments"), "alice"))
                .andExpect(status().isOk());

        assertThat(failures.successes).singleElement().satisfies(event -> {
            assertThat(event.getAuthentication().getName()).isEqualTo("alice");
            assertThat(event.getAuthentication().getPrincipal()).isInstanceOf(Jwt.class);
        });
    }

    // A DPoP-scheme request carries an Authorization header, so it is never cookie-authenticated and needs
    // no CSRF token; without this exemption Spring would 403 every DPoP POST.
    @Test
    void aDpopSchemePostIsExemptFromCsrf() throws Exception {
        int status = mvc.perform(post("/services/experiments").contextPath("/services")
                        .header("Authorization", "DPoP some-token"))
                .andReturn().getResponse().getStatus();

        // The DPoP filter itself is off while cli_require_dpop is, so this stays unauthenticated (302 or
        // 401, as for any unauthenticated request); what matters is that it is not 403 CSRF.
        assertThat(status).isIn(302, 401);
    }

    @Test
    void aDpopSchemeWithoutATokenIsNotExemptFromCsrf() throws Exception {
        // The exemption is scheme-plus-space, like Bearer: a header that names no token gets no exemption.
        mvc.perform(post("/services/experiments").contextPath("/services").header("Authorization", "DPoP"))
                .andExpect(status().isForbidden());
    }

    @Test
    void bearerTokenOfTheLaptopClientIsAccepted() throws Exception {
        storedUser("alice", true);

        mvc.perform(withBearer(get("/services/experiments"), "alice.mip-cli"))
                .andExpect(status().isOk());
    }

    @Test
    void idTokenOfThisFederationIsRejectedAsBearerToken() throws Exception {
        storedUser("alice", true);

        mvc.perform(withBearer(get("/services/experiments"), "alice.client.ID"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void bearerClientCannotAcceptTheTerms() throws Exception {
        storedUser("alice", false);

        mvc.perform(withBearer(post("/services/activeUser/agreeNDA"), "alice"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value(TermsOfUseNotAcceptedException.MESSAGE));
        verify(userRepository, never()).save(any());
    }

    @Test
    void tokenEndpointNoLongerExists() throws Exception {
        storedUser("alice", true);

        mvc.perform(withBearer(get("/services/activeUser/token"), "alice"))
                .andExpect(status().isNotFound());
    }

    @Test
    void bearerUserWhoHasNotAgreedCanStillReadTheActiveUser() throws Exception {
        mvc.perform(withBearer(get("/services/activeUser"), "alice"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.agreeNDA").value(false));
    }

    @Test
    void usernameHeldByAnotherSubjectIsForbidden() throws Exception {
        UserDAO previousHolder = new UserDAO("alice", "alice", "alice@example.org", "sub-1");
        previousHolder.setAgreeNDA(true);
        when(userRepository.findByUsername("alice")).thenReturn(previousHolder);

        mvc.perform(withBearer(get("/services/activeUser"), "alice.client.Bearer.sub-2"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value(UserIdentityConflictException.MESSAGE));
        mvc.perform(withBearer(get("/services/experiments"), "alice.client.Bearer.sub-2"))
                .andExpect(status().isForbidden());
    }

    @Test
    void sessionUserWhoHasNotAgreedIsBlocked() throws Exception {
        storedUser("alice", false);

        mvc.perform(get("/services/experiments").contextPath("/services").session(session("alice")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value(TermsOfUseNotAcceptedException.MESSAGE));
    }

    @Test
    void sessionUserWhoHasNotAgreedCanAcceptTheTerms() throws Exception {
        storedUser("alice", false);

        mvc.perform(post("/services/activeUser/agreeNDA").contextPath("/services").session(session("alice"))
                        .cookie(new Cookie("XSRF-TOKEN", "csrf"))
                        .header("X-XSRF-TOKEN", "csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.agreeNDA").value(true));
        verify(userRepository, atLeastOnce()).save(argThat(user -> Boolean.TRUE.equals(user.getAgreeNDA())));
    }

    @Test
    void authConfigIsPublic() throws Exception {
        mvc.perform(get("/services/auth-config").contextPath("/services"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://idp.example.org/realms/MIP"))
                .andExpect(jsonPath("$.clientId").value("mip-cli"));
    }

    @Test
    void sessionPastItsMaximumAgeIsSignedOut() throws Exception {
        storedUser("alice", true);
        MockHttpSession session = session("alice");
        mvc.perform(get("/services/experiments").contextPath("/services").session(session))
                .andExpect(status().isOk());

        // MockHttpSession's creation time is fixed: an old session is one created before "now minus the maximum".
        MockHttpSession old = new MockHttpSession() {
            @Override
            public long getCreationTime() {
                return System.currentTimeMillis() - Duration.ofHours(9).toMillis();
            }
        };
        old.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));

        assertThat(mvc.perform(get("/services/experiments").contextPath("/services").session(old))
                .andReturn().getResponse().getStatus()).isIn(302, 401);
        assertThat(old.isInvalid()).isTrue();
    }

    @Test
    void backChannelLogoutIsReachableWithoutASessionAndRefusesABadToken() throws Exception {
        mvc.perform(post("/services/logout/connect/back-channel/keycloak").contextPath("/services")
                        .contentType("application/x-www-form-urlencoded").param("logout_token", "not-a-token"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void apiDescriptionAndActuatorRootNeedALogin() throws Exception {
        for (String path : List.of("/services/v3/api-docs", "/services/swagger-ui.html", "/services/actuator")) {
            assertThat(mvc.perform(get(path).contextPath("/services")).andReturn().getResponse().getStatus())
                    .as(path).isIn(302, 401);
        }
    }

    @Test
    void logoutClearsTheSiteDataOverHttps() throws Exception {
        mvc.perform(post("/services/logout").contextPath("/services").secure(true).session(session("alice")))
                .andExpect(header().string("Clear-Site-Data", "\"cache\", \"storage\""))
                .andExpect(cookie().maxAge("jupyterhub-hub-login", 0))
                .andExpect(cookie().path("jupyterhub-hub-login", "/notebook/hub/"));
    }

    @Test
    void loopbackLogoutEndsTheSessionWithoutACsrfToken() throws Exception {
        // MockMvc's default remote address is 127.0.0.1: Spring's back-channel logout calls this instance from there.
        MockHttpSession session = session("alice");

        mvc.perform(post("/services/logout").contextPath("/services").session(session))
                .andExpect(status().is3xxRedirection());

        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void remoteLogoutNeedsTheCsrfToken() throws Exception {
        RequestPostProcessor remote = request -> {
            request.setRemoteAddr("203.0.113.5");
            return request;
        };

        mvc.perform(post("/services/logout").contextPath("/services").with(remote).session(session("alice")))
                .andExpect(status().isForbidden());
        // What the portal's sign-out form sends: the value of the XSRF-TOKEN cookie.
        mvc.perform(post("/services/logout").contextPath("/services").with(remote).session(session("alice"))
                        .cookie(new Cookie("XSRF-TOKEN", "csrf")).param("_csrf", "csrf"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void authenticationCanOnlyBeOffForALocalPortal() {
        assertThat(SecurityConfiguration.isLocalOrUnset("")).isTrue();
        assertThat(SecurityConfiguration.isLocalOrUnset("http://localhost")).isTrue();
        assertThat(SecurityConfiguration.isLocalOrUnset("http://localhost:4200")).isTrue();
        assertThat(SecurityConfiguration.isLocalOrUnset("https://hbpmip.link")).isFalse();
        // No host can be read from these, and each may still be a public portal.
        assertThat(SecurityConfiguration.isLocalOrUnset("mip.example.org")).isFalse();
        assertThat(SecurityConfiguration.isLocalOrUnset("mip.example.org:443")).isFalse();
        assertThat(SecurityConfiguration.isLocalOrUnset("https://my_portal.example.org")).isFalse();
        assertThat(SecurityConfiguration.isLocalOrUnset("http://a b")).isFalse();
    }

    @Test
    void unauthenticatedRequestIsStillRejectedByAuthentication() throws Exception {
        int status = mvc.perform(get("/services/experiments").contextPath("/services"))
                .andReturn().getResponse().getStatus();

        // 302 to the login page or 401, depending on which entry point Spring Security picks; never our 403.
        assertThat(status).isIn(302, 401);
    }

    private void storedUser(String username, boolean agreeNDA) {
        UserDAO user = new UserDAO(username, username, username + "@example.org", username);
        user.setAgreeNDA(agreeNDA);
        when(userRepository.findByUsername(username)).thenReturn(user);
    }

    private static MockHttpServletRequestBuilder withBearer(MockHttpServletRequestBuilder request, String username) {
        return request.contextPath("/services").header("Authorization", "Bearer " + username);
    }

    private static MockHttpSession session(String username) {
        OidcIdToken idToken = new OidcIdToken("id-token", Instant.now(), Instant.now().plusSeconds(300),
                Map.of("sub", username, "preferred_username", username));
        DefaultOidcUser user = new DefaultOidcUser(List.of(), idToken, "preferred_username");
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new SecurityContextImpl(new OAuth2AuthenticationToken(user, List.of(), "keycloak")));
        return session;
    }

    @Configuration
    @EnableWebMvc
    @Import({SecurityConfiguration.class, SpaRedirectAuthenticationSuccessHandler.class,
            FrontendRedirectCaptureFilter.class, ControllerExceptionHandler.class, ActiveUserAPI.class,
            AuthConfigAPI.class, StandInAPI.class, FailureEvents.class})
    static class Config {

        @Bean
        public AuthenticationEventListener authenticationEventListener() {
            return new AuthenticationEventListener();
        }

        @Bean
        UserRepository userRepository() {
            return mock(UserRepository.class);
        }

        @Bean
        ActiveUserService activeUserService(UserRepository userRepository) {
            return new ActiveUserService(userRepository);
        }

        // Applies every OAuth2TokenValidator<Jwt> bean, as Spring Boot's issuer-uri JwtDecoder does.
        @Bean
        JwtDecoder jwtDecoder(ObjectProvider<OAuth2TokenValidator<Jwt>> validators) {
            OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators.orderedStream().toList());
            return token -> {
                String[] parts = token.split("\\.");
                Jwt jwt = Jwt.withTokenValue(token)
                        .header("alg", "none")
                        .subject(parts.length > 3 ? parts[3] : parts[0])
                        .claim("preferred_username", parts[0])
                        .claim("azp", parts.length > 1 ? parts[1] : "client")
                        .claim("typ", parts.length > 2 ? parts[2] : "Bearer")
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(300))
                        .build();
                OAuth2TokenValidatorResult result = validator.validate(jwt);
                if (result.hasErrors()) {
                    throw new JwtValidationException("invalid token", result.getErrors());
                }
                return jwt;
            };
        }

        @Bean
        ClientRegistrationRepository clientRegistrationRepository() {
            return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("keycloak")
                    .clientId("client")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .authorizationUri("https://idp.example.org/auth")
                    .tokenUri("https://idp.example.org/token")
                    .build());
        }
    }

    static class FailureEvents {
        final List<AbstractAuthenticationFailureEvent> events = new ArrayList<>();
        final List<AuthenticationSuccessEvent> successes = new ArrayList<>();

        @EventListener
        void record(AbstractAuthenticationFailureEvent event) {
            events.add(event);
        }

        @EventListener
        void recordSuccess(AuthenticationSuccessEvent event) {
            successes.add(event);
        }
    }

    @RestController
    static class StandInAPI {
        @GetMapping("/experiments")
        String experiments() {
            return "experiments";
        }
    }
}
