package hbp.mip.configurations;

import hbp.mip.user.ActiveUserAPI;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.AuthConfigAPI;
import hbp.mip.user.UserDAO;
import hbp.mip.user.UserRepository;
import hbp.mip.utils.ControllerExceptionHandler;
import hbp.mip.utils.Exceptions.TermsOfUseNotAcceptedException;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
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
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import jakarta.servlet.http.Cookie;
import java.time.Instant;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The terms-of-use gate through the real SecurityConfiguration filter chain, so moving the filter to a point
 * where the session or Bearer authentication is not yet known fails here. The real ActiveUserAPI and
 * ControllerExceptionHandler render the responses; /experiments is a stand-in. No datasource, Keycloak or
 * Exaflow. A Bearer token's value is {@code <username>[.<azp>]}; azp defaults to the platform client.
 */
@SpringJUnitWebConfig(TermsOfUseSecurityChainTest.Config.class)
@TestPropertySource(properties = {"authentication.enabled=1", "authentication.cli_client_id=mip-cli",
        "spring.security.oauth2.client.registration.keycloak.client-id=client",
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://idp.example.org/realms/MIP"})
class TermsOfUseSecurityChainTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private UserRepository userRepository;

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
    void bearerTokenOfTheLaptopClientIsAccepted() throws Exception {
        storedUser("alice", true);

        mvc.perform(withBearer(get("/services/experiments"), "alice.mip-cli"))
                .andExpect(status().isOk());
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
    void tokenEndpointIsBlockedUntilTheTermsAreAccepted() throws Exception {
        storedUser("alice", false);

        mvc.perform(withBearer(get("/services/activeUser/token"), "alice"))
                .andExpect(status().isForbidden());
    }

    @Test
    void bearerUserWhoHasNotAgreedCanStillReadTheActiveUser() throws Exception {
        mvc.perform(withBearer(get("/services/activeUser"), "alice"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.agreeNDA").value(false));
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
            AuthConfigAPI.class, StandInAPI.class})
    static class Config {

        @Bean
        UserRepository userRepository() {
            return mock(UserRepository.class);
        }

        @Bean
        ActiveUserService activeUserService(UserRepository userRepository) {
            return new ActiveUserService(userRepository);
        }

        @Bean
        OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository registrations) {
            return new InMemoryOAuth2AuthorizedClientService(registrations);
        }

        // Applies every OAuth2TokenValidator<Jwt> bean, as Spring Boot's issuer-uri JwtDecoder does.
        @Bean
        JwtDecoder jwtDecoder(ObjectProvider<OAuth2TokenValidator<Jwt>> validators) {
            OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators.orderedStream().toList());
            return token -> {
                String[] parts = token.split("\\.");
                Jwt jwt = Jwt.withTokenValue(token)
                        .header("alg", "none")
                        .subject(parts[0])
                        .claim("preferred_username", parts[0])
                        .claim("azp", parts.length > 1 ? parts[1] : "client")
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

    @RestController
    static class StandInAPI {
        @GetMapping("/experiments")
        String experiments() {
            return "experiments";
        }
    }
}
