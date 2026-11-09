package hbp.mip.configurations;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import hbp.mip.user.ActiveUserAPI;
import hbp.mip.user.ActiveUserService;
import hbp.mip.user.AuthConfigAPI;
import hbp.mip.user.UserDAO;
import hbp.mip.user.UserRepository;
import hbp.mip.utils.ControllerExceptionHandler;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The laptop client over the DPoP scheme (RFC 9449) through the real SecurityConfiguration filter chain with
 * {@code authentication.cli_require_dpop=1}. The DPoP proof is signed here with a throwaway RSA key; the
 * access token's {@code cnf.jkt} claim carries that key's thumbprint, as Keycloak would set it. A Bearer
 * token's value is {@code <username>[.<azp>[.<typ>[.<sub>[.<jkt>]]]]}}.
 */
@SpringJUnitWebConfig(DpopSecurityChainTest.Config.class)
@TestPropertySource(properties = {"authentication.enabled=1", "authentication.cli_client_id=mip-cli",
        "authentication.cli_require_dpop=true", "authentication.session_max_age=8h",
        "spring.security.oauth2.client.registration.keycloak.client-id=client",
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://idp.example.org/realms/MIP"})
class DpopSecurityChainTest {

    // The proof is signed with a throwaway key; the access token names its thumbprint in cnf.jkt.
    private static final RSAKey PROOF_JWK = proofKey();
    private static final String THUMBPRINT = thumbprint(PROOF_JWK);

    private static String thumbprint(RSAKey key) {
        try {
            return key.computeThumbprint().toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static RSAKey proofKey() {
        try {
            KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
            rsa.initialize(2048);
            KeyPair keyPair = rsa.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

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

    @AfterEach
    void forgetTheRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void aDpopBoundLaptopTokenOverTheDpopSchemeIsNotBlockedByCsrfAndGetsThrough() throws Exception {
        storedUser("alice", true);

        mvc.perform(withDpop(post("/services/experiments"), laptopToken("alice")))
                .andExpect(status().isOk())
                .andExpect(content().string("experiments"));
    }

    @Test
    void theSameProofIsAReplay() throws Exception {
        storedUser("alice", true);

        String proof = proof(laptopToken("alice"));
        MockHttpServletRequestBuilder request = post("/services/experiments").contextPath("/services")
                .header("Authorization", "DPoP " + laptopToken("alice"))
                .header("DPoP", proof)
                .with(inRequestScope());

        assertThat(mvc.perform(request).andReturn().getResponse().getStatus()).isEqualTo(200);
        assertThat(mvc.perform(request).andReturn().getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void aDpopBoundLaptopTokenIsRefusedOverBearer() throws Exception {
        storedUser("alice", true);

        // In request scope, so the refusal tests the Bearer scheme, not the missing request scope.
        mvc.perform(withBearer(get("/services/experiments"), laptopToken("alice")).with(inRequestScope()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void aLaptopTokenWithoutTheBindingIsRefused() throws Exception {
        storedUser("alice", true);
        String unbound = laptopToken("alice").replace("." + THUMBPRINT, "");

        assertThat(mvc.perform(withBearer(get("/services/experiments"), unbound))
                .andReturn().getResponse().getStatus()).isEqualTo(401);
        assertThat(mvc.perform(withDpop(post("/services/experiments"), unbound))
                .andReturn().getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void aPlatformTokenOverBearerIsUnaffected() throws Exception {
        storedUser("alice", true);

        mvc.perform(withBearer(get("/services/experiments"), "alice"))
                .andExpect(status().isOk());
    }

    @Test
    void aProofForAnotherUrlIsRefused() throws Exception {
        storedUser("alice", true);
        String token = laptopToken("alice");

        // What a request looks like when nginx does not pass X-Forwarded-Proto/Host: the proof names the
        // public https URL, but the backend still sees its own http one.
        String proofForPublicUrl = proof(token, "https://portal.example.org/services/experiments");
        int status = mvc.perform(post("/services/experiments").contextPath("/services")
                        .header("Authorization", "DPoP " + token)
                        .header("DPoP", proofForPublicUrl)
                        .with(inRequestScope()))
                .andReturn().getResponse().getStatus();

        assertThat(status).isEqualTo(401);
    }

    @Test
    void aDpopRequestWithoutAProofIsRefused() throws Exception {
        storedUser("alice", true);

        mvc.perform(post("/services/experiments").contextPath("/services")
                        .header("Authorization", "DPoP " + laptopToken("alice"))
                        .with(inRequestScope()))
                .andExpect(status().isUnauthorized());
    }

    // The proof's htu is the request URL as the backend sees it; MockMvc serves http://localhost/services.
    private static String proof(String accessToken) {
        return proof(accessToken, "http://localhost/services/experiments");
    }

    private static String proof(String accessToken, String htu) {
        try {
            SignedJWT proof = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .type(new JOSEObjectType("dpop+jwt"))
                            .jwk(PROOF_JWK.toPublicJWK())
                            .build(),
                    new JWTClaimsSet.Builder()
                            .claim("htm", "POST")
                            .claim("htu", htu)
                            .claim("iat", Instant.now().getEpochSecond())
                            .claim("jti", UUID.randomUUID().toString())
                            .claim("ath", sha256UrlSafe(accessToken))
                            .build());
            try {
                proof.sign(new RSASSASigner(PROOF_JWK));
            } catch (com.nimbusds.jose.JOSEException e) {
                throw new IllegalStateException(e);
            }
            return proof.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String sha256UrlSafe(String value) {
        try {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(java.security.MessageDigest.getInstance("SHA-256")
                            .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String laptopToken(String username) {
        return username + ".mip-cli.Bearer." + username + "." + THUMBPRINT;
    }

    private MockHttpServletRequestBuilder withDpop(MockHttpServletRequestBuilder request, String token) {
        return request.contextPath("/services")
                .header("Authorization", "DPoP " + token)
                .header("DPoP", proof(token))
                // The validators read the request from RequestContextHolder, which only the real
                // RequestContextFilter would set; MockMvc does not.
                .with(inRequestScope());
    }

    private MockHttpServletRequestBuilder withBearer(MockHttpServletRequestBuilder request, String username) {
        return request.contextPath("/services").header("Authorization", "Bearer " + username);
    }

    private static RequestPostProcessor inRequestScope() {
        return request -> {
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
            return request;
        };
    }

    private void storedUser(String username, boolean agreeNDA) {
        UserDAO user = new UserDAO(username, username, username + "@example.org", username);
        user.setAgreeNDA(agreeNDA);
        when(userRepository.findByUsername(username)).thenReturn(user);
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

        // Applies every OAuth2TokenValidator<Jwt> bean, as Spring Boot's issuer-uri JwtDecoder does.
        @Bean
        JwtDecoder jwtDecoder(ObjectProvider<OAuth2TokenValidator<Jwt>> validators) {
            OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators.orderedStream().toList());
            return token -> {
                String[] parts = token.split("\\.");
                Jwt.Builder builder = Jwt.withTokenValue(token)
                        .header("alg", "none")
                        .subject(parts.length > 3 ? parts[3] : parts[0])
                        .claim("preferred_username", parts[0])
                        .claim("azp", parts.length > 1 ? parts[1] : "client")
                        .claim("typ", parts.length > 2 ? parts[2] : "Bearer")
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(300));
                if (parts.length > 4) {
                    builder.claim("cnf", Map.of("jkt", parts[4]));
                }
                Jwt jwt = builder.build();
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

        @PostMapping("/experiments")
        String runExperiments() {
            return "experiments";
        }
    }
}
