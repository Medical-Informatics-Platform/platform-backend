package hbp.mip.configurations;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakClientValidatorTest {

    private final OAuth2TokenValidator<Jwt> validator = SecurityConfiguration.clientValidator("mippublic", "mip-cli");

    private static Jwt token(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("t").header("alg", "RS256").claim("sub", "alice");
        claims.forEach(builder::claim);
        return builder.build();
    }

    @Test
    void acceptsTokensIssuedToThisFederationsClients() {
        assertThat(validator.validate(token(Map.of("azp", "mippublic", "aud", List.of("account")))).hasErrors()).isFalse();
        assertThat(validator.validate(token(Map.of("azp", "mip-cli", "aud", List.of("mippublic")))).hasErrors()).isFalse();
    }

    @Test
    void rejectsOtherFederationsTokensEvenWhenTheyNameThisClientInAud() {
        // Keycloak's audience resolve lists every client the user has roles on.
        assertThat(validator.validate(token(Map.of("azp", "mipfed_dementia", "aud", List.of("mipfed_dementia", "mippublic"))))
                .hasErrors()).isTrue();
        assertThat(validator.validate(token(Map.of("azp", "other", "aud", List.of("account")))).hasErrors()).isTrue();
        assertThat(validator.validate(token(Map.of("sub", "alice"))).hasErrors()).isTrue();
    }

    @Test
    void anUnsetLaptopClientAdmitsNothingExtra() {
        OAuth2TokenValidator<Jwt> platformOnly = SecurityConfiguration.clientValidator("mippublic", "");
        assertThat(platformOnly.validate(token(Map.of("azp", "mippublic"))).hasErrors()).isFalse();
        assertThat(platformOnly.validate(token(Map.of("azp", ""))).hasErrors()).isTrue();
    }

    @Test
    void acceptsOnlyAccessTokens() {
        OAuth2TokenValidator<Jwt> accessTokens = new SecurityConfiguration(null, null, null, null).accessTokenValidator();
        assertThat(accessTokens.validate(token(Map.of("typ", "Bearer"))).hasErrors()).isFalse();
        assertThat(accessTokens.validate(token(Map.of("typ", "ID"))).hasErrors()).isTrue();
        assertThat(accessTokens.validate(token(Map.of("typ", "Refresh"))).hasErrors()).isTrue();
        assertThat(accessTokens.validate(token(Map.of())).hasErrors()).isTrue();
    }

    @Test
    void requiredAudienceIsCheckedOnlyWhenSet() {
        OAuth2TokenValidator<Jwt> required = SecurityConfiguration.audienceValidator("mippublic");
        assertThat(required.validate(token(Map.of("aud", List.of("account", "mippublic")))).hasErrors()).isFalse();
        assertThat(required.validate(token(Map.of("aud", List.of("account")))).hasErrors()).isTrue();
        assertThat(required.validate(token(Map.of())).hasErrors()).isTrue();

        assertThat(SecurityConfiguration.audienceValidator("").validate(token(Map.of())).hasErrors()).isFalse();
    }

    @Test
    void rejectsEverythingWithoutAClientId() {
        assertThat(SecurityConfiguration.clientValidator("", "").validate(token(Map.of("azp", ""))).hasErrors()).isTrue();
    }

    // The validator only sees the JWT; the request tells Bearer and DPoP apart.
    @AfterEach
    void forgetTheRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    private static void requestArrivedWith(String scheme) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", scheme + " the-token");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @Test
    void whenRequiredEveryLaptopTokenMustBeDpopBoundAndArriveWithTheDpopScheme() {
        OAuth2TokenValidator<Jwt> validator = SecurityConfiguration.dpopValidator("mip-cli", true);

        assertThat(validator.validate(token(Map.of("azp", "mip-cli"))).hasErrors()).isTrue();
        assertThat(validator.validate(token(Map.of("azp", "mip-cli", "cnf", Map.of("jkt", "thumbprint"))))
                .hasErrors()).isTrue();

        requestArrivedWith("DPoP");
        assertThat(validator.validate(token(Map.of("azp", "mip-cli"))).hasErrors()).isTrue();
        assertThat(validator.validate(token(Map.of("azp", "mip-cli", "cnf", Map.of("jkt", "thumbprint"))))
                .hasErrors()).isFalse();
    }

    @Test
    void platformTokensKeepWorkingOverBearerWhenDpopIsRequired() {
        OAuth2TokenValidator<Jwt> validator = SecurityConfiguration.dpopValidator("mip-cli", true);

        assertThat(validator.validate(token(Map.of("azp", "mippublic", "cnf", Map.of("jkt", "thumbprint"))))
                .hasErrors()).isFalse();
        assertThat(validator.validate(token(Map.of("azp", "mippublic"))).hasErrors()).isFalse();
    }

    @Test
    void withoutTheFlagOrTheLaptopClientTheValidatorAdmitsEverything() {
        assertThat(SecurityConfiguration.dpopValidator("mip-cli", false)
                .validate(token(Map.of("azp", "mip-cli"))).hasErrors()).isFalse();
        assertThat(SecurityConfiguration.dpopValidator("", true)
                .validate(token(Map.of("azp", "mip-cli"))).hasErrors()).isFalse();
    }

    @Test
    void withoutARequestScopeTheValidatorFailsClosed() {
        OAuth2TokenValidator<Jwt> validator = SecurityConfiguration.dpopValidator("mip-cli", true);

        assertThat(validator.validate(token(Map.of("azp", "mip-cli", "cnf", Map.of("jkt", "thumbprint"))))
                .hasErrors()).isTrue();
    }
}
