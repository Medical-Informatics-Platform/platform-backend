package hbp.mip.configurations;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

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
    void rejectsEverythingWithoutAClientId() {
        assertThat(SecurityConfiguration.clientValidator("", "").validate(token(Map.of("azp", ""))).hasErrors()).isTrue();
    }
}
