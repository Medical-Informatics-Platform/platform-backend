package hbp.mip.configurations;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationEventListenerTest {

    @Test
    void onlyAnExpiredTokenCountsAsRoutine() {
        assertThat(AuthenticationEventListener.isExpiredToken(new InvalidBearerTokenException(
                "An error occurred while attempting to decode the Jwt: Jwt expired at 2026-11-06T10:00:00Z"))).isTrue();
        assertThat(AuthenticationEventListener.isExpiredToken(new InvalidBearerTokenException(
                "An error occurred while attempting to decode the Jwt: Signed JWT rejected"))).isFalse();
        assertThat(AuthenticationEventListener.isExpiredToken(new BadCredentialsException(null))).isFalse();
    }

    @Test
    void aBearerLoginLogsItsClientButNeverTheToken() {
        Jwt token = Jwt.withTokenValue("token-value-never-log")
                .header("alg", "RS256")
                .claim("azp", "mip-cli-x")
                .build();
        JwtAuthenticationToken authentication = new JwtAuthenticationToken(token, List.of());

        assertThat(AuthenticationEventListener.clientSuffix(authentication)).isEqualTo(" client=mip-cli-x");
    }

    @Test
    void aJwtWithoutAClientLogsNone() {
        Jwt token = Jwt.withTokenValue("t").header("alg", "RS256").claim("sub", "alice").build();
        assertThat(AuthenticationEventListener.clientSuffix(new JwtAuthenticationToken(token, List.of())))
                .isEqualTo(" client=none");
    }
}
