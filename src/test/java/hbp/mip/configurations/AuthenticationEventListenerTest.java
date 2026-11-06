package hbp.mip.configurations;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

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
}
