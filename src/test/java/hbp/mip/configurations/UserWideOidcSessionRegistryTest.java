package hbp.mip.configurations;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class UserWideOidcSessionRegistryTest {

    private static final String ISSUER = "https://idp.example.org/realms/MIP";

    @Test
    void logoutNamingOneSessionEndsAllOfThatUsersSessionsOnly() {
        UserWideOidcSessionRegistry registry = new UserWideOidcSessionRegistry();
        registry.saveSessionInformation(session("portal-1", "keycloak-1", "alice"));
        registry.saveSessionInformation(session("portal-2", "keycloak-2", "alice"));
        registry.saveSessionInformation(session("portal-3", "keycloak-3", "bob"));

        OidcLogoutToken token = OidcLogoutToken.withTokenValue("t").issuer(ISSUER).subject("alice")
                .sessionId("keycloak-1").audience(List.of("mippublic")).issuedAt(Instant.now()).jti("j").build();

        assertThat(registry.removeSessionInformation(token)).extracting(OidcSessionInformation::getSessionId)
                .containsExactlyInAnyOrder("portal-1", "portal-2");
        assertThat(registry.removeSessionInformation("portal-3")).isNotNull();
    }

    @Test
    void logoutNamingOnlyASessionEndsThatSession() {
        UserWideOidcSessionRegistry registry = new UserWideOidcSessionRegistry();
        registry.saveSessionInformation(session("portal-1", "keycloak-1", "alice"));
        registry.saveSessionInformation(session("portal-2", "keycloak-2", "alice"));

        OidcLogoutToken token = OidcLogoutToken.withTokenValue("t").issuer(ISSUER)
                .sessionId("keycloak-1").audience(List.of("mippublic")).issuedAt(Instant.now()).jti("j").build();

        assertThat(registry.removeSessionInformation(token)).extracting(OidcSessionInformation::getSessionId)
                .containsExactly("portal-1");
    }

    private static OidcSessionInformation session(String portalSession, String keycloakSession, String subject) {
        OidcIdToken idToken = new OidcIdToken("id", Instant.now(), Instant.now().plusSeconds(300),
                Map.of("iss", ISSUER, "sub", subject, "sid", keycloakSession, "aud", List.of("mippublic")));
        return new OidcSessionInformation(portalSession, Map.of(),
                new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, idToken));
    }
}
