package hbp.mip.configurations;

import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;

/**
 * Ends all of a user's portal sessions on any back-channel logout. Keycloak's "sign out this user" sends one logout
 * token per client, naming one session, however many are open; following that sid would leave the others alive. The
 * cost is that signing out at Keycloak in one browser also ends the portal in the user's other browsers.
 */
class UserWideOidcSessionRegistry implements OidcSessionRegistry {

    private final OidcSessionRegistry delegate = new InMemoryOidcSessionRegistry();

    @Override
    public void saveSessionInformation(OidcSessionInformation info) {
        delegate.saveSessionInformation(info);
    }

    @Override
    public OidcSessionInformation removeSessionInformation(String clientSessionId) {
        return delegate.removeSessionInformation(clientSessionId);
    }

    @Override
    public Iterable<OidcSessionInformation> removeSessionInformation(OidcLogoutToken logoutToken) {
        // A token may name only a session: there is no subject to widen the match to.
        if (logoutToken.getSubject() == null) {
            return delegate.removeSessionInformation(logoutToken);
        }
        // Without a sid, the registry matches on the token's subject.
        return delegate.removeSessionInformation(OidcLogoutToken.withTokenValue(logoutToken.getTokenValue())
                .claims(claims -> {
                    claims.putAll(logoutToken.getClaims());
                    claims.remove("sid");
                })
                .build());
    }
}
