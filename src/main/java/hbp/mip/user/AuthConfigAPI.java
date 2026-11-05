package hbp.mip.user;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * Tells the mip client which Keycloak to sign in with from the user's own computer (`mip login`, OAuth 2.0
 * device flow). Public: the issuer and a public client's id are not secrets. 404 when the platform has no
 * client for it, so the client can say laptop sign-in is not set up here.
 */
@RestController
@RequestMapping(value = "/auth-config", produces = { APPLICATION_JSON_VALUE })
public class AuthConfigAPI {

    record AuthConfigDTO(String issuer, String clientId) {
    }

    private final String issuer;
    private final String cliClientId;

    public AuthConfigAPI(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") String issuer,
            @Value("${authentication.cli_client_id:}") String cliClientId) {
        this.issuer = issuer;
        this.cliClientId = cliClientId;
    }

    @GetMapping
    public ResponseEntity<AuthConfigDTO> getAuthConfig() {
        if (!StringUtils.hasText(issuer) || !StringUtils.hasText(cliClientId)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(new AuthConfigDTO(issuer, cliClientId));
    }
}
