package hbp.mip.configurations;

import hbp.mip.utils.Logger;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEventListener {

    @EventListener
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        String username = authentication.getName();
        Logger logger = new Logger(username, "LOGGING IN");
        logger.info("User " + username + " has logged in successfully from " + remoteAddress(authentication));

        // If you need to log additional details:
        authentication.getAuthorities().forEach(authority ->
                logger.debug("User " + username + " has authority " + authority.getAuthority())
        );
    }

    @EventListener
    public void handleAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        // Never the authentication's name: on a failed Bearer request that is the token itself.
        Logger logger = new Logger("unknown", "LOGGING IN");
        String message = "Authentication failed from " + remoteAddress(event.getAuthentication())
                + ": " + event.getException().getClass().getSimpleName();
        // A client polling with a stale token is routine and would flood the log; anything else may be an attack.
        if (isExpiredToken(event.getException())) {
            logger.debug(message);
        } else {
            logger.warn(message);
        }
    }

    // Spring Security marks expiry only in the message, written by JwtTimestampValidator.
    static boolean isExpiredToken(Exception exception) {
        return exception.getMessage() != null && exception.getMessage().contains("Jwt expired at");
    }

    private static String remoteAddress(Authentication authentication) {
        return authentication.getDetails() instanceof WebAuthenticationDetails details
                ? details.getRemoteAddress()
                : "unknown";
    }
}
