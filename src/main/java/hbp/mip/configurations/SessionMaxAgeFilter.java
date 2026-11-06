package hbp.mip.configurations;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

/**
 * Ends a portal session once it is older than the maximum, however active it is, so the roles it took from Keycloak
 * at login cannot live on. The servlet container only has an idle timeout.
 *
 * Runs before the security context is loaded, so the request continues as a signed-out one. Not a {@code @Component}
 * so Spring Boot does not also register it as a plain servlet filter.
 */
public class SessionMaxAgeFilter extends OncePerRequestFilter {

    private final long maxAgeMillis;

    public SessionMaxAgeFilter(Duration maxAge) {
        this.maxAgeMillis = maxAge.toMillis();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            try {
                if (System.currentTimeMillis() - session.getCreationTime() > maxAgeMillis) {
                    session.invalidate();
                }
            } catch (IllegalStateException alreadyInvalidated) {
                // A parallel request on the same session got here first: this one also continues signed out.
                logger.debug("Session was already invalidated");
            }
        }
        filterChain.doFilter(request, response);
    }
}
