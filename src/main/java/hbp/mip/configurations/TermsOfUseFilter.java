package hbp.mip.configurations;

import hbp.mip.user.ActiveUserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Set;

/**
 * Server-side enforcement of the MIP terms of use (NDA). The portal's TermsGuard only protects the UI,
 * so API clients (Bearer JWTs from notebooks or laptops) would otherwise skip it.
 *
 * Registered in the security chain after authorization, only when authentication is enabled; not a
 * {@code @Component} so Spring Boot does not also register it as a plain servlet filter.
 */
public class TermsOfUseFilter extends OncePerRequestFilter {

    static final String MESSAGE = "Accept the MIP terms of use in the portal before using the API";
    private static final String BODY = "{\"statusCode\":403,\"message\":\"" + MESSAGE + "\"}";

    // What the portal calls before the terms page is accepted (active user, agreeNDA, token),
    // the login/logout handshake, and the public infrastructure endpoints of SecurityConfiguration.
    private static final Set<String> EXEMPT_PATHS = Set.of(
            "/activeUser",
            "/activeUser/agreeNDA",
            "/activeUser/token",
            "/logout",
            "/actuator",
            "/v3/api-docs",
            "/swagger-ui.html");
    private static final List<String> EXEMPT_PREFIXES = List.of(
            "/login/",
            "/oauth2/",
            "/actuator/",
            "/v3/api-docs/",
            "/swagger-ui/");

    private final ActiveUserService activeUserService;

    public TermsOfUseFilter(ActiveUserService activeUserService) {
        this.activeUserService = activeUserService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return EXEMPT_PATHS.contains(path) || EXEMPT_PREFIXES.stream().anyMatch(path::startsWith);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken
                || activeUserService.hasAgreedToNDA(authentication)) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(BODY);
    }
}
