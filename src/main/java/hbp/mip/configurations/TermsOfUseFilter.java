package hbp.mip.configurations;

import hbp.mip.user.ActiveUserService;
import hbp.mip.utils.Exceptions.TermsOfUseNotAcceptedException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

/**
 * Server-side enforcement of the MIP terms of use (NDA). The portal's TermsGuard only protects the UI,
 * so API clients (Bearer JWTs from notebooks or laptops) would otherwise skip it.
 *
 * Registered in the security chain after authorization, only when authentication is enabled; not a
 * {@code @Component} so Spring Boot does not also register it as a plain servlet filter. The 403 is
 * rendered by ControllerExceptionHandler, like every other API error.
 */
public class TermsOfUseFilter extends OncePerRequestFilter {

    private final RequestMatcher exempt;
    private final ActiveUserService activeUserService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    /**
     * @param publicPaths the paths SecurityConfiguration permits without login; they stay reachable here too.
     */
    public TermsOfUseFilter(ActiveUserService activeUserService, HandlerExceptionResolver handlerExceptionResolver,
            String... publicPaths) {
        this.activeUserService = activeUserService;
        this.handlerExceptionResolver = handlerExceptionResolver;
        // Besides the public paths: what the portal calls before its terms page is accepted.
        // agreeNDA itself only accepts portal sessions (ActiveUserService.agreeToNDA).
        this.exempt = new OrRequestMatcher(Stream.<RequestMatcher>concat(
                Arrays.stream(publicPaths).map(PathPatternRequestMatcher::pathPattern),
                Stream.of(pathPattern(HttpMethod.GET, "/activeUser"), pathPattern(HttpMethod.POST, "/activeUser/agreeNDA")))
                .toList());
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return exempt.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Runs after AuthorizationFilter, so every request that gets here is authenticated.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (activeUserService.hasAgreedToNDA(authentication)) {
            filterChain.doFilter(request, response);
            return;
        }

        TermsOfUseNotAcceptedException exception = new TermsOfUseNotAcceptedException();
        if (handlerExceptionResolver.resolveException(request, response, null, exception) == null) {
            // ControllerExceptionHandler could not render it (e.g. the client does not accept JSON).
            response.sendError(HttpStatus.FORBIDDEN.value(), exception.getMessage());
        }
    }
}
