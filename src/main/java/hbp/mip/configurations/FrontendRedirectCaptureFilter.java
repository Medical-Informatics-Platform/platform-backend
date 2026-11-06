package hbp.mip.configurations;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Remembers where to send the user after login. Only the path: the host comes from frontend.base-url, never from
 * the request, or a crafted link would redirect a freshly signed-in user to another site.
 */
@Component
public class FrontendRedirectCaptureFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_PATH = "/oauth2/authorization";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (isAuthorizationRequest(request)) {
            String targetPath = resolveTargetPath(request);
            if (StringUtils.hasText(targetPath)) {
                request.getSession(true).setAttribute(SpaRedirectAuthenticationSuccessHandler.REDIRECT_PATH_ATTRIBUTE, targetPath);
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isAuthorizationRequest(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        String expectedPrefix = contextPath + AUTHORIZATION_PATH;
        return requestUri.startsWith(expectedPrefix);
    }

    private String resolveTargetPath(HttpServletRequest request) {
        String explicitValue = request.getParameter("frontend_redirect");
        if (StringUtils.hasText(explicitValue)) {
            URI explicitUri = parseUri(explicitValue);
            if (explicitUri != null && StringUtils.hasText(explicitUri.getScheme()) && StringUtils.hasText(explicitUri.getRawAuthority())) {
                // frontend_redirect can be a full URL (e.g. http://localhost:4200/#/home).
                return buildPathQueryFragment(explicitUri);
            }

            // Otherwise treat it as a path (or hash route) and normalize.
            return normalizePath(explicitValue);
        }

        URI refererUri = parseUri(request.getHeader("Referer"));
        return refererUri != null ? buildPathQueryFragment(refererUri) : null;
    }

    private URI parseUri(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            return new URI(value);
        } catch (URISyntaxException ex) {
            return null;
        }
    }

    private static String buildPathQueryFragment(URI uri) {
        String path = uri.getRawPath();
        String query = uri.getRawQuery();
        String fragment = uri.getRawFragment();

        if (!StringUtils.hasText(path)) {
            path = "/";
        }

        String normalizedPath = normalizePath(path);
        if (StringUtils.hasText(query)) {
            normalizedPath += "?" + query;
        }
        if (StringUtils.hasText(fragment)) {
            normalizedPath += "#" + fragment;
        }

        return normalizedPath;
    }

    private static String normalizePath(String path) {
        return SpaRedirectAuthenticationSuccessHandler.normalizeRedirectPath(path);
    }
}
