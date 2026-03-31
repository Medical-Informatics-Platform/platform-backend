package hbp.mip.configurations;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;

@Component
public class SpaRedirectAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    public static final String REDIRECT_PATH_ATTRIBUTE = "SPA_REDIRECT_TARGET_PATH";
    public static final String PLATFORM_UI_BASE_URL_ATTRIBUTE = "SPA_REDIRECT_PLATFORM_UI_BASE_URL";

    private final String frontendBaseUrl;

    public SpaRedirectAuthenticationSuccessHandler(@Value("${frontend.base-url:}") String frontendBaseUrl) {
        // Don't crash the whole backend if this is missing. In production it SHOULD be set,
        // but dev tooling often runs without a full env-file loaded.
        this.frontendBaseUrl = StringUtils.hasText(frontendBaseUrl) ? normalizeBaseUrl(frontendBaseUrl) : null;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        String targetPath = resolveTargetPath(request);
        if (!StringUtils.hasText(targetPath)) {
            // Fallback: do not fail the login. Just go to backend root.
            return request.getContextPath() + "/";
        }

        String baseUrl = resolveFrontendBaseUrl(request);
        if (!StringUtils.hasText(baseUrl)) {
            // No frontend base URL available. Fallback to relative redirect on the backend domain.
            return targetPath;
        }

        if ("/".equals(targetPath)) {
            return baseUrl + "/";
        }

        return baseUrl + targetPath;
    }

    private String resolveTargetPath(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object attribute = session.getAttribute(REDIRECT_PATH_ATTRIBUTE);
            session.removeAttribute(REDIRECT_PATH_ATTRIBUTE);
            if (attribute instanceof String storedPath && !storedPath.isBlank()) {
                return normalizeRedirectPath(storedPath);
            }
        }
        return null;
    }

    private String resolveFrontendBaseUrl(HttpServletRequest request) {
        String sessionBaseUrl = resolveSessionFrontendBaseUrl(request);

        if (StringUtils.hasText(frontendBaseUrl)) {
            if (StringUtils.hasText(sessionBaseUrl) && shouldPreferSessionBaseUrl(frontendBaseUrl, sessionBaseUrl)) {
                return sessionBaseUrl;
            }
            return frontendBaseUrl;
        }

        if (StringUtils.hasText(sessionBaseUrl)) {
            return sessionBaseUrl;
        }

        return resolveRequestOrigin(request);
    }

    private static String resolveSessionFrontendBaseUrl(HttpServletRequest request) {
        // Dev/live fallback: FrontendRedirectCaptureFilter stores this based on Referer / frontend_redirect.
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }

        Object attribute = session.getAttribute(PLATFORM_UI_BASE_URL_ATTRIBUTE);
        session.removeAttribute(PLATFORM_UI_BASE_URL_ATTRIBUTE);
        if (attribute instanceof String storedUrl && StringUtils.hasText(storedUrl)) {
            return normalizeBaseUrl(storedUrl);
        }

        return null;
    }

    private static boolean shouldPreferSessionBaseUrl(String configuredBaseUrl, String sessionBaseUrl) {
        return isLoopbackBaseUrl(configuredBaseUrl) || sameOrigin(configuredBaseUrl, sessionBaseUrl);
    }

    private static boolean isLoopbackBaseUrl(String baseUrl) {
        URI uri = parseUri(baseUrl);
        if (uri == null || !StringUtils.hasText(uri.getHost())) {
            return false;
        }

        String host = uri.getHost();
        return "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host)
                || "0.0.0.0".equals(host)
                || "::1".equals(host);
    }

    private static boolean sameOrigin(String left, String right) {
        URI leftUri = parseUri(left);
        URI rightUri = parseUri(right);
        if (leftUri == null || rightUri == null) {
            return false;
        }

        String leftScheme = leftUri.getScheme();
        String rightScheme = rightUri.getScheme();
        String leftHost = leftUri.getHost();
        String rightHost = rightUri.getHost();
        if (!StringUtils.hasText(leftScheme) || !StringUtils.hasText(rightScheme)
                || !StringUtils.hasText(leftHost) || !StringUtils.hasText(rightHost)) {
            return false;
        }

        return leftScheme.equalsIgnoreCase(rightScheme)
                && leftHost.equalsIgnoreCase(rightHost)
                && resolvePort(leftUri) == resolvePort(rightUri);
    }

    private static int resolvePort(URI uri) {
        int port = uri.getPort();
        if (port >= 0) {
            return port;
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static String resolveRequestOrigin(HttpServletRequest request) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        if (!StringUtils.hasText(scheme) || !StringUtils.hasText(host)) {
            return null;
        }

        int port = request.getServerPort();
        boolean defaultHttpPort = "http".equalsIgnoreCase(scheme) && port == 80;
        boolean defaultHttpsPort = "https".equalsIgnoreCase(scheme) && port == 443;
        if (port <= 0 || defaultHttpPort || defaultHttpsPort) {
            return scheme + "://" + host;
        }

        return scheme + "://" + host + ":" + port;
    }

    private static URI parseUri(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }

        try {
            return new URI(value);
        } catch (URISyntaxException ex) {
            return null;
        }
    }

    private static String normalizeRedirectPath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }

        String normalized = path.trim();

        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }

        if (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        return normalized;
    }

    private static String normalizeBaseUrl(String baseUrl) {
        String trimmed = baseUrl.trim();
        if (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }
}
