package hbp.mip.configurations;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class SpaRedirectAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    public static final String REDIRECT_PATH_ATTRIBUTE = "SPA_REDIRECT_TARGET_PATH";

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

        if (frontendBaseUrl == null) {
            // No frontend base URL available. Fallback to relative redirect on the backend domain.
            return targetPath;
        }

        if ("/".equals(targetPath)) {
            return frontendBaseUrl + "/";
        }

        return frontendBaseUrl + targetPath;
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

    /** A path on this site: exactly one leading slash, because //host and /\host are other sites to a browser. */
    static String normalizeRedirectPath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }

        String normalized = "/" + path.trim().replaceFirst("^[/\\\\]+", "");

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
