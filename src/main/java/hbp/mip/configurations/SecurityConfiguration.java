package hbp.mip.configurations;

import hbp.mip.user.ActiveUserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.convert.DurationStyle;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

    // Reachable without login, and without accepting the terms of use.
    static final String[] PUBLIC_PATHS = {
            "/login/**",
            "/oauth2/**",
            "/auth-config",
            "/actuator/health/**"};

    private final SpaRedirectAuthenticationSuccessHandler spaRedirectAuthenticationSuccessHandler;
    private final FrontendRedirectCaptureFilter frontendRedirectCaptureFilter;
    private final ActiveUserService activeUserService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Value("${authentication.enabled}")
    private boolean authenticationEnabled;

    @Value("${frontend.base-url:}")
    private String frontendBaseUrl;

    // The Keycloak client shared by the portal and JupyterHub.
    @Value("${spring.security.oauth2.client.registration.keycloak.client-id:}")
    private String keycloakClientId;

    @Value("${authentication.session_max_age:8h}")
    private String sessionMaxAge;

    // The public Keycloak client (device flow) of the mip client on users' own computers is named by the
    // validator beans below; the chain itself only needs the DPoP flag.
    @Value("${authentication.cli_require_dpop:false}")
    private boolean cliRequireDpop;

    @Value("${server.port:8080}")
    private int serverPort;

    @Value("${server.servlet.contextPath:/services}")
    private String contextPath;

    public SecurityConfiguration(SpaRedirectAuthenticationSuccessHandler spaRedirectAuthenticationSuccessHandler,
            FrontendRedirectCaptureFilter frontendRedirectCaptureFilter,
            ActiveUserService activeUserService,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver handlerExceptionResolver) {
        this.spaRedirectAuthenticationSuccessHandler = spaRedirectAuthenticationSuccessHandler;
        this.frontendRedirectCaptureFilter = frontendRedirectCaptureFilter;
        this.activeUserService = activeUserService;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    // The dummy ClientRegistrationRepository (used when authentication is disabled and no
    // Keycloak server is running, to avoid the OAuth2 server lookup bug) is defined in
    // DummyClientRegistrationConfiguration. It is kept in a separate @Configuration class to
    // avoid a circular reference; see that class for details.

    @Bean
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http,
            ClientRegistrationRepository clientRegistrationRepo) throws Exception {
        if (authenticationEnabled) {
            http.addFilterBefore(frontendRedirectCaptureFilter, OAuth2AuthorizationRequestRedirectFilter.class);
            http.authorizeHttpRequests(auth -> auth
                    .requestMatchers(PUBLIC_PATHS)
                    .permitAll()
                    .requestMatchers("/**").authenticated());

            http.oauth2Login(login -> login.successHandler(spaRedirectAuthenticationSuccessHandler));

            http.addFilterBefore(new SessionMaxAgeFilter(DurationStyle.detectAndParse(sessionMaxAge)), SecurityContextHolderFilter.class);

            // Keycloak ends a disabled user's or a signed-out user's portal session (needs the client's Backchannel
            // Logout URL). Spring then calls /logout on this instance with that session's cookie.
            // ponytail: the session registry is in memory, one backend replica; a shared registry if that changes.
            http.oidcLogout(logout -> logout.backChannel(backChannel -> backChannel
                    .logoutUri("http://localhost:" + serverPort + contextPath + "/logout")));

            // Allow API clients (e.g. notebooks) to authenticate with Bearer JWTs.
            // This runs alongside oauth2Login (session-based) authentication.
            http.oauth2ResourceServer(oauth2 -> {
                oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter(keycloakClientId)));
                if (cliRequireDpop) {
                    // Spring's DPoP filter takes "Authorization: DPoP <token>" plus a DPoP proof header and
                    // verifies the proof: its signature, htm/htu against this request, iat, jti replay and
                    // the token's cnf.jkt against the proof's key. It reads request.getRequestURL(), which
                    // the native forward-headers strategy builds from X-Forwarded-Proto/Host, so nginx must
                    // send those for the backend location (platform-ui's nginx.conf.template does not yet).
                    // ponytail: Spring keeps proof replays in an in-memory jti cache, one backend replica.
                    oauth2.dPoP(Customizer.withDefaults());
                }
            });

            // Terms of use (NDA) apply to session and Bearer clients alike, not only to the portal UI.
            http.addFilterAfter(new TermsOfUseFilter(activeUserService, handlerExceptionResolver, PUBLIC_PATHS),
                    AuthorizationFilter.class);

            // Open ID Logout
            // https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html#oauth2login-advanced-oidc-logout
            OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(
                    clientRegistrationRepo);
            if (StringUtils.hasText(frontendBaseUrl)) {
                successHandler.setPostLogoutRedirectUri(frontendBaseUrl);
            }
            http.logout(logout -> logout
                    // Not its cookies directive: browsers apply that to the whole registrable domain, so signing out
                    // of a portal on a shared domain would also sign the user out of unrelated services.
                    .addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(
                            ClearSiteDataHeaderWriter.Directive.CACHE,
                            ClearSiteDataHeaderWriter.Directive.STORAGE)))
                    .addLogoutHandler(new CookieClearingLogoutHandler(
                            expiredHubCookie("jupyterhub-hub-login"), expiredHubCookie("jupyterhub-session-id")))
                    .deleteCookies("JSESSIONID")
                    .logoutSuccessHandler(successHandler));

            // ---> XSRF Token handling
            // https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#deferred-csrf-token
            // https://stackoverflow.com/questions/74447118/csrf-protection-not-working-with-spring-security-6
            XorCsrfTokenRequestAttributeHandler requestHandler = new XorCsrfTokenRequestAttributeHandler();
            // set the name of the attribute the CsrfToken will be populated on
            requestHandler.setCsrfRequestAttributeName(null);

            // Change cookie path
            CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
            tokenRepository.setCookiePath("/");

            http.csrf((csrf) -> csrf
                    .csrfTokenRepository(tokenRepository)
                    .csrfTokenRequestHandler(requestHandler::handle)
                    // Bearer-token clients should not need CSRF (they are not cookie-authenticated).
                    .ignoringRequestMatchers((request) -> {
                        String authz = request.getHeader("Authorization");
                        // Same prefix test Spring's DPoP filter uses, so no request that filter handles
                        // still gets 403 for CSRF.
                        return authz != null && (StringUtils.startsWithIgnoreCase(authz, "Bearer ")
                                || StringUtils.startsWithIgnoreCase(authz, "DPoP"));
                    })
                    // Only this instance's own call: Spring's back-channel logout posts here without a token.
                    .ignoringRequestMatchers(SecurityConfiguration::isLocalLogout));
            // <--- XSRF Token handling

        } else {
            if (!isLocalOrUnset(frontendBaseUrl)) {
                throw new IllegalStateException("AUTHENTICATION is off but the portal is public at " + frontendBaseUrl
                        + ": every endpoint would be open. Turn authentication on.");
            }
            http.authorizeHttpRequests(auth -> auth
                    .requestMatchers("/**").permitAll());
            http.csrf((csrf) -> csrf
                    .ignoringRequestMatchers("/**"));

        }
        return http.build();
    }

    // Back-channel logout keeps session ids in its registry; login changes the id, and the registry only hears of it
    // through these events. Without them Keycloak's logout finds no session to end.
    @Bean
    HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    OidcSessionRegistry oidcSessionRegistry() {
        return new UserWideOidcSessionRegistry();
    }

    // ponytail: assumes the hub's default base path; a setting if a deployment moves it. A notebook server's own
    // cookie is not cleared, because its path holds the username: it ends at the hub's next token refresh.
    private static Cookie expiredHubCookie(String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setPath("/notebook/hub/");
        cookie.setMaxAge(0);
        return cookie;
    }

    private static boolean isLocalLogout(HttpServletRequest request) {
        String address = request.getRemoteAddr();
        return PathPatternRequestMatcher.pathPattern("/logout").matches(request)
                && ("127.0.0.1".equals(address) || "0:0:0:0:0:0:0:1".equals(address) || "::1".equals(address));
    }

    static boolean isLocalOrUnset(String url) {
        if (!StringUtils.hasText(url)) {
            return true;
        }
        // A URL with no host we can read (no scheme, a bad character) may still be public: never count it as local.
        String host;
        try {
            host = new URI(url.trim()).getHost();
        } catch (URISyntaxException e) {
            return false;
        }
        return host != null && (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]"));
    }

    // The default publisher sends no event for OAuth2 exceptions, so failed Bearer and OIDC logins would go unlogged.
    @Bean
    AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
        DefaultAuthenticationEventPublisher eventPublisher = new DefaultAuthenticationEventPublisher(publisher);
        eventPublisher.setDefaultAuthenticationFailureEvent(AuthenticationFailureBadCredentialsEvent.class);
        return eventPublisher;
    }

    // Spring Boot adds this to the issuer-uri JwtDecoder: a Bearer token must have been issued to one of this
    // federation's own Keycloak clients, not merely by the same realm. Keycloak names the requesting client in azp:
    // the platform client (shared by the portal and JupyterHub) or the public client of the mip client on users'
    // own computers. aud is not enough: other federations' tokens can list this client there (Keycloak adds every
    // client the user has roles on), and their authorities claim holds the other federation's roles.
    @Bean
    OAuth2TokenValidator<Jwt> keycloakClientValidator(@Value("${authentication.cli_client_id:}") String cliClientId) {
        return clientValidator(keycloakClientId, cliClientId);
    }

    static OAuth2TokenValidator<Jwt> clientValidator(String... clientIds) {
        Set<String> allowed = Arrays.stream(clientIds).filter(StringUtils::hasText).collect(Collectors.toSet());
        return jwt -> allowed.contains(jwt.getClaimAsString("azp"))
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                        "The token was not issued for this MIP platform", null));
    }

    // Optional, because not every federation's tokens name this service in aud yet: set it once they do.
    @Bean
    OAuth2TokenValidator<Jwt> requiredAudienceValidator(@Value("${authentication.required_audience:}") String audience) {
        return audienceValidator(audience);
    }

    // The laptop client's tokens must be DPoP-bound: Spring's DPoP filter verifies the proof, and this
    // validator refuses a laptop-client token without the binding or one that arrives over the Bearer
    // scheme. Platform-client tokens (portal, notebooks) stay Bearer. Only meaningful together with the
    // dPoP() configurer above, which the same flag turns on.
    @Bean
    OAuth2TokenValidator<Jwt> cliDpopValidator(
            @Value("${authentication.cli_client_id:}") String cliClientId,
            @Value("${authentication.cli_require_dpop:false}") boolean requireDpop) {
        return dpopValidator(cliClientId, requireDpop);
    }

    static OAuth2TokenValidator<Jwt> dpopValidator(String cliClientId, boolean requireDpop) {
        return jwt -> !requireDpop || !StringUtils.hasText(cliClientId)
                || !cliClientId.equals(jwt.getClaimAsString("azp"))
                || (isDpopBound(jwt) && arrivedWithDpopScheme())
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                        "The laptop client's token must be DPoP-bound and used with the DPoP scheme", null));
    }

    private static boolean isDpopBound(Jwt jwt) {
        Object confirmation = jwt.getClaims().get("cnf");
        return confirmation instanceof Map<?, ?> claims && claims.get("jkt") != null;
    }

    // The validators only see the JWT; the request tells Bearer and DPoP apart. Spring Boot registers its
    // RequestContextFilter before the security chain, so the request is in scope here; without it (tests)
    // this fails closed.
    static boolean arrivedWithDpopScheme() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (!(attributes instanceof ServletRequestAttributes servlet)) {
            return false;
        }
        String authz = servlet.getRequest().getHeader("Authorization");
        return authz != null && StringUtils.startsWithIgnoreCase(authz, OAuth2AccessToken.TokenType.DPOP.getValue());
    }

    static OAuth2TokenValidator<Jwt> audienceValidator(String audience) {
        return jwt -> !StringUtils.hasText(audience) || (jwt.getAudience() != null && jwt.getAudience().contains(audience))
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                        "The token is not meant for this MIP platform", null));
    }

    // Keycloak signs ID tokens with the same key and the same azp, so only its typ claim tells them from access tokens.
    // DPoP-bound access tokens may carry typ "DPoP" instead of "Bearer" (RFC 9449); then cnf.jkt must be
    // present, which is what makes such a token a bound access token and not an ID token. Keycloak's exact
    // typ for DPoP tokens is still to be confirmed on a DPoP-enabled realm.
    @Bean
    OAuth2TokenValidator<Jwt> accessTokenValidator() {
        return jwt -> {
            String typ = jwt.getClaimAsString("typ");
            return "Bearer".equals(typ) || ("DPoP".equals(typ) && isDpopBound(jwt))
                    ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                            "The token is not an access token", null));
        };
    }

    static JwtAuthenticationConverter jwtAuthenticationConverter(String clientId) {
        JwtGrantedAuthoritiesConverter fallback = new JwtGrantedAuthoritiesConverter();
        // Do not force ROLE_ prefix; the app expects raw authority strings (e.g. research_dataset_*).
        fallback.setAuthorityPrefix("");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter((Jwt jwt) -> {
            // 1) Preferred: our realm may map roles directly into an "authorities" claim.
            List<GrantedAuthority> out = new ArrayList<>(GrantedAuthoritiesMapperImpl.extractAuthorities(jwt.getClaims()));

            // 2) Keycloak default: resource_access.<client>.roles, of this federation's client only.
            // Realm roles (realm_access) and other clients' roles span every federation of the realm,
            // so they grant nothing here: no access crosses federations.
            Object resourceAccess = jwt.getClaims().get("resource_access");
            if (resourceAccess instanceof Map<?, ?> ra && ra.get(clientId) instanceof Map<?, ?> m
                    && m.get("roles") instanceof Collection<?> col) {
                for (Object v : col) {
                    if (v != null) {
                        out.add(new SimpleGrantedAuthority(v.toString()));
                    }
                }
            }

            if (!out.isEmpty()) {
                return out;
            }

            // Fallback to scope-based authorities if present.
            return fallback.convert(jwt);
        });
        return converter;
    }

    @Component
    @RequiredArgsConstructor
    static class GrantedAuthoritiesMapperImpl implements GrantedAuthoritiesMapper {
        private static Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
            Object rawAuthorities = claims.get("authorities");
            if (!(rawAuthorities instanceof Collection<?> authorities)) {
                return Collections.emptyList();
            }
            return authorities.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }

        @Override
        public Collection<? extends GrantedAuthority> mapAuthorities(
                Collection<? extends GrantedAuthority> authorities) {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                    mappedAuthorities.addAll(extractAuthorities(oidcUserAuthority.getIdToken().getClaims()));
                }
            });

            return mappedAuthorities;
        }
    }
}
