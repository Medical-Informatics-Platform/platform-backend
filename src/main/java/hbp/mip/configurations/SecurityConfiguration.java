package hbp.mip.configurations;

import hbp.mip.user.ActiveUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerExceptionResolver;

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
            "/actuator/**",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html"};

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

            // Allow API clients (e.g. notebooks) to authenticate with Bearer JWTs.
            // This runs alongside oauth2Login (session-based) authentication.
            http.oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));

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
            http.logout(logout -> logout.logoutSuccessHandler(successHandler));

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
                        return authz != null && authz.startsWith("Bearer ");
                    })
                    .ignoringRequestMatchers("/logout"));
            // <--- XSRF Token handling

        } else {
            http.authorizeHttpRequests(auth -> auth
                    .requestMatchers("/**").permitAll());
            http.csrf((csrf) -> csrf
                    .ignoringRequestMatchers("/**"));

        }
        return http.build();
    }

    // Spring Boot adds this to the issuer-uri JwtDecoder: a Bearer token must have been issued to this
    // federation's own Keycloak client (shared by the portal and JupyterHub), not merely by the same realm.
    // Keycloak names the requesting client in azp. aud is not enough: other federations' tokens can list this
    // client there (Keycloak adds every client the user has roles on), and their authorities claim holds the
    // other federation's roles.
    @Bean
    OAuth2TokenValidator<Jwt> keycloakClientValidator() {
        return clientValidator(keycloakClientId);
    }

    static OAuth2TokenValidator<Jwt> clientValidator(String... clientIds) {
        Set<String> allowed = Arrays.stream(clientIds).filter(StringUtils::hasText).collect(Collectors.toSet());
        return jwt -> allowed.contains(jwt.getClaimAsString("azp"))
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                        "The token was not issued for this MIP platform", null));
    }

    private static JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter fallback = new JwtGrantedAuthoritiesConverter();
        // Do not force ROLE_ prefix; the app expects raw authority strings (e.g. research_dataset_*).
        fallback.setAuthorityPrefix("");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter((Jwt jwt) -> {
            List<GrantedAuthority> out = new ArrayList<>();

            // 1) Preferred: our realm may map roles directly into an "authorities" claim.
            Object raw = jwt.getClaims().get("authorities");
            if (raw instanceof Collection<?> col) {
                for (Object v : col) {
                    if (v != null) {
                        out.add(new SimpleGrantedAuthority(v.toString()));
                    }
                }
            }

            // 2) Keycloak default: realm_access.roles
            Object realmAccess = jwt.getClaims().get("realm_access");
            if (realmAccess instanceof Map<?, ?> m) {
                Object roles = m.get("roles");
                if (roles instanceof Collection<?> col) {
                    for (Object v : col) {
                        if (v != null) {
                            out.add(new SimpleGrantedAuthority(v.toString()));
                        }
                    }
                }
            }

            // 3) Keycloak default: resource_access.<client>.roles (collect all client roles)
            Object resourceAccess = jwt.getClaims().get("resource_access");
            if (resourceAccess instanceof Map<?, ?> ra) {
                for (Object entryVal : ra.values()) {
                    if (!(entryVal instanceof Map<?, ?> m)) {
                        continue;
                    }
                    Object roles = m.get("roles");
                    if (!(roles instanceof Collection<?> col)) {
                        continue;
                    }
                    for (Object v : col) {
                        if (v != null) {
                            out.add(new SimpleGrantedAuthority(v.toString()));
                        }
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
