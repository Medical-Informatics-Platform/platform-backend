package hbp.mip.configurations;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Provides a dummy {@link ClientRegistrationRepository} when authentication is disabled, so
 * Spring Security's OAuth2 auto-configuration has a bean to autowire without triggering a
 * Keycloak server lookup.
 * <p>
 * This deliberately lives in its own {@link Configuration} class (not inside
 * {@link SecurityConfiguration}) to avoid a circular reference: {@code OAuth2ClientConfiguration}
 * autowires this bean while {@code SecurityConfiguration} is still being created.
 * See https://github.com/spring-projects/spring-security/issues/11397
 */
@Configuration
@ConditionalOnProperty(prefix = "authentication", name = "enabled", havingValue = "0")
public class DummyClientRegistrationConfiguration {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration dummyRegistration = ClientRegistration.withRegistrationId("dummy")
                .clientId("google-client-id")
                .clientSecret("google-client-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid")
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .build();
        return new InMemoryClientRegistrationRepository(dummyRegistration);
    }
}
