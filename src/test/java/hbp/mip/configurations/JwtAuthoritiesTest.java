package hbp.mip.configurations;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthoritiesTest {

    private static List<String> authorities(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("t").header("alg", "RS256").claim("sub", "alice");
        claims.forEach(builder::claim);
        return SecurityConfiguration.jwtAuthenticationConverter("mippublic").convert(builder.build())
                .getAuthorities().stream().map(GrantedAuthority::getAuthority)
                // Spring Security adds FACTOR_BEARER itself; only the role mapping is under test.
                .filter(authority -> !authority.startsWith("FACTOR_")).toList();
    }

    @Test
    void takesClientRolesOnlyFromThePlatformClient() {
        assertThat(authorities(Map.of("resource_access", Map.of(
                "mippublic", Map.of("roles", List.of("research_dataset_dementia")),
                "other-federation", Map.of("roles", List.of("research_dataset_all")),
                "account", Map.of("roles", List.of("manage-account"))))))
                .containsExactly("research_dataset_dementia");
    }

    @Test
    void keepsTheAuthoritiesClaimButNotRealmRoles() {
        assertThat(authorities(Map.of(
                "authorities", List.of("research_experiment_all"),
                "realm_access", Map.of("roles", List.of("research_dataset_tbi")),
                "resource_access", Map.of("other-federation", Map.of("roles", List.of("research_dataset_all"))))))
                .containsExactly("research_experiment_all");
    }

    @Test
    void realmRolesAndOtherClientsRolesAloneGrantNothing() {
        assertThat(authorities(Map.of(
                "realm_access", Map.of("roles", List.of("research_dataset_tbi")),
                "resource_access", Map.of("other-federation", Map.of("roles", List.of("research_dataset_all"))))))
                .doesNotContain("research_dataset_tbi", "research_dataset_all");
    }
}
