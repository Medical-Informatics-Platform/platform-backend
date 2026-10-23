package hbp.mip.user;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthConfigAPITest {

    @Test
    void returnsIssuerAndCliClient() {
        var response = new AuthConfigAPI("https://idp.example.org/realms/MIP", "mip-cli").getAuthConfig();

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo(
                new AuthConfigAPI.AuthConfigDTO("https://idp.example.org/realms/MIP", "mip-cli"));
    }

    @Test
    void notFoundWithoutCliClient() {
        assertThat(new AuthConfigAPI("https://idp.example.org/realms/MIP", "").getAuthConfig()
                .getStatusCode().value()).isEqualTo(404);
    }
}
