package hbp.mip.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * agreeToNDA in authentication-disabled mode, which TermsOfUseSecurityChainTest (authentication enabled)
 * does not reach: the portal-session-only rule must not apply to the anonymous user.
 */
@ExtendWith(MockitoExtension.class)
class ActiveUserServiceAgreeToNDATest {

    @Mock
    private UserRepository userRepository;

    @Test
    void authenticationDisabledModeIsUnchanged() {
        ActiveUserService service = new ActiveUserService(userRepository);
        ReflectionTestUtils.setField(service, "authenticationIsEnabled", false);

        UserDTO user = service.agreeToNDA(null);

        assertThat(user.username()).isEqualTo("anonymous");
        assertThat(user.agreeNDA()).isTrue();
    }
}
