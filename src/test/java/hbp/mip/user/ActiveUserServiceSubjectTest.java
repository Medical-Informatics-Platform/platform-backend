package hbp.mip.user;

import hbp.mip.utils.Exceptions.UserIdentityConflictException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Users are stored by username, which Keycloak may give to someone else later: the stored subject must match.
 */
@ExtendWith(MockitoExtension.class)
class ActiveUserServiceSubjectTest {

    @Mock
    private UserRepository userRepository;

    private ActiveUserService service;

    @BeforeEach
    void setUp() {
        service = new ActiveUserService(userRepository);
        ReflectionTestUtils.setField(service, "authenticationIsEnabled", true);
    }

    @Test
    void sameSubjectGetsItsStoredUser() {
        storedUser("sub-1");

        assertThat(service.getActiveUser(token("sub-1")).agreeNDA()).isTrue();
        assertThat(service.hasAgreedToNDA(token("sub-1"))).isTrue();
    }

    @Test
    void anotherSubjectIsRefusedAndChangesNothing() {
        storedUser("sub-1");

        assertThatThrownBy(() -> service.getActiveUser(token("sub-2")))
                .isInstanceOf(UserIdentityConflictException.class);
        verify(userRepository, never()).save(any());
    }

    @Test
    void anotherSubjectDoesNotInheritTheAcceptedTerms() {
        storedUser("sub-1");

        assertThatThrownBy(() -> service.hasAgreedToNDA(token("sub-2")))
                .isInstanceOf(UserIdentityConflictException.class);
    }

    @Test
    void rowWithoutARealSubjectIsFilledIn() {
        // Empty, or the username fallback buildUserFromAuthentication writes for a token without a subject.
        for (String legacySubject : new String[] {null, "", "alice"}) {
            storedUser(legacySubject);

            assertThat(service.getActiveUser(token("sub-2")).subjectId()).isEqualTo("sub-2");
        }
        verify(userRepository, org.mockito.Mockito.times(3))
                .save(argThat(user -> "sub-2".equals(user.getSubjectId())));
    }

    @Test
    void tokenWithoutASubjectIsNotAConflict() {
        storedUser("sub-1");

        Jwt jwt = Jwt.withTokenValue("t").header("alg", "RS256").claim("preferred_username", "alice")
                .claim("email", "alice@example.org").claim("name", "alice").build();

        assertThat(service.getActiveUser(new JwtAuthenticationToken(jwt)).subjectId()).isEqualTo("sub-1");
    }

    private void storedUser(String subject) {
        UserDAO user = new UserDAO("alice", "alice", "alice@example.org", subject);
        user.setAgreeNDA(true);
        when(userRepository.findByUsername("alice")).thenReturn(user);
    }

    private static Authentication token(String subject) {
        return new JwtAuthenticationToken(Jwt.withTokenValue("t").header("alg", "RS256").subject(subject)
                .claim("preferred_username", "alice").claim("email", "alice@example.org").claim("name", "alice")
                .build());
    }
}
