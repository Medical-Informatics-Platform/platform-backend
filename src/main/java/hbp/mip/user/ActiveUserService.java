package hbp.mip.user;

import hbp.mip.utils.Exceptions.TermsOfUseNotAcceptedException;
import hbp.mip.utils.Exceptions.UserIdentityConflictException;
import hbp.mip.utils.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Service
public class ActiveUserService {

    private final UserRepository userRepository;
    @Value("${authentication.enabled}")

    private boolean authenticationIsEnabled;

    public ActiveUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Fetches the details of the active user.
     * If the user doesn't exist, it's created on the fly from the auth token.
     *
     * @return the userDAO
     */
    @Transactional
    public UserDTO getActiveUser(Authentication authentication) {
        UserDAO activeUserDAO;
        if (authenticationIsEnabled) {
            // If Authentication is ON, get user details from authentication info.
            activeUserDAO = buildUserFromAuthentication(authentication);

            UserDAO activeUserDatabaseDetails = userRepository.findByUsername(activeUserDAO.getUsername());
            if (activeUserDatabaseDetails != null) {
                refuseAnotherSubject(activeUserDatabaseDetails, activeUserDAO);
                boolean changed = false;
                if ((!Objects.equals(activeUserDAO.getEmail(), activeUserDatabaseDetails.getEmail()))
                        || !Objects.equals(activeUserDAO.getFullname(), activeUserDatabaseDetails.getFullname())) {
                    // Fullname and email are the only values allowed to change.
                    // username is the PK in our database and subjectid is the PK in keycloak
                    activeUserDatabaseDetails.setFullname(activeUserDAO.getFullname());
                    activeUserDatabaseDetails.setEmail(activeUserDAO.getEmail());
                    changed = true;
                }
                if (!isKnownSubject(activeUserDatabaseDetails) && isKnownSubject(activeUserDAO)) {
                    activeUserDatabaseDetails.setSubjectId(activeUserDAO.getSubjectId());
                    changed = true;
                }
                if (changed) {
                    userRepository.save(activeUserDatabaseDetails);
                }
                activeUserDAO = activeUserDatabaseDetails;
            } else {
                userRepository.save(activeUserDAO);
            }

        } else {
            // If Authentication is OFF, ensure anonymous user exists with accepted NDA.
            UserDAO anonymous = userRepository.findByUsername("anonymous");
            if (anonymous == null) {
                anonymous = new UserDAO("anonymous", "anonymous", "anonymous@anonymous.com", "anonymousId");
                anonymous.setAgreeNDA(true);
                userRepository.save(anonymous);
            } else if (!Boolean.TRUE.equals(anonymous.getAgreeNDA())) {
                anonymous.setAgreeNDA(true);
                userRepository.save(anonymous);
            }
            activeUserDAO = anonymous;
        }

        return new UserDTO(activeUserDAO);
    }

    @Transactional
    public UserDTO agreeToNDA(Authentication authentication) {
        // The terms are accepted by a person in the portal (OIDC session), never by an API client on their behalf.
        if (authenticationIsEnabled && !(authentication instanceof OAuth2AuthenticationToken)) {
            throw new TermsOfUseNotAcceptedException();
        }
        UserDTO userDTO = getActiveUser(authentication);

        UserDAO userDAO = userRepository.findByUsername(userDTO.username());
        if (userDAO == null) {
            userDAO = new UserDAO(userDTO);
        }

        userDAO.setAgreeNDA(true);
        userRepository.save(userDAO);

        return new UserDTO(userDAO);
    }

    /**
     * Per-request terms-of-use check: one lookup by username, never creates the user.
     * A user who has never called GET /activeUser does not exist yet, so has not agreed.
     */
    public boolean hasAgreedToNDA(Authentication authentication) {
        UserDAO authenticated = buildUserFromAuthentication(authentication);
        UserDAO user = userRepository.findByUsername(authenticated.getUsername());
        if (user == null) {
            return false;
        }
        refuseAnotherSubject(user, authenticated);
        return Boolean.TRUE.equals(user.getAgreeNDA());
    }

    // A username Keycloak gave to someone else must not inherit the previous holder's experiments or accepted terms.
    private static void refuseAnotherSubject(UserDAO stored, UserDAO authenticated) {
        if (isKnownSubject(stored) && isKnownSubject(authenticated)
                && !stored.getSubjectId().equals(authenticated.getSubjectId())) {
            new Logger(authenticated.getUsername(), "ActiveUserService")
                    .warn("Refused: the stored user has another Keycloak subject.");
            throw new UserIdentityConflictException();
        }
    }

    // buildUserFromAuthentication falls back to the username when a token has no subject, and older rows may be empty.
    private static boolean isKnownSubject(UserDAO user) {
        String subject = user.getSubjectId();
        return subject != null && !subject.isBlank() && !subject.equals(user.getUsername());
    }

    private static UserDAO buildUserFromAuthentication(Authentication authentication) {
        Object principal = authentication != null ? authentication.getPrincipal() : null;

        // Browser login flow (session-based): OIDC user.
        if (principal instanceof DefaultOidcUser oidcUser) {
            OidcUserInfo userinfo = oidcUser.getUserInfo();
            String username = firstNonBlank(
                    userinfo != null ? userinfo.getPreferredUsername() : null,
                    oidcUser.getName(),
                    oidcUser.getSubject());
            String fullName = firstNonBlank(
                    userinfo != null ? userinfo.getFullName() : null,
                    (String) oidcUser.getClaims().get("name"),
                    username);
            String email = firstNonBlank(
                    userinfo != null ? userinfo.getEmail() : null,
                    (String) oidcUser.getClaims().get("email"),
                    username + "@unknown.local");
            String subject = firstNonBlank(
                    userinfo != null ? userinfo.getSubject() : null,
                    oidcUser.getSubject(),
                    username);
            return new UserDAO(
                    username,
                    fullName,
                    email,
                    subject);
        }

        // API client flow (token-based): JWT bearer.
        Jwt jwt = null;
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            jwt = jwtAuth.getToken();
        } else if (principal instanceof Jwt pJwt) {
            jwt = pJwt;
        }

        if (jwt != null) {
            String username = firstNonBlank(
                    jwt.getClaimAsString("preferred_username"),
                    jwt.getClaimAsString("username"),
                    jwt.getSubject());
            String fullName = firstNonBlank(
                    jwt.getClaimAsString("name"),
                    jwt.getClaimAsString("given_name"));
            String email = firstNonBlank(jwt.getClaimAsString("email"), username + "@unknown.local");
            String subject = firstNonBlank(jwt.getSubject(), username);
            return new UserDAO(username, fullName, email, subject);
        }

        // Fallback: keep behavior explicit rather than ClassCastException.
        String fallbackName = authentication != null ? authentication.getName() : "unknown";
        return new UserDAO(fallbackName, fallbackName, fallbackName + "@unknown.local", fallbackName);
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v != null && !v.trim().isEmpty()) {
                return v;
            }
        }
        return null;
    }
}
