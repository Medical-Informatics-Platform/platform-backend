# Session Management

What ASVS 5 V7.1 asks to document. Values are defaults in `application.yml`; operators can override them.

## Timeouts

| Session | Idle | Maximum | Set by |
|---|---|---|---|
| Portal (`JSESSIONID`) | 30 minutes (`SESSION_IDLE_TIMEOUT`) | 8 hours (`SESSION_MAX_AGE`) | This backend |
| Bearer access token | None | About 5 minutes | Keycloak realm |
| Laptop sign-in (offline refresh token) | 30 days | 180 days | Keycloak client `mip-cli-<federation>` |
| Keycloak SSO | Realm setting | Realm setting | EBRAINS |
| JupyterHub | Not set here | Not set here | JupyterHub defaults |

Why these values: MIP handles research data, not transactions, and analyses run for a working day. 8 hours bounds how long roles taken at login stay in effect. Because Keycloak SSO usually survives, an ended portal session normally signs in again without a password. MFA and NIST 800-63B re-authentication rules depend on EBRAINS; Unknown / TODO: verify with its operators.

## Concurrent sessions

Not limited. One account may hold several portal sessions, laptop sign-ins and a hub session. Reaching a limit therefore has no behaviour to describe.

## How the systems end sessions

| Event | Portal | Bearer tokens | Laptop sign-in | JupyterHub |
|---|---|---|---|---|
| Portal sign-out | Ended here and at Keycloak | Expire within minutes | Not affected | Its login cookies are expired on sign-out; a notebook server's own cookie lasts until the next token refresh, which is refused |
| Keycloak ends the session, or an admin uses *Sign out* on the user | All the user's portal sessions end by back-channel logout, if configured below | Expire within minutes | Refused at next renewal | Refused at next token refresh |
| Keycloak disables the user, without *Sign out* | Continues until a timeout (at most 8 hours): Keycloak sends no logout | Refused at next renewal | Refused at next renewal | Refused at next token refresh |
| `mip logout` | Not affected | Expire within minutes | Revoked | Not affected |
| Role removed in Keycloak | At next login, at most 8 hours | Within minutes | At next renewal | At next token refresh |

## Operator setup

- Back-channel logout needs the platform client's *Backchannel Logout URL* set to `https://<publicHost>/services/logout/connect/back-channel/keycloak`. Without it, a signed-out user's portal session lasts until one of the timeouts above.
- The back-channel session registry is in memory: this works with one backend replica.
- Any back-channel logout ends all of that user's portal sessions: Keycloak's user logout names only one session.
- Set `KEYCLOAK_REQUIRED_AUDIENCE` once all of a federation's clients issue tokens naming it in `aud`. Empty means `aud` is not checked; `azp` always is.

## Not available

- Administrators cannot end one portal session from an interface. To remove someone at once, disable the user in Keycloak and then use *Sign out* on that user; this needs back-channel logout. Restarting the backend ends all.
- Users cannot list their portal sessions. The Keycloak account console lists its own sessions.
