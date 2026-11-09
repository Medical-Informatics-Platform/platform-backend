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
- DPoP for the laptop client: with `KEYCLOAK_CLI_REQUIRE_DPOP` on, the laptop client's (`mip-cli-<federation>`) tokens must be DPoP-bound (RFC 9449) and arrive with the `DPoP` scheme, and Spring verifies the DPoP proof (signature, `htu`/`htm`, `ath` — the SHA-256 of the access token, `iat`, replay and the token's `cnf.jkt` against the proof's key). Platform-client tokens (portal, notebooks) keep working over `Bearer`; remove the flag once every federation has switched. The proof's `htu` is the request URL, so nginx must pass `X-Forwarded-Proto`/`X-Forwarded-Host` for the backend location.
- Turn-on order: while the flag is off, a DPoP-bound token sent with `Bearer` is accepted without a proof (the binding is not enforced). With the flag on before clients send DPoP, every laptop user fails. Turn on Keycloak DPoP for the laptop client, this flag, and a DPoP-capable mip client release in one change window.
- The proof replay check keeps recent `jti` values in memory, per backend replica: with more than one replica, a proof can be replayed on another replica within the short `iat` window (it stays bound to one method and URL). Acceptable for now; use a shared cache if it matters later.
- JupyterHub login cookies expired on portal sign-out are marked Secure when the request is HTTPS (`COOKIE_SECURE`, default true, including `X-Forwarded-Proto`). Set `COOKIE_SECURE=false` for a portal served over plain HTTP, so those cookies can still be cleared.

## Not available

- Administrators cannot end one portal session from an interface. To remove someone at once, disable the user in Keycloak and then use *Sign out* on that user; this needs back-channel logout. Restarting the backend ends all.
- Users cannot list their portal sessions. The Keycloak account console lists its own sessions.
