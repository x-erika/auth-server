# auth-server

OAuth 2.0 + OpenID Connect authorization server, built on Actix-web (Rust 2024 edition).

Implements the six core auth primitives: **OAuth2, OIDC, JWT, PKCE, RBAC, SSO** — runnable end-to-end with admin bootstrap, browser-based login, and a companion Next.js admin UI ([`auth-admin-but-java`](https://github.com/x-erika/auth-admin-but-java)). Backed by Postgres (durable state) + Redis (transient artifacts, hot-path cache, rate-limit counters).

## Quick start

Point at a Postgres instance and a Redis instance (override via `DATABASE_URL` / `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASS`). In production also set `AUTH_TOKEN_HMAC_KEY` to a long random string — it keys the HMAC-SHA256 hash applied to refresh / password-reset / email-verification tokens at rest. Then:

```bash
cargo run
```

On first boot the server runs all sqlx migrations, seeds the `admin` and `user` roles plus a bootstrap admin account, generates an RSA-2048 keypair under `~/.xerika/auth/keys/` (or `%USERPROFILE%\.xerika\auth\keys\` on Windows), and starts listening on [`http://localhost:8080`](http://localhost:8080) with `/login` as the browser entry point.

Readiness: the server emits a `starting service ... listening` tracing log when `actix-web` is bound — there is no separate `/health` endpoint yet.

## Documentation

| File | Contents |
|---|---|
| `migrations/` | sqlx migrations (`0001` schema → `0008`: device codes, role hierarchy, consent, logout URIs, claims request; `0009`: drop tables now backed by Redis; `0010`: password_resets table) |
| `src/` | Self-contained feature packages — see [Architecture](#architecture) |

## Feature coverage

| Feature | What's implemented |
|---|---|
| **OAuth 2.0** | authorization_code, refresh_token (rotation + reuse-detection family revoke per OAuth 2.0 Security BCP §4.13), client_credentials, device_code (RFC 8628), revoke (RFC 7009, returns 200), introspect (RFC 7662, response bound to caller's `aud`) |
| **OIDC** | id_token (with `sid` for back/front-channel logout + bound to active session at /userinfo), /userinfo (rejects tokens without `typ: at+jwt`, RFC 9068 §4), discovery doc, JWKS, RP-initiated logout (`post_logout_redirect_uri` validated against client's registered URIs, accepts expired `id_token_hint` per RP-Initiated Logout 1.0 §3), nonce, auth_time, prompt (with re-auth grace window so prompt=login doesn't loop), max_age, consent screen, claims parameter |
| **JWT** | RS256 with persistent RSA keypair, full claims (iss/sub/aud/exp/iat/jti/typ/...), `typ: at+jwt` on access tokens (RFC 9068), strict validation (`alg` locked to RS256, `iss`+`exp` required, strict `kid` lookup — unknown kid rejected, optional `aud` enforcement via overload), `kid` header, multi-key rotation with atomic write (`tmp` + rename) and POSIX 600 on private keys (Unix); `DELETE /admin/keys/{kid}` retires non-active keys |
| **PKCE** | S256 only (RFC 9700 §2.1.1.1 — `plain` MUST NOT be used). Verified whenever the auth code carries a challenge — not only when `client.pkce_required=true` — so a public client opting in can't be downgraded. Constant-time compare via `subtle::ConstantTimeEq` |
| **RBAC** | Role entity + assignment, role hierarchy (parent_id, cycle-checked at repo level with `SELECT FOR UPDATE` so concurrent admin edits can't race), recursive effective-role resolution, admin role gate via `require_admin()`, roles claim in JWT |
| **SSO** | Shared session (cookie + Bearer, case-insensitive scheme per RFC 6750), browser-redirect OAuth flow with CSRF-protected `/login` POST (double-submit cookie), consent screen, RP-initiated logout, front-channel logout (iframe propagation), back-channel logout (signed logout_token POST), auth_time + sid in tokens |
| **Rate limiting** | Lua-atomic INCR+EXPIRE on `/auth/login` (per email + per IP), `/auth/signup` (per IP), `/auth/verify-email` (per IP), `/oauth/device-authorization` (per client_id). Per-email login bucket resets on successful auth so a user with valid credentials doesn't lock themselves out; per-IP bucket keeps counting up (defends against one IP, many target accounts). Source IP for IP-keyed buckets read from the TCP peer; XFF-trust must be opted into via proxy configuration. Fail-open if Redis is down. Returns 429 with `Retry-After`. |
| **Hardening** | Client secrets Argon2id-hashed at rest (constant-time verify, dual-mode for legacy rows). User passwords Argon2id with OWASP 2024 baseline (`t=3, m=12 MiB, p=1`); per-row params are read back from the credential blob so old hashes still verify. Refresh, password-reset, and email-verify tokens stored as `HMAC-SHA256` (key = `AUTH_TOKEN_HMAC_KEY`) so a DB-only leak still doesn't yield usable tokens. Login timing-equalised against missing/disabled/unverified accounts (always runs Argon2). `/login` `return_to`, `/oauth/logout` `post_logout_redirect_uri`, and admin-added redirect URIs (`javascript:`/`data:`/`file:`/`vbscript:` rejected) validated to block open redirects + XSS. Self-service password change kicks every other session of the user. Email + username normalised to lowercase on write and looked up via `LOWER(...)` so `Alice` / `alice` resolve to the same account. Signup uniqueness check + PG unique constraint translates `23505` to 409 instead of 500. `pg_advisory_xact_lock` serialises bootstrap inserts across replicas. Hourly tokio task sweeps expired refresh tokens (revoked rows kept until natural expiry so reuse-detection still fires). Backchannel logout requests restricted to `http(s)` schemes. Audit log on `POST /admin/keys/rotate` + `DELETE /admin/keys/{kid}`. |

## Standards

### OAuth 2.0 (IETF RFCs)

| RFC | Title | What it covers here |
|---|---|---|
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | The OAuth 2.0 Authorization Framework | Core grants: `authorization_code`, `refresh_token`, `client_credentials` |
| [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) | Bearer Token Usage | `Authorization: Bearer …` header |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE | `code_challenge` / `code_verifier` with S256 (plain rejected per RFC 9700) |
| [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) | Token Revocation | `POST /oauth/revoke` |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | Token Introspection | `POST /oauth/introspect` (response active=false when token's aud ≠ caller's client_id) |
| [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) | Device Authorization Grant | `POST /oauth/device-authorization` + `POST /oauth/device/verify` (user_code case-insensitive + hyphen-tolerant per §6.1, SET-NX retry on collision) |
| [RFC 6585](https://datatracker.ietf.org/doc/html/rfc6585) | Additional HTTP Status Codes | `429 Too Many Requests` + `Retry-After` for rate limits |
| [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) | JWT Profile for OAuth 2.0 Access Tokens | `typ: at+jwt` header + `client_id` claim on access tokens; §4 enforced at `/userinfo` |
| [RFC 9700 (OAuth 2.0 Security BCP)](https://datatracker.ietf.org/doc/html/rfc9700) | Browser-based + native client guidance | Refresh-token rotation with reuse detection (§4.13), PKCE S256-only (§2.1.1.1 — `plain` MUST NOT be used) |

### JWT / JOSE (IETF RFCs)

| RFC | Title | What it covers here |
|---|---|---|
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token (JWT) | Token structure: header.payload.signature |
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | JSON Web Signature (JWS) | Signing wire format, `kid` in header |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) | JSON Web Key (JWK) | JWKS published at `/.well-known/jwks.json` |
| [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) | JSON Web Algorithms (JWA) | `RS256` for id_token/access_token/logout_token |

### OpenID Connect (OpenID Foundation specs)

| Spec | What it covers here |
|---|---|
| [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | `id_token`, `/userinfo`, `nonce`, `auth_time`, `prompt`, `max_age`, `claims` parameter, consent |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` |
| [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | `/oauth/logout` with `id_token_hint` + `post_logout_redirect_uri` |
| [OIDC Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) | iframe-based propagation to registered `frontchannel_logout_uri` |
| [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Signed `logout_token` POST to registered `backchannel_logout_uri` |

### RBAC and SSO

Neither is a single IETF RFC. RBAC implementation follows the formal model from **NIST INCITS 359-2012** (roles with hierarchical inheritance, role-permission assignment, session-role activation). SSO here is a pattern realised through the combination of shared session cookies + the OAuth/OIDC flows above — not a standalone wire protocol.

## Storage layout

Two stores, with a clear split of responsibilities:

| Concern | Postgres (durable) | Redis (volatile / hot) |
|---|---|---|
| Users, credentials, roles, role assignments, consents | Source of truth | — |
| Clients + redirect URIs | Source of truth | Cache-aside (`client:<client_id>`, TTL ~30min ±10% jitter) |
| Sessions | Source of truth | Cache-aside (`session:<sha256(token)>`, TTL = remaining session lifetime) |
| Refresh tokens, email verifications, password resets | Source of truth (HMAC-SHA256 of raw token) | — |
| Authorization codes (single-use, ~10min TTL) | — | Redis-only (`authcode:<sha256(code)>`, Lua GET+DEL atomic consume) |
| Device authorizations + user_code lookup | — | Redis-only Hash with two-key pattern (`device:dc:<deviceCode>` + `device:uc:<userCode>` pointer) |
| Pending consent state | — | Redis-only (`pending:<requestId>`) |
| Rate-limit counters | — | Redis-only (`rl:*`, Lua INCR+EXPIRE) |

Cache-aside writes invalidate Redis only after the Postgres transaction commits, so a concurrent reader cannot populate the cache with pre-commit data. Read-side falls back to Postgres on any Redis exception (fail-open). Session delete DELs Redis first and aborts on failure (fail-closed for logout, prevents post-delete cache hits leaving users authenticated).

## Architecture

Package-by-feature layout under `src/`:

```
admin/          GET/POST/DELETE /admin/* — user/role administration, role hierarchy,
                signing key rotation + retire
bootstrap/      Idempotent startup seeders (admin user, roles + hierarchy, default clients).
                Each acquires `pg_advisory_xact_lock` so multi-replica deploys converge cleanly.
client/         OAuth client entity + repository (cache-aside via ClientSnapshot DTO) + redirect URIs
common/
  crypto/         argon2, hmac_sha256, jwt (JwtSigner + JwtValidator), random_tokens,
                  rsa_keys (multi-key, rotate + retire), sha256
  ratelimit/      RateLimiter (Lua INCR+EXPIRE, fail-open), RateLimitDecision, 429+Retry-After helper
  redis/          keys (namespacing), json (serde_json with naive-datetime), lua (SCRIPT LOAD + EVALSHA
                  with NOSCRIPT fallback)
  web/            bearer (header + cookie token resolution), client_ip
login/          /auth/login (JSON, rate-limited per email + IP) + /login (HTML, Askama) + LoginService
oauth/
  authorize/      AuthorizeFlow, AuthCodeStore (Redis-only, single-use via Lua GET+DEL with
                  sha256(code) key), AuthorizationCode (struct), ClaimsRequest
  consent/        ConsentService, UserConsent, PendingAuthorizationStore (Redis-only), /consent (Askama)
  device/         DeviceFlow, DeviceAuthorization, DeviceAuthorizationRepository
                  (Redis Hash + two-key pattern: deviceCode blob + userCode pointer)
  logout/         LogoutFlow, BackchannelLogoutNotifier (front- + back-channel, http(s)-only)
  pkce/           PkceVerifier (S256 only, constant-time compare)
  token/          TokenFlow, TokenIssuer, RefreshToken, IntrospectFlow, RevokeFlow, cleanup task
  resource.rs     /oauth/* Actix routes (device-authorization rate-limited per client_id)
  scopes.rs       shared parse/subset utility
oidc/           /userinfo, /.well-known/openid-configuration, /.well-known/jwks.json (all active keys)
role/           Role (with parent_id) + RoleRepository (effective-role walk)
session/        UserSession + SessionService (8-hour TTL) + SessionRepository (cache-aside via
                SessionSnapshot DTO; bulk-delete revokes refresh_tokens explicitly before cascade)
signup/         /auth/signup + /auth/verify-email + EmailVerification (both endpoints rate-limited per IP)
user/           User + Credential entities + repositories
```

Each subpackage is self-contained: entity, repository, flow/service, and DTOs all live next to each other, not split by layer.

## Token model

- **Session token** (opaque, 8h) — for browser/admin sessions. Accepted via `Authorization: Bearer` (scheme case-insensitive), `X-Session-Token` header, or `session_token` cookie (HttpOnly, SameSite=Lax, Secure when `AUTH_COOKIE_SECURE=true`). Cached in Redis by `sha256(token)`; Postgres is source of truth.
- **Access token** (JWT RS256, 15min, `typ: at+jwt`) — for resource server APIs. Carries `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, `scope`, `roles`, `sid`, `email`, `username`. `/userinfo` re-validates `sid` against `user_sessions` so admin-revoked sessions kill in-flight access tokens.
- **Refresh token** (opaque, 30 days, HMAC-SHA256-hashed in DB) — rotated on each use. A presented-but-revoked token triggers family revocation: every refresh token bound to that session is invalidated and the session itself is dropped on next request. The hourly cleanup task leaves `revoked=true` rows alone until their natural expiry so the reuse-detection window matches the token TTL.
- **ID token** (JWT RS256, 1h) — OIDC identity assertion, issued only with `openid` scope. Carries `sid` so back-channel / front-channel logout receivers can resolve the session.

JWTs are signed with a persistent RSA-2048 keypair stored at `~/.xerika/auth/keys/`, named `<kid>.private.pem` / `<kid>.public.pem` per key, with `active.kid` selecting the current signing key. `POST /admin/keys/rotate` generates a new keypair and rotates the active kid in place — old kids remain in the JWKS so tokens already in flight continue to verify until they expire. `DELETE /admin/keys/{kid}` retires a non-active key (its PEM files are removed; any JWT still signed by it fails validation immediately). Both routes write an audit log entry naming the admin actor.

## Project status

This is a **learning project** showcasing the core auth primitives. It is **not production-ready**:

- Email verification token + password-reset token are returned in the API response (in production, would be emailed)
- No general-purpose audit log (only key rotation/retire is logged)
- JAR (request object, RFC 9101) not supported — a correct implementation needs either a separate raw-secret column or RS256 against the client's registered JWKS; this server provides neither
- Default bootstrap credentials are committed to the repo (admin@gmail.com / admin123, service-client secret seeded then hashed) — rotate before exposing the server beyond localhost
- Client secrets are stored Argon2id-hashed for new writes; pre-existing plaintext rows still verify via a constant-time fallback until rotated. Admins should rotate any pre-hash-migration secrets via `PUT /admin/clients/{id}` and inspect the startup log for any "plaintext secret" warnings.
- **`AUTH_TOKEN_HMAC_KEY` MUST be set in production** — the default in code is a placeholder; rotating the key invalidates every live refresh / reset / verify token (the intended emergency-rotation behaviour). Set `AUTH_COOKIE_SECURE=true` so the session/CSRF cookies refuse plain HTTP. Behind a load balancer, the server reads source IP from the TCP peer by default; trust upstream `X-Forwarded-For` headers only when terminating TLS at a known proxy.
- POSIX file permissions (0o600 on private key PEMs) only apply on Unix. Windows deployments accept the umask default; protect the keys directory at the ACL/disk level.

---

Built with Rust 2024, Actix-web 4.13, sqlx 0.8 (PostgreSQL), redis 0.27 + deadpool-redis 0.18, jsonwebtoken 9, rsa 0.9, argon2 0.5, hmac 0.12, askama 0.12 (templates), tracing 0.1, prometheus 0.13.
