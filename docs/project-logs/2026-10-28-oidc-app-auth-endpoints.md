# 2026-10-28 — OIDC App-Auth Endpoints for Seekarr (`/exchange`, `/me`)

Branch: `feature/oidc-app-auth`.
Spec: `/home/missioncontrol/Nextcloud/vibe-codez/Seekarr/docs/sonarr-oidc-app-auth-spec.md`
(patched during work: rule 4 now requires ≥256-bit signing key, fail closed).

## Goal
Let the Seekarr mobile app authenticate via Authentik and get a short-lived
Sonarr-scoped token + role/permissions, without the app resolving groups.

## Changes (in commit order)

1. **`SonarrServiceTokenService`** (`770a92d70c`)
   - New `src/Sonarr.Http/Authentication/SonarrServiceTokenService.cs`:
     `ISonarrServiceTokenService { MintToken(subject, role), ValidateToken(token) }`
     + `SonarrRolePermissions.ForRole` (ReadOnly→[UI.Read] … Admin→all four).
   - HS256 JWT, `iss`/`aud` = `sonarr`, 5-min TTL, `sub`+`role` claims.
   - Key: `<AppData>/service-token.key`, 32 random bytes Base64 if missing;
     constructor throws if key < 32 bytes (fail closed, →500).
   - Fixture: roundtrip, expiry/audience/tamper rejection, short-key throw.

2. **`AuthentikTokenValidationService`** (`a49d63605b`)
   - New `AuthentikTokenValidationService.cs`: validates Authentik JWTs —
     issuer exact `https://auth.piracyhub.win/application/o/seekarr/`,
     aud must contain `seekarr`, JWKS via `ConfigurationManager` (24h refresh,
     refresh-on-unknown-kid + retry), ±2min clock skew, `sub` required.
   - Groups extracted via shared `AuthenticationBuilderExtensions.GetGroups`
     (no reimplementation). Tokens never logged.
   - Fixture with locally-minted RSA tokens: bad issuer/aud/expiry/missing
     sub fail; key rotation triggers refresh + retry.

3. **Endpoints** (`1968f3eaf6`)
   - `POST /api/auth/oidc/exchange` (in `AuthenticationController`):
     `subject_token` from JSON body (wins) or `Authorization: Bearer`.
     400 missing / 401 `invalid_token` / 403 `insufficient_group` /
     200 `{token, token_type: Bearer, expires_in: 300, role, permissions}`.
     In-memory per-IP rate limit (10/min, 429 on 11th).
   - `GET /api/auth/me`: validates service token (401), looks up user by
     `OidcSubject` (404 if row missing), returns
     `{username, role, groups, permissions}`.
   - Both services registered as singletons in `AddAppAuthentication`.
   - `AuthenticationControllerOidcFixture`: 8/8 pass (all status paths + rate limit).

## Verification
- Build 0 errors; Http.Test OIDC fixtures green.
