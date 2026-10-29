# 2026-10-29 — Server-Agent Hardening Verification + Per-Service Token Architecture

## Server-agent hardening (commit `221d53e`, verified in-repo)
Server agents landed three commits on `feature/oidc-app-auth` (same working
tree, author `wetw0rks-c0ding`):

- `221d53e` — remove Forms→OIDC auto-link by username (IdP-controlled
  `preferred_username` takeover risk; Forms/OIDC rows now fully separate);
  issuer/audience derived from `IConfigFileProvider.OidcAuthority/ClientId`
  (`ValidIssuer` exact via `GetIssuer()`, exact audience via
  `GetExpectedAudience()`, fail closed when unconfigured);
  **removed** unverified `BackchannelLogout` (+ `DecodeBase64Url`);
  permission schemes limited to effective scheme + API/Bearer;
  `OidcUserIdentifier` fallback to Admin when groups don't match (single-user
  backwards compat).
- `2a10460` — `docs/project-logs/2026-10-29-sonarr-oidc-verification.md`
  (285 lines: T1 blocked, T2+ roles) + cutover doc.
- `c4c3729` — restore `Issuer` alias for the fixture.

Follow-up by this session (`077fbe4`): 2 StyleCop nits from the hardening
commit (blank lines from backchannel removal, comment spacing). Build is
0 warnings / 0 errors after the fix.

## Cross-checked against server-agent claims — all confirmed in code
- `UserService.cs:173` — no-link insert path, comment cites takeover rationale.
- `AuthentikTokenValidationService.cs:95` — `ValidIssuer`/`ValidAudience`
  exact; substring check only when no clientId configured (tests).
- `UiAuthorizationPolicyProvider.cs:63` — schemes = effective + API/Bearer.
- `AuthenticationController.cs:200` — no backchannel endpoint.
- `OidcGroupMapping.cs:27` — highest-wins resolve; T1 → null → 403.

## Live deployment (server-agent reported, not independently probed)
- `bertha:8989` switched to `oidc` (`PUT /api/v3/config/host` 200, GET
  confirms `oidc`/`seekarr`); image `sonarr-oidc:fix-221d53e` (630 MB);
  `backups/pre-oidc-20261029-081934` (752 MB); migrations 238/239 applied.

## Architecture decision (both agents agree)
- **Sonarr door is `per_provider`**: service token `aud=sonarr`, `iss=sonarr`,
  exact match — ready for Sonarr `code → exchange → 200`.
- **Per-service tokens are Seekarr-side** (Seekarr commit `5d7c8e9`):
  Sonarr mints only `aud=sonarr`. Radarr/Lidarr later reuse the same pattern
  with their own provider (`.../o/radarr/`, `aud=radarr`).
- `password` grant with `testoidc-homie` fails `invalid_grant` on the
  `authorization_flow` (needs `code`, not `password`) — expected; the `code`
  + PKCE flow is the supported path.
