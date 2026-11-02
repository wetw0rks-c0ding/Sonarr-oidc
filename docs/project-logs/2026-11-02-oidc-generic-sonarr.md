# 2026-11-02 — Sonarr OIDC-generic (Authentik-specific code removed)

Branch: `feature/oidc-app-auth`
Scope: commits `0efe279814` → `73704b836b` (8 commits).

## What changed
- `0efe279814` — `OidcRoleMappings` config field (AuthOptions/ConfigFileProvider/HostConfigResource + validator).
- `1d785a45c7` — `OidcGroupMapping.Resolve(groups, mappings)` mapping-aware, highest-wins, malformed ignored.
- `7be947de09` / `0af3be2245` — rename `AuthentikTokenValidationService` → `OidcTokenValidationService` (class + interface + DI + controller; fixtures reverted to HEAD in the second commit).
- `746411446a` — adopt OIDC fixtures + mapping-driven `OidcGroupMapping` cases.
- `730017e275` — fixture fixes: temp key-file setup, controller mock wiring, JWKS rotation case, Mocker-registered config.
- `0453375dd6` — runtime hardening C1-C4: `MapInboundClaims=false`, no throw (invalid token → failure), in-call JWKS refresh+retry, single assignment path; fixtures updated.
- `73704b836b` — pure `git mv` of the service file to its correct name.

## Verification
- Build: `dotnet build src/Sonarr.sln -c Debug -p:Platform=Posix` → 0 warnings, 0 errors.
- Fixtures: 37/37 passed (9 token validation, 9 controller, 19 group mapping). 3 `UpsertOidcUser` failures remain pre-existing (order-dependent flake, proven on base `f99f2ece7b`).
- Full `Sonarr.Http.Test`: 118 tests, 15 failures, all pre-existing (`AuthenticationServiceFixture` warn-count assertions), none in changed fixtures.

## Deferred minors (final review to triage)
- StyleCop `HostConfigController.cs:113` note (re-reviewer flagged; unrelated to Task 1 diff).
- Wrong-key-material signature test missing (only unknown-kid path exercised).
- Negative refresh-gating test missing (no assertion that expiry/issuer/audience do not call `RequestRefresh`).
- Debug-only failure logging in `OidcTokenValidationService`; consider Warning for non-validation exceptions.
- Doc nit: comment at `:31` cites "JWT-bearer path" but only the OIDC handler sets `MapInboundClaims=false`.

## Backward-compat config recipe
Set `OidcAuthority=https://auth.piracyhub.win/application/o/arrstack/` (exact string including trailing slash), `OidcClientId=arrstack`, `OidcRoleMappings=homies=ReadOnly;family=AddSearch;maintenance=Manage;authentik Admins=Admin`. Current deployment behaves identically.
