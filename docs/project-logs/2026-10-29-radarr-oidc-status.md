# 2026-10-29 — Radarr OIDC Status (for the per-service port)

## Short answer
Radarr upstream `develop` already has the **OIDC authN base** (pulled from
Sonarr via the `sonarr-pull` bot). It has **none** of this fork's authZ /
app-auth work. The port is: replay fork-only commits onto Radarr's existing
OIDC base.

## Evidence (via `gh` API, 2026-10-29)
- `Radarr/Radarr` issue #7047 "LDAP and SSO Support" — still OPEN
  (`Status: Maybe One Day`). No native SSO commitment upstream.
- Issue #11974 "Pull Sonarr commit 'Remember Me for OIDC login'" — CLOSED
  2026-10-25. The sonarr-pull automation is actively porting Sonarr's OIDC
  commits (which is where our base `9f0cb928` + `465b5192` came from).
- `src/Radarr.Http/Authentication/` on `develop` contains:
  `OidcOptionsChangeTokenSource.cs` + OIDC wiring in
  `AuthenticationBuilderExtensions.cs` / `AuthenticationController.cs`.
  Code search for `Oidc` in `Radarr/Radarr`: **37 hits**.
- Code search for `OidcGroupMapping`: **0 hits**.
- Code search for `oidc/exchange`: **0 hits**.
- Repo search for independent `radarr oidc` projects: empty. Top forks
  (Bonarr, Animarr, Comarr2, …) show no OIDC signal.

## Port plan (when ready)
Our fork-only stack, in order, onto Radarr `develop`:
1. `SonarrRole` → `RadarrRole`, `OidcGroupMapping` (group names identical —
   Authentik side unchanged), `OidcGroupsClaim` config.
2. `User` extension + migration (check Radarr's latest migration number;
   ours is 238/239 in Sonarr's sequence — Radarr's will differ).
3. `UpsertOidcUser` (note: server-agent C5 removed username auto-link —
   port the no-link version).
4. `OnTokenValidated` callback authZ + `sonarr_role`-equivalent claim
   (namespaced per app, e.g. `radarr_role`), PKCE/offline_access already
   upstream.
5. `PermissionRequirement`/`RequiresPermission` + policy provider
   (adapt scheme names; Radarr's `AddAppAuthentication` mirrors Sonarr's).
6. RBAC annotations per Radarr's controllers (fresh inventory — route names
   differ from Sonarr's).
7. Service-token minting (`aud=radarr`, `iss=radarr`) + `/api/auth/oidc/exchange`
   + `/api/auth/me` (shapes identical, aud differs).
8. Authentik provider `.../o/radarr/` + `aud=radarr` (server-agent pattern).

## Watch-outs
- Radarr's OIDC base will keep moving via sonarr-pull; rebase the port
  before starting, and expect the callback/policy files to have drifted.
- Verify Radarr's `AuthenticationType` enum + `EffectiveAuthenticationMethod`
  equivalents before porting the policy provider.
- Upstream will never take the hardcoded Authentik bits — keep the port as
  fork patches, same as here.
