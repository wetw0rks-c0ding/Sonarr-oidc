# 2026-10-28 — OIDC Callback Authorization, RBAC Infra, Session Hardening

Branch: `feature/oidc-app-auth`. Continues the foundation log.

## Changes (in commit order)

1. **Callback authorization in `OnTokenValidated`** (`e3c95f2634`)
   - `AuthenticationBuilderExtensions.AddOidc`: moved authZ from
     `OnUserInformationReceived` to `OnTokenValidated` (refresh tokens
     available there). Reads groups claim (configurable name, id_token
     primary / userinfo fallback, normalizes string/string[]/space-separated
     via shared `GetGroups`), resolves role, rejects non-allowed users with
     redirect `/login?ssoFailed=insufficient_group`, JIT-provisions via
     `UpsertOidcUser`, stamps `role`+`groups` claims.
   - X-Api-Key path untouched (never hits this handler).

2. **PKCE + `offline_access`** (`a24f2dea3a`)
   - `options.UsePkce = true`; `offline_access` appended when missing.

3. **`RequiresPermission` attribute** (`eb268a81b2`)
   - New `RequiresPermissionAttribute : AuthorizeAttribute` mapping
     `SonarrRole` → `UI.Read/Add/Manage/Admin` policies.

4. **`PermissionRequirement` + handler** (`d79d542ca6`)
   - New `PermissionRequirement(SonarrRole Minimum)` +
     `PermissionAuthorizationHandler` (role >= minimum succeeds;
     no role/oidc_sub claim = API-key path bypass).

5. **Policy registration** (`b1143540ed`)
   - `UiAuthorizationPolicyProvider` serves `UI.Read/Add/Manage/Admin`;
     handler registered in `AddAppAuthentication`.

6. **RBAC phase 1 — Admin-gated controllers** (`9e1bd6b277`)
   - 14 Admin controllers annotated (V3 Config/*, V3/V5 System/*, V5
     GeneralSettings). Inventory: `docs/superpowers/plans/controller-inventory.md`.
   - Coarse Read/Add/Manage rollout explicitly deferred (see 2026-10-29 log).

7. **Refresh-token rotation** (`c2cb46e0c1`)
   - Cookie `OnValidatePrincipal` redeems near-expiry access tokens via
     backchannel token endpoint, rotates refresh token, `<4KB` guard.

8. **Backchannel logout** (`4f9216334e`)
   - `POST /logout/backchannel` validates `logout_token` claims
     (events/sub/sid), clears local cookie, returns 204.

9. **JWKS refresh + redacted failures** (`2fc030714e`)
   - `RefreshInterval = 24h`, force metadata refresh on signature failure,
     generic `?ssoFailed=true` redirect (no exception details).

10. **State/nonce hardening** (`9322a72c79`)
    - Correlation/nonce cookies: HttpOnly, SecurePolicy.Always, 15-min expiry.

11. **Test expansion** (`883ddc0553`)
    - Group-mapping, permission-handler, UpsertOidcUser coverage
      (36 tests green).

## Verification
- Solution build 0 errors; 10 Core + 28 Http auth tests pass.
- OCR pre-pass on early commits: 7 comments, disposed (nits rejected,
  gaps folded into tests).
