# OIDC Group Authorization + Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add group-based authorization (Authentik groups → Sonarr roles) plus security hardening on top of the existing OIDC authentication, while preserving X-Api-Key auth for automation.

**Architecture:** Extend `User` with `OidcSubject`/`OidcGroups`/`Role`; add a hardcoded group→tier mapper; move callback authorization into `OnTokenValidated` with JIT user provisioning; introduce a `PermissionRequirement`/`RequiresPermission` attribute and update `UiAuthorizationPolicyProvider` to enforce role hierarchy; harden OIDC options (PKCE, refresh-token rotation, backchannel logout, JWKS refresh). Forms/External/None users default to Admin (no behavior change).

**Tech Stack:** .NET 10 / ASP.NET Core 10, OpenIdConnect middleware, FluentMigrator, NUnit, StyleCop (TreatWarningsAsErrors).

**Spec:** `docs/...` (see `/home/missioncontrol/.opencode/plan/oidc-group-authorization-spec.md`)

## Global Constraints
- SDK: build from `/tmp` with `/home/missioncontrol/.dotnet/dotnet` (SDK 10.0.400) against `src/Sonarr.sln` to bypass `global.json` pin (10.0.403).
- StyleCop: usings outside namespace; `TreatWarningsAsErrors=true`; no warnings.
- Migrations numbered sequentially after 237 (`238_...`).
- Do not break X-Api-Key auth (`ApiKeyAuthenticationHandler`, SignalR handler) — verify every Task 11-12 build with `curl -H X-Api-Key:` still 200 on a protected route.
- Forms users default `Role = Admin`.

## Review Focus
- A user in multiple groups must get the **highest** tier, not the first match.
- A user with no allowed group must be rejected at callback with `?ssoFailed=insufficient_group`, not granted access.
- An OIDC subject must not be reusable across two User rows (filtered unique index).
- Refresh-token rotation must not grow the cookie past 4KB; fall back to re-login if it does.
- X-Api-Key requests must never be subjected to OIDC role checks.

---

### Task 1: `SonarrRole` enum

**Files:**
- Create: `src/NzbDrone.Core/Authentication/SonarrRole.cs`
- Test: `src/NzbDrone.Core.Test/Authentication/SonarrRoleFixture.cs`

**Interfaces:**
- Produces: `enum SonarrRole { ReadOnly=0, AddSearch=1, Manage=2, Admin=3 }`

- [ ] **Step 1: Write failing test** asserting enum values and ordering (`ReadOnly < AddSearch < Manage < Admin`).
- [ ] **Step 2: Run test** → FAIL (type not defined).
- [ ] **Step 3: Implement enum** in file above.
- [ ] **Step 4: Run test** → PASS.
- [ ] **Step 5: Commit** `feat(auth): add SonarrRole enum for OIDC authorization`.

### Task 2: `OidcGroupMapping`

**Files:**
- Create: `src/Sonarr.Http/Authentication/OidcGroupMapping.cs`
- Test: `src/Sonarr.Http.Test/Authentication/OidcGroupMappingFixture.cs`

**Interfaces:**
- Consumes: `SonarrRole`
- Produces: `static class OidcGroupMapping { static Dictionary<string,string> GroupToTier; static SonarrRole? Resolve(IEnumerable<string> groups); }`

- [ ] **Step 1: Write failing tests** covering: each tier maps correctly; highest-tier-wins for multiple groups; `pirates`-only returns null; empty returns null; case-insensitive matching; unknown groups ignored.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** with hardcoded map (`pirates→T1`, `homies→T2`, `family→T3`, `maintenance→T4`, `authentik Admins→T5`). `Resolve` returns null if no T2–T5 group present.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(auth): add hardcoded OidcGroupMapping`.

### Task 3: Config `OidcGroupsClaim`

**Note:** Verify `HostConfigResource`/`GeneralSettingsResource` mapping — if Task 3 builds but settings don't persist via API, add the property there too (same pattern as `OidcAuthority`).

**Files:**
- Modify: `src/NzbDrone.Common/Options/AuthOptions.cs` (add `OidcGroupsClaim` property)
- Modify: `src/NzbDrone.Core/Configuration/ConfigFileProvider.cs` interface + impl (add `OidcGroupsClaim` property, default `groups`)
- Modify: `src/Sonarr.Http/Authentication/OidcOptionsChangeTokenSource.cs` (`GetSettings` include new value)

- [ ] **Step 1: Add property** to `AuthOptions`.
- [ ] **Step 2: Add to interface** `IConfigFileProvider`.
- [ ] **Step 3: Add impl** `public string OidcGroupsClaim => _authOptions.OidcGroupsClaim ?? GetValue("OidcGroupsClaim", "groups", persist: false);`
- [ ] **Step 4: Update change-token source** to include `_configFileProvider.OidcGroupsClaim`.
- [ ] **Step 5: Build** → 0 errors.
- [ ] **Step 6: Commit** `feat(config): add OidcGroupsClaim option`.

### Task 4: `User` model extension

**Files:**
- Modify: `src/NzbDrone.Core/Authentication/User.cs`

**Interfaces:**
- Produces: `User.OidcSubject`, `User.OidcGroups`, `User.Role` (default `Admin`).

- [ ] **Step 1: Add properties** `string OidcSubject`, `string OidcGroups`, `SonarrRole Role { get; set; } = SonarrRole.Admin;`.
- [ ] **Step 2: Make `Password`/`Salt` nullable** (for OIDC users) — change to `string?`.
- [ ] **Step 3: Build** → 0 errors.
- [ ] **Step 4: Commit** `feat(auth): extend User model with OIDC subject/groups/role`.

### Task 5: Migration 238

**Files:**
- Create: `src/NzbDrone.Core/Datastore/Migration/238_oidc_user_role_and_subject.cs`

- [ ] **Step 1: Write migration** following `NzbDroneMigrationBase` pattern: add columns `OidcSubject` (string, nullable), `OidcGroups` (string, nullable), `Role` (int, not null, default 3). Backfill `Role = 3` for existing rows. Add filtered unique index `IX_Users_OidcSubject` on `OidcSubject` where not null — use raw SQL `CREATE UNIQUE INDEX ... WHERE "OidcSubject" IS NOT NULL` for SQLite compat (FluentMigrator `Create.Index().Where()` not portable).
- [ ] **Step 2: Build** → 0 errors.
- [ ] **Step 3: Commit** `feat(db): migration 238 add OIDC subject/groups/role to Users`.

### Task 6: `IUserService.UpsertOidcUser`

**Files:**
- Modify: `src/NzbDrone.Core/Authentication/UserService.cs` (interface + impl)

**Interfaces:**
- Consumes: `User`, `SonarrRole`
- Produces: `User UpsertOidcUser(string subject, string username, string groups, SonarrRole role)`

- [ ] **Step 1: Add to interface.**
- [ ] **Step 2: Implement**: lookup by `OidcSubject`; if found, update role/groups/username. If not found, try lookup by `NormalizedUsername` (case-insensitive) with null subject → attach subject (forms→OIDC migration, one-time, requires `email_verified` or username match + no existing subject). Else insert new User with `Password=null`, subject, groups, role.
- [ ] **Step 3: Add repository support** if needed (`IUserRepository.FindBySubject`, `FindByUsername`).
- [ ] **Step 4: Build** → 0 errors.
- [ ] **Step 5: Commit** `feat(auth): add UpsertOidcUser to IUserService`.

### Task 7: Callback authorization in `OnTokenValidated`

**Files:**
- Modify: `src/Sonarr.Http/Authentication/AuthenticationBuilderExtensions.cs` (`AddOidc`)

**Interfaces:**
- Consumes: `IConfigFileProvider`, `IUserService`, `OidcGroupMapping`
- Produces: role claim on principal + cookie; JIT user row.

- [ ] **Step 1: Register `IUserService`** in the `OnTokenValidated` handler (resolve from `context.HttpContext.RequestServices`).
- [ ] **Step 2: Read groups claim** using configured `oidcGroupsClaim` from id_token, falling back to userinfo. Normalize `string`/`string[]`/space-separated.
- [ ] **Step 3: Resolve role** via `OidcGroupMapping.Resolve`. If null → `context.Fail` + set redirect `/login?ssoFailed=insufficient_group` via `HandleResponse`.
- [ ] **Step 4: `TryAuthorize(..., role)`** adding `role` + `groups` claims; call `UpsertOidcUser`.
- [ ] **Step 5: Move from `OnUserInformationReceived`** to `OnTokenValidated` (remove old handler or keep as no-op).
- [ ] **Step 6: Build** → 0 errors.
- [ ] **Step 7: Commit** `feat(auth): authorize OIDC users by group claim with JIT provisioning`.

### Task 8: PKCE + scopes

**Files:**
- Modify: `src/Sonarr.Http/Authentication/AuthenticationBuilderExtensions.cs`

- [ ] **Step 1: Set `options.UsePkce = true`.**
- [ ] **Step 2: Ensure `offline_access` in scopes** (add to default `OidcScopes`? or append in builder if missing).
- [ ] **Step 3: Build** → 0 errors.
- [ ] **Step 4: Commit** `feat(auth): enable PKCE and offline_access for OIDC`.

### Task 9: `PermissionRequirement` + handler

**Files:**
- Create: `src/Sonarr.Http/Authentication/PermissionRequirement.cs`
- Create: `src/Sonarr.Http/Authentication/PermissionAuthorizationHandler.cs`

**Interfaces:**
- Produces: `class PermissionRequirement : IAuthorizationRequirement { SonarrRole Minimum; }`, `class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>`.

- [ ] **Step 1: Write failing tests** for handler: principal role >= minimum succeeds; lower fails; non-OIDC (no role claim) treated as Admin succeeds.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** handler reading `role` claim, defaulting to Admin when absent. Handler must return success immediately if `context.User` has no `role` claim but request was authenticated via `ApiKeyAuthenticationHandler` (check `AuthenticationMethod` claim or absence of `oidc_sub`).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(auth): add PermissionRequirement authorization handler`.

### Task 10: `RequiresPermission` attribute

**Files:**
- Create: `src/Sonarr.Http/Authentication/RequiresPermissionAttribute.cs`

**Interfaces:**
- Produces: `[RequiresPermission(SonarrRole)]` attribute implementing `IAuthorizeData` with `Policy = "UI.<role>"`.

- [ ] **Step 1: Implement attribute** mapping role to policy name string.
- [ ] **Step 2: Build** → 0 errors.
- [ ] **Step 3: Commit** `feat(auth): add RequiresPermission attribute`.

### Task 11: `UiAuthorizationPolicyProvider` update

**Files:**
- Modify: `src/Sonarr.Http/Authentication/UiAuthorizationPolicyProvider.cs`

- [ ] **Step 1: Register permission policies** `UI.Read/Add/Manage/Admin` using `PermissionRequirement`.
- [ ] **Step 2: Keep "UI" policy** building as before (anonymous-allow gate), add requirement.
- [ ] **Step 3: Build** → 0 errors.
- [ ] **Step 4: Commit** `feat(auth): register permission policies in UiAuthorizationPolicyProvider`.

### Task 12: Apply `RequiresPermission` to controllers

**Files:**
- Modify: `src/Sonarr.Api.V3/*Controller.cs` and `src/Sonarr.Api.V5/*Controller.cs` (coarse buckets per spec §7).

**Pre-step:** Inventory every controller's verb: `grep -l "Authorize"` + `grep Controller`. Classify GET vs mutating. Confirm with maintainer that `ui.read` bucket is not too permissive for `AddSearch` data.

- [ ] **Step 1: Annotate read controllers** with `[RequiresPermission(SonarrRole.ReadOnly)]`.
- [ ] **Step 2: Annotate add/search/import** with `[RequiresPermission(SonarrRole.AddSearch)]`.
- [ ] **Step 3: Annotate manage endpoints** (queue, profiles, indexers, notifications) with `[RequiresPermission(SonarrRole.Manage)]`.
- [ ] **Step 4: Annotate settings/users/config/system/backup** with `[RequiresPermission(SonarrRole.Admin)]`.
- [ ] **Step 5: Build** → 0 errors.
- [ ] **Step 6: Commit** `feat(auth): enforce permission policies on API controllers`.

### Task 13: Refresh-token rotation middleware

**Files:**
- Modify: `src/Sonarr.Http/Authentication/AuthenticationBuilderExtensions.cs` (cookie `OnValidatePrincipal`)

- [ ] **Step 1: In cookie `OnValidatePrincipal`,** when access token expires within 5 min, redeem refresh token via backchannel `TokenEndpoint`, update tokens in `Properties`, set `context.ShouldRenew = true` and `ReplacePrincipal` if new principal. Rotate refresh token if returned.
- [ ] **Step 2: Guard cookie size** (<4KB); if exceeded, clear refresh token and let session expire.
- [ ] **Step 3: Build** → 0 errors.
- [ ] **Step 4: Commit** `feat(auth): rotate OIDC refresh tokens in cookie validation`.

### Task 14: Backchannel logout endpoint

**Files:**
- Modify: `src/Sonarr.Http/Authentication/AuthenticationController.cs`

- [ ] **Step 1: Add `POST logout/backchannel`** action accepting `logout_token`, validating signature + `events` claim, clearing local cookie, returning 200.
- [ ] **Step 2: Build** → 0 errors.
- [ ] **Step 3: Commit** `feat(auth): add OIDC backchannel logout endpoint`.

### Task 15: JWKS refresh + `OnRemoteFailure` redaction

**Files:**
- Modify: `src/Sonarr.Http/Authentication/AuthenticationBuilderExtensions.cs`

- [ ] **Step 1: Set `options.RefreshInterval = TimeSpan.FromHours(24)`.**
- [ ] **Step 2: In `OnRemoteFailure`,** force metadata refresh (reset `ConfigurationManager`) and redact exception details from redirect (use `?ssoFailed=true`).
- [ ] **Step 3: Build** → 0 errors.
- [ ] **Step 4: Commit** `feat(auth): configure JWKS refresh and redact remote failures`.

### Task 16: State/nonce cookie hardening

**Files:**
- Modify: `src/Sonarr.Http/Authentication/AuthenticationBuilderExtensions.cs`

- [ ] **Step 1: Set `CorrelationCookie`/`NonceCookie` expiration 15 min, SameSite=Lax, HttpOnly.**
- [ ] **Step 2: Build** → 0 errors.
- [ ] **Step 3: Commit** `feat(auth): harden OIDC state/nonce cookies`.

### Task 17: Unit tests for group mapping + callback + policy handler

**Files:**
- Create/Modify test files under `src/Sonarr.Http.Test/Authentication/` and `src/NzbDrone.Core.Test/Authentication/`.

- [ ] **Step 1: OidcGroupMappingFixture** — all tiers, highest-tier-wins, reject, normalization, case-insensitivity.
- [ ] **Step 2: Callback authorization tests** — reject non-allowed → `insufficient_group`; provision user; role claim present.
- [ ] **Step 3: PermissionAuthorizationHandlerFixture** — role hierarchy; default Admin.
- [ ] **Step 4: Run all** → PASS.
- [ ] **Step 5: Commit** `test(auth): cover group mapping, callback, permission handler`.

### Task 18: Final build + review

- [ ] **Step 1: Build solution** from /tmp → 0 errors, 0 warnings.
- [ ] **Step 2: Run affected test projects** (Core.Test, Http.Test) → PASS.
- [ ] **Step 3: Commit** any fixups.

---

**Execution recommendation:** Subagent-driven, because tasks have tight interface dependencies (especially Tasks 6→7→9→11) and a shipped authorization mistake would grant unintended access.
