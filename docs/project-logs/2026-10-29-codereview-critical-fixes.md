# 2026-10-29 — CodeRabbit Review Findings Fix Pass (C1–C4 + follow-ups)

Branch: `feature/oidc-app-auth`. Full-diff CodeRabbit review returned
14 findings (2 critical, 10 major, 2 minor); all fixed or dispositioned.
Senior-reviewer subagent review: 4 Critical (C1–C4) + 11 Important.
This log covers the Critical fixes.

## C1 — Permission policies dropped the API-key fallback (`a735a79009`)
- Anonymous requests to `[RequiresPermission]` controllers returned 200 with
  Admin rights: fallback policy (`RequireAuthenticatedUser` on "API" scheme)
  only applies when no `IAuthorizeData` is present; the attribute removed it
  and the handler treated anonymous as the API-key path.
- Fix: `UiAuthorizationPolicyProvider` permission policies now
  `.RequireAuthenticatedUser()` + schemes Cookies/API/Forms(/Bearer later);
  `PermissionAuthorizationHandler` bypasses only for *authenticated*
  principals without oidc_sub/role. Unauthenticated → 401.
- Fixture asserts headerless requests fail.

## C3 — Duplicate `GetConfig` descriptor, over-broad Admin (`ccb0f61158`)
- `UiConfigController.GetConfig()` used `new` over non-virtual base →
  `AmbiguousMatchException` → HTTP 500 on `/api/v3/config/ui` (breaks UI boot).
- Fix: base `ConfigController.GetConfig()` made `virtual`, override used.
  Class-level Admin moved to mutating actions; `GetStatus`/`config/ui` GET
  scoped ReadOnly (V3 + V5 System, V3 UiConfig).

## C2 — `Users.Password` still NOT NULL (`75dc847753`)
- `UpsertOidcUser` inserts `Password = null` → constraint violation for every
  second OIDC user; migration 238 didn't touch nullability.
- Fix: migration `239_oidc_password_nullable.cs` drops NOT NULL on
  `Password`/`Salt` (`NzbDroneSQLiteProcessor` rebuilds the table; verified
  override at `NzbDroneSqliteProcessor.cs:32`).

## C4 — Service token authenticated nothing (`4b42d6459f`)
- No Bearer scheme registered; `role` claim consumed nowhere.
- Fix: `.AddJwtBearer("Bearer", …)` (`Microsoft.AspNetCore.Authentication.JwtBearer
  10.0.403` added to `Sonarr.Http.csproj`), iss/aud=`sonarr`, HS256 key,
  2-min skew, maps `sub`→`oidc_sub`, `role`→`sonarr_role`; "Bearer" added to
  UI.* policy schemes.

## Follow-up review rounds
- `b302bd71c9`: reflection-based key lookup replaced with compile-time
  `ISonarrServiceTokenService.SigningKey`; None/External scheme added to
  UI.* policies.
- `07cf1a3e2c`: scheme whitelist guard — only registered schemes
  (Cookies/API/Forms/Bearer/None/External/Oidc) are added; unreachable
  names (e.g. obsolete `Basic`) can no longer break the PolicyEvaluator.
- `eb19a99ac3` (preceded C1–C4): strip provider-supplied `sonarr_role`
  before `AddIdentity`; redact `UpsertOidcUser` errors to fixed message.

## Rejected with reason (no code change)
- Hardcoded Authentik issuer + substring audience, hardcoded group map:
  spec-mandated for the pilot.
- Backchannel revocation store: spec non-goal ("do not touch").
- Dead-code/duplicate-constant minors: left (harmless, noted).

## Verification
- Build 0 errors/0 warnings; targeted suites green
  (11 Api.Test + 37 Http.Test on final guard).
- `~Authentication` filter: 15–17 failures, verified IDENTICAL on clean
  `develop` (pre-existing log-assertion tests); the one extra branch failure
  passes in isolation (order-dependent flake).
- CodeRabbit re-review of fixes: 2 → fixed; final guard commit pending
  re-review (quota exhausted, 23-min cooldown at push time).
- `global.json` SDK downgrade (10.0.403→10.0.400) by a worker agent:
  REVERTED, not pushed.
