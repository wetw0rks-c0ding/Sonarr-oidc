# Task 3b report — runtime hardening for OidcTokenValidationService

Date: 2026-11-02. Branch: `feature/oidc-app-auth`. Base: `730017e275`.
Files changed (2): `src/Sonarr.Http/Authentication/AuthentikTokenValidationService.cs` (contains `OidcTokenValidationService`), `src/Sonarr.Http.Test/Authentication/OidcTokenValidationServiceFixture.cs`.
No other file, no csproj/global.json/infra, no contract/status/message/resolver/group-extraction changes.

## C3 — inbound claim mapping (load-bearing, fixed)

`JwtSecurityTokenHandler` is now constructed as `new() { MapInboundClaims = false }`, matching the
JWT-bearer path at `AuthenticationBuilderExtensions.cs:238`. Raw `sub` / `preferred_username` /
`groups` lookups now work on real tokens; a valid token no longer returns `missing_subject`.

Fixture: removed `DisableInboundClaimMapping` and its `<handler>k__BackingField` reflection seam
(previously lines 100-110) entirely. `should_accept_a_valid_oidc_token` now asserts
`result.Subject == "subject-1"` through the production handler with no reflection. The test passing
is the direct evidence: with the old handler it returned `missing_subject` (Task 3 report, concern 3).

## C2 — never throw (fixed)

`ValidateAsync` wraps the whole validation path (lazy config creation, discovery, token validation,
refresh) in a try/catch and returns `OidcValidationResult(false, "invalid_token", ...)` on any
failure; it logs at Debug. `ExchangeOidc` therefore gets a failure result for invalid
signature/expiry/issuer/audience, and its documented 401 path works instead of a 500.

Fixture: `should_reject_expired_token`, `should_reject_wrong_issuer`, `should_reject_wrong_audience`
converted from `Throws.InstanceOf<SecurityTokenException>()` to failure-result assertions
(`Success == false`, `FailureReason == "invalid_token"`). The rotation test's stale-after-retry block
additionally asserts an unknown-kid signature failure returns `invalid_token`, never throws.

## C1 — in-call JWKS retry (fixed)

On a signature/kid validation failure (`SecurityTokenSignatureKeyNotFoundException`,
`SecurityTokenInvalidSignatureException`, including AggregateException/inner unwrapping), the service
calls `_configurationManager.RequestRefresh()`, re-fetches configuration, rebuilds
`TokenValidationParameters` from the new key set, and retries once inside the same `ValidateAsync`
call. Retry is deliberately limited to signature/kid failures so expired/issuer/audience rejections
do not cause a discovery round-trip (no invalidation DoS amplification).

Fixture: `should_accept_rotated_key_after_jwks_refresh` now asserts the rotated-key token succeeds in
a single `ValidateAsync` call, with `RequestRefresh()` exactly once and
`GetConfigurationAsync` exactly twice. Same test also covers a still-stale refreshed key set →
`invalid_token` (C2), `RequestRefresh()` once. The previous across-calls-only behavior is no longer
documented as a gap.

## C4 — constructor collapse (fixed, low risk)

The either/or constructor is now one assignment path:

```csharp
public OidcTokenValidationService(
    IConfigurationManager<OpenIdConnectConfiguration> configurationManager = null,
    IOptionsMonitor<IConfigFileProvider> configProvider = null)
{
    _configurationManager = configurationManager;
    _configFileProvider = configProvider?.CurrentValue;
}
```

Both dependencies are assigned when supplied, so a manager supplied together with the options monitor
(the test seam) always has `OidcClientId` available. The signature is unchanged, so production DI
(monitor only, lazy network manager) is byte-for-byte the same activation path. The fixture now calls
`new OidcTokenValidationService(configurationManager, _configMonitor.Object)` directly — the
`_configurationManager` reflection helper is gone, so the fixture uses only the public constructor.

## Verification (run from `/tmp`)

Build, full solution:

```
/home/missioncontrol/.dotnet/dotnet build /home/missioncontrol/Nextcloud/vibe-codez/Sonarr-oidc/src/Sonarr.sln -c Debug -p:Platform=Posix -p:SolutionDir=/home/missioncontrol/Nextcloud/vibe-codez/Sonarr-oidc/src/
```

Result: **Build succeeded. 0 Warning(s), 0 Error(s).** (28 s)

Tests:

```
/home/missioncontrol/.dotnet/dotnet test /home/missioncontrol/Nextcloud/vibe-codez/Sonarr-oidc/src/Sonarr.Http.Test/Sonarr.Http.Test.csproj -c Debug -p:Platform=Posix -p:SolutionDir=/home/missioncontrol/Nextcloud/vibe-codez/Sonarr-oidc/src/ --filter "FullyQualifiedName~OidcTokenValidationService|FullyQualifiedName~AuthenticationControllerOidc|FullyQualifiedName~OidcGroupMapping"
```

Result: **Passed! - Failed: 0, Passed: 37, Skipped: 0, Total: 37** (time 834 ms; 9 token-validation,
9 controller, 19 group-mapping). Test count unchanged, as required.

## Concerns / notes

1. The brief names the runtime file `src/Sonarr.Http/Authentication/OidcTokenValidationService.cs`,
   but that path does not exist on this branch. The class `OidcTokenValidationService` still lives in
   `AuthentikTokenValidationService.cs` (Task 2 renamed the class, not the file). I edited the file
   that actually contains the service and did not rename it, to stay inside the allowed file set.
   Rename remains a Task 2 loose end; it would be a pure `git mv` with no code change.
2. Retry-on-signature-failure also fires when the kid is known but the signature is bad (per brief
   "signature/kid validation failure"), costing one unnecessary JWKS refresh for such tokens. Bounded
   to one retry per call.
3. Discovery/network failures now also fail closed as `invalid_token` (Debug log) rather than throwing
   into `ExchangeOidc`; this follows from "never throw" and is the safe path for the 401 contract.
4. `UpsertOidcUserFixture`'s 3 pre-existing failures were not touched or claimed.
