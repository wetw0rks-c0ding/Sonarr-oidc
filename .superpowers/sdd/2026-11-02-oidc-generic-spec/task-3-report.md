Task 3: OIDC fixtures adopted and OidcGroupMapping mapping-driven cases added.
Files: AuthenticationControllerOidcFixture.cs, OidcTokenValidationServiceFixture.cs, OidcGroupMappingFixture.cs.
Build: 0 warnings / 0 errors (Sonarr.Http.Test, net10.0, Platform=Posix, SolutionDir=src).
Adopted untracked fixtures (fixed static/instance, usings, ExchangeOidc signature, removed SetOptions).
Added mapping-driven cases: exact, case-insensitive, highest-wins, unmapped->null, empty->null, malformed ignored.
Concerns: pre-existing stylecop config requires SolutionDir; exact command without it reports SA1200 unrelated to changes.

## Round 1 fix (2026-11-02)

Fixed all open findings, fixture files only (`git status`: two modified fixtures, no shared infra/runtime/csproj changes).

1. `OidcTokenValidationServiceFixture` (now 9 tests, was 0/8): `Setup` writes `service-token.key` into `TempFolder` before `ReadKey()` reads it; TempFolder creation stays in TestBase. Signing key/config are fixture-owned; no network discovery is performed.
2. `AuthenticationControllerOidcFixture` (now 9 tests, was 0/6): corrected `Login` callback to the 3-parameter signature `(HttpRequest, string, string)`; controller now has `ControllerContext`/`HttpContext` and `HttpContext.RequestServices` registers `IOidcTokenValidationService`, `ISonarrServiceTokenService`, `IUserService`, `IUserRepository`, so the real controller paths resolve. Assertions are behavioral: 200 body shape (`token`, `token_type`, `expires_in`, `role`, `permissions`) plus upsert/mint verification, 400 (null + whitespace), 401 (`invalid_token`), 403 (`insufficient_group`), 429 on the 11th request for one IP, and `/me` 401/404/200. Per-test client IPs isolate the static rate limiter.
3. JWKS rotation: added `should_accept_rotated_key_after_jwks_refresh` (unknown `kid` rejected against the stale key set; same token validates once discovery returns the rotated key; exactly 2 `GetConfigurationAsync` calls). The pre-revert `unknown_kid_triggers_refresh_and_retries` semantics could not be reproduced: the current runtime never calls `RequestRefresh()` and does not retry inside one validation. See concern 1.
4. Mocked config is registered with Mocker in both fixtures (`IConfigFileProvider` + `IOptionsMonitor<IConfigFileProvider>` in the token fixture; `IConfigFileProvider` in the controller fixture).
5. `UpsertOidcUserFixture`: untouched (not in the verification filter); the 3 pre-existing failures remain and are not claimed fixed.

Verification (run from `/tmp`):

```
/home/missioncontrol/.dotnet/dotnet build /home/missioncontrol/Nextcloud/vibe-codez/Sonarr-oidc/src/Sonarr.Http.Test/Sonarr.Http.Test.csproj -c Debug -p:Platform=Posix -p:SolutionDir=/home/missioncontrol/Nextcloud/vibe-codez/Sonarr-oidc/src/
```
Result: Build succeeded, 0 Warning(s), 0 Error(s). `SolutionDir` must end with `/` because `src/Directory.Build.props` includes `$(SolutionDir)stylecop.json`; without it every project emits SA1200 (539 errors), unrelated to these changes.

```
/home/missioncontrol/.dotnet/dotnet test /home/missioncontrol/Nextcloud/vibe-codez/Sonarr-oidc/src/Sonarr.Http.Test/Sonarr.Http.Test.csproj -c Debug -p:Platform=Posix -p:SolutionDir=/home/missioncontrol/Nextcloud/vibe-codez/Sonarr-oidc/src/ --filter "FullyQualifiedName~OidcTokenValidationService|FullyQualifiedName~AuthenticationControllerOidc|FullyQualifiedName~OidcGroupMapping"
```
Result: `Passed! - Failed: 0, Passed: 37, Skipped: 0, Total: 37` (9 token-validation, 9 controller, 19 group-mapping).

Concerns (runtime, outside Task 3's "fixture files only" scope — please route to the Task 2 owner):

1. `OidcTokenValidationService` does not retry JWKS on unknown `kid`: it ignores `IConfigurationManager.RequestRefresh()`, so the rotation path only works on a later validation. The fixture documents this gap instead of asserting a retry that does not exist.
2. Invalid signature/lifetime/issuer/audience throw from `ValidateAsync` (`src/Sonarr.Http/Authentication/AuthentikTokenValidationService.cs:136-140`) instead of returning `OidcValidationResult(false, ...)`. `AuthenticationController.ExchangeOidc` has no catch, so a genuinely invalid token would surface as 500, not the documented 401. The controller 401 test covers the controller contract with a failure result; it cannot make the real validator return one.
3. `JwtSecurityTokenHandler` is created with default inbound claim mapping (`AuthentikTokenValidationService.cs:165`), which maps `sub` to `ClaimTypes.NameIdentifier`. `FindFirst("sub")` at line 143 therefore returns null and a fully valid token yields `missing_subject`. Verified: the fixture's first run, using the production handler, returned `missing_subject` for a valid token. The fixture injects a `MapInboundClaims = false` handler into the subject so it can exercise the intended accept/reject logic; the production bug remains. Fix is either `MapInboundClaims = false` on that handler or checking `ClaimTypes.NameIdentifier`.
4. Constructor is either/or (`AuthentikTokenValidationService.cs:31-41`): supplying an `IConfigurationManager` leaves `_configFileProvider` null, so `OidcClientId` is unavailable and validation fails closed. The fixtures construct through the options-monitor path and inject the fake manager via reflection (`_configurationManager` and `<handler>k__BackingField`) because there is no public test seam; this is fixture-only and fragile if those private members are renamed.
