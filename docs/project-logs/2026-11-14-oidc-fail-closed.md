# Project log — 2026-11-14: OIDC fail-closed fix

## What landed

- Web OIDC login no longer elevates a principal to Admin when `OidcRoleMappings` is configured and the principal's groups map to no allowed role.
- The legacy `OidcUserIdentifier` single-user identifier fallback now applies only when no group mapping is configured (`null`/empty). When mappings are configured, a mapping resolution that yields nothing is denied, mirroring `/api/auth/oidc/exchange` (403 `insufficient_group`) and the fork's OIDC spec (unmapped groups must deny).
- Same fix applied to both `feature/oidc-group-auth` (PR branch) and `feature/oidc-app-auth` (deployed branch, cherry-picked as efe56e06a7).

## Audit trigger

Scoped security audit of the fork diff (audit workspace `~/security-audit-skill/Sonarr-oidc/run-1/`): finding `SonarrOidc.IdentifierFallbackBypassesGroupMapping`, severity high, independently verified from source and confirmed by the exchange endpoint in the same fork.

## Verification

- `dotnet build -c Debug -p:Platform=Posix`: 0 warnings / 0 errors for both branches.
- Dedicated Oidc fixture suite (44 tests) green; earlier 15 pre-existing `AuthenticationServiceFixture` failures are unrelated (upstream) and unchanged.
- 7 new fixture cases covering mapped/unmapped/legacy paths.

## Images

Immutable tag `ghcr.io/wetw0rks-c0ding/sonarr-oidc:fix-efe56e06` (digest `sha256:88d9…`, see registry) contains the fix. `:feature-oidc-app-auth` not moved.

## Not done

- Upstream contribution burned for this account; no upstream PR.
- `RadarrOidc.PermissionHandlerFailsOpenWithoutRoleClaim` (forms-login, no role claim) remains a needs_validation candidate, tracked in the audit NEEDS-VALIDATION.md.
