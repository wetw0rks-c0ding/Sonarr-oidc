# 2026-10-28 — OIDC Group-Auth Foundation (Role model, group mapping, JIT provisioning)

Branch: `feature/oidc-app-auth` (forked from `develop` @ `58fe696648`).
Spec: `/home/missioncontrol/.opencode/plan/oidc-group-authorization-spec.md`.

## What was built
Authorization (group → tier → role) on top of the pre-existing OIDC
authentication (commit `9f0cb928`, authN only: login works, no permissions).

## Changes (in commit order)

1. **`SonarrRole` enum** (`1e478e49c1`)
   - New `src/NzbDrone.Core/Authentication/SonarrRole.cs`:
     `ReadOnly=0, AddSearch=1, Manage=2, Admin=3`. Ordered, cumulative.
   - Fixture `src/NzbDrone.Core.Test/Authentication/SonarrRoleFixture.cs`.

2. **`OidcGroupMapping`** (`80e8123c2f`)
   - New `src/Sonarr.Http/Authentication/OidcGroupMapping.cs`, hardcoded
     Authentik groups → tiers (`pirates→T1` … `authentik Admins→T5`) →
     roles. `Resolve()` returns null for T1-only/empty/unknown (reject),
     highest-tier-wins, case-insensitive.
   - Fixture with full tier + rejection coverage.

3. **Config `OidcGroupsClaim`** (`e6ad87d194`)
   - `AuthOptions.OidcGroupsClaim`, `IConfigFileProvider.OidcGroupsClaim`
     (default `"groups"`), change-token source updated, plus both API
     resources/mappers (V3 `HostConfig`, V5 `GeneralSettings`).

4. **`User` model extension** (`bd30cceb7d`)
   - `User.cs`: `OidcSubject`, `OidcGroups` (comma-joined),
     `Role` (default `Admin` for forms users). Password/Salt left
     non-nullable at this stage (see 2026-10-29 C2/C5).

5. **Migration 238** (`54bcb5bc65`)
   - New `238_oidc_user_role_and_subject.cs`: adds `OidcSubject`/`OidcGroups`
     (nullable), `Role` (int, default 3), filtered unique index
     `IX_Users_OidcSubject` (prevents subject reuse, survives renames).

6. **`IUserService.UpsertOidcUser`** (`3596d4ba53`)
   - `UserService` + `IUserRepository.FindBySubject/FindByUsername`.
   - Subject-first lookup → update; else one-time username link for
     forms→OIDC migration (null-subject + email_verified guard);
     else insert new row with null password.

## Verification
- `dotnet build src/Sonarr.sln -c Debug -p:Platform=Posix`: 0 errors.
- New fixtures pass. Pre-existing `InitialUserService` failures (2) confirmed
  identical on clean `develop` — unrelated.
