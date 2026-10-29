# 2026-10-29 — C5 Client-Agent Changes (issuer schemes, password sentinel)

Branch: `feature/oidc-app-auth`. Commit `fbf3c16cf5` by client agents
(wetw0rks-c0ding), landed before the Docker build.

## Changes
1. **`AuthentikTokenValidationService.cs`**: accept both `http` and `https`
   issuer variants — the token endpoint is hit via internal
   `http://127.0.0.1:9001`, which otherwise fails with IDX10205
   (issuer mismatch).
2. **`UserService.cs`**: OIDC users store the **empty-string sentinel** for
   `Password`/`Salt` instead of null.
3. **Migration 239**: effectively a no-op — client agents hit a SQLite
   `AlterColumn` failure path in FluentMigrator and chose the sentinel
   approach instead of relying on the nullability change.

## Implication
- C2's migration-239 reasoning (processor table-rebuild) is superseded:
  live code path no longer depends on nullable `Password`.
- Migration 239 remains in the chain (harmless no-op); do not remove
  (sequence gap would break migrator versioning).
