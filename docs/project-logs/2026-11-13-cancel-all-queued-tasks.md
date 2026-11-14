# 2026-11-13 — Cancel All queued tasks (System -> Tasks)

Branch: `feature/oidc-app-auth` (worktree `/tmp/opencode/sonarr-appauth`)
Scope: commits `33e185edb8`, `1a09a710` on `feature/oidc-app-auth`.

## Feature

- Added a "Cancel All" button for queued tasks on System -> Tasks, above the queue table.
- The existing per-row cancel action is retained.
- Frontend only.

## Files changed

- `frontend/src/System/Tasks/Queued/QueuedTasks.tsx`
- `src/NzbDrone.Core/Localization/Core/en.json` (keys `CancelAll`, `CancelAllQueuedTasksMessage`)

## Implementation

- React Query. `useCommands()` supplies `data` (defaulted to `[]`).
- The handler filters to `status === 'queued'`, closes the DANGER confirm modal first, and no-ops on an empty list.
- Deletes each queued command with `fetchJson` `DELETE /command/{id}` (same endpoint the existing `useCancelCommand` mutation uses).
- Removes each id from the `['/command']` cache on success.
- Calls `queryClient.invalidateQueries({ queryKey: ['/command'] })` in `.finally()` after `Promise.allSettled`, so anything that failed to cancel reappears.

## Why queued-only

- Backend `DELETE /api/v3/command/{id}` -> `Cancel(id)` -> `RemoveIfQueued(id)` throws 409 "Unable to cancel task" for started commands.

## Commits on `feature/oidc-app-auth` (worktree)

| Commit | Description |
| --- | --- |
| `33e185edb8` | Merge of `upstream/develop` into `feature/oidc-app-auth` (17 commits: STJson/UTF-8 JSON, JSON compaction, queue refresh fix, multi-season pack import, UI/accessibility tweaks, translations, Postgres-password log fix). Clean ort merge, no conflicts. Migrations: ours `238_oidc_user_role_and_subject` and `239_oidc_password_nullable`, upstream `240_series_title_slug_not_unique` — no collision. OIDC symbols verified present after merge. |
| `1a09a710` | `New: Add Cancel All control for queued tasks` (final after lint fixes). |

## Same feature on `feature/oidc-group-auth`

- Same feature also exists on branch `feature/oidc-group-auth` at commit `892cbe177` (the clean branch built from `upstream/develop` for a possible upstream contribution). Both branches carry identical code.

## Why the feature was cherry-picked

- The feature was first written on `feature/oidc-group-auth`, but the deployed GHCR image builds from `feature/oidc-app-auth`, so the commit was cherry-picked there (it applied cleanly because that branch already used the `useCommands` hook).

## Verification

| Check | Result |
| --- | --- |
| `dotnet build src/Sonarr.sln -c Debug -p:Platform=Posix -p:SolutionDir=<src>/` (worktree) | 0 Warning(s), 0 Error(s). |
| Dockerfile `frontend` stage build | vite/rolldown "built in 3.98s". |
| ESLint inside the verify image (both branches) | `LINT_OK`. Initially reported 4 errors on this file: two prettier formatting errors, `no-void` on `void Promise.allSettled(...)`, and `max-nested-callbacks` (5 > 4). Fixed by removing `void` and extracting the per-command cache removal into its own `useCallback`; prettier was run to format. |
| `npx tsc --noEmit -p tsconfig.json` | Zero errors in `frontend/src` (remaining output is pre-existing `node_modules` typedef noise). |
| Full image build | `ghcr.io/wetw0rks-c0ding/sonarr-oidc:cancelall-1a09a710` (image id `40f70bfe1a18`). Built UI bundle contains the `CancelAll` key. |
| Backend cancel contract (Prowlarr build of the same shared code path) | queued `DELETE` -> 200 and row removed; started -> 409; completed -> 409. |

## Notes

- Project logs were committed on the deployed branch (`feature/oidc-app-auth`) only.
- A later pass should mirror this log onto `feature/oidc-group-auth` if that branch is ever pushed.
