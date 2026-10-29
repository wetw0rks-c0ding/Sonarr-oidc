# 2026-10-29 — Docker Runtime Image Build + GHCR Push

Branch: `feature/oidc-app-auth`. Skill: `builddocker`.

## Image
`ghcr.io/wetw0rks-c0ding/sonarr-oidc:feature-oidc-app-auth`,
`:8a967c68ac` (same digest `sha256:3750a3…`, 630 MB).
Self-contained `Sonarr` apphost, prebuilt UI, `sqlite3` + `mediainfo` +
`tzdata`. `ENTRYPOINT ["/app/Sonarr", "-nobrowser", "-data=/config"]`,
port 8989, `/config` volume.

## Files added (committed on branch, pushed)
- `Dockerfile` — 3-stage: node:24 frontend (`yarn build` → `_output/UI`),
  `dotnet/sdk:10.0.403` backend (`msbuild PublishAllRids`, self-contained,
  mirrors CI), `dotnet/aspnet:10.0` runtime.
- `.dockerignore` — excludes `.git`, `_output/`, `node_modules/`, docs, etc.
  (Keeps `Logo/` — `Logo/64.png` is an embedded resource.)

## Build issues hit and resolved
1. `yarn install` ETIMEDOUT in container (bridge NAT throttling bursts;
   host + single-connection curl fine). Fixed: `--network=host` build,
   yarn flags hardened (concurrency 4, 60s timeout, 5s retry delay).
2. `mcr…/sdk:10.0-bookworm-slim` tag doesn't exist → `sdk:10.0`, then
   pinned to `sdk:10.0.403` to match `global.json`/CI.
3. `dotnet publish` needs `-f net10.0` (multi-targeted console project);
   superseded by switching to CI-identical `msbuild -t:PublishAllRids`.
4. Release-only CA warnings (CA1304/CA1724 in untouched NzbDrone.Common)
   fail the build under newer SDK analyzers → `-p:TreatWarningsAsErrors=false`
   **Docker-only** (CI stays strict).
5. `Logo/64.png` missing from backend stage (`COPY src` only) → `COPY Logo`.

## Verification (per skill)
- Pre-build secret scan: clean (only `GITHUB_TOKEN` ref + a class named
  `*Credential*`).
- Post-build: 630 MB; leak check (`/app` for `.env`/`.git`/`config.xml`/
  `sonarr.db`) clean; `/app/UI` contains `index.html`, `login.html`,
  `logout.html`, `assets/`.
- Docker `ghcr.io` credential (stored PAT) validated with `docker login`
  before push. Credential left in place afterwards (shared with other
  projects — no `docker logout`).
- Branch `feature/oidc-app-auth` pushed to fork `wetw0rks-c0ding/Sonarr-oidc`
  (upstream `Sonarr/Sonarr` untouched).

## Test deployment — `sonarr-oidc:test` on `bertha:8988` (2026-10-29 03:xx UTC)

Sidecar to stock `bertha:8989` (`lscr.io/linuxserver/sonarr:latest`). Built from `_output/net10.0/linux-x64/publish` (dotNet fix `fbf3c16` — `ValidIssuers` http+https, empty sentinel for Password/Salt).

- Image: `sonarr-oidc:test` `sha256:0eb8d09d...` (25 MB tgz, `dotnet/aspnet:10.0` runtime, `REPORT` -> `sonarr-oidc-test2`)
- Run: `docker run -d --name sonarr-oidc-test -p 8988:8989 -v /tmp/sonarr-oidc-config:/config sonarr-oidc:test` — `Up 5s`, migrates `238 oidc_user_role_and_subject` + `239 oidc_password_nullable` (no-op), `Now listening on: http://[::]:8989`
- Probes (non-disruptive):
  - `POST /api/auth/oidc/exchange {}` → `400 subject_token is required` ✓
  - `GET /api/auth/me` no token → `401 invalid_token` ✓
  - PKCE `akadmin (T5)` via `auth.piracyhub.win` (`seekarr` implicit-consent, `http://127.0.0.1:8765/callback`) → `code` → `POST http://127.0.0.1:9001/application/o/token/` → `access_token` 1836b → `POST /api/auth/oidc/exchange` → `200 {role:Admin, permissions:[UI.Read,UI.Add,UI.Manage,UI.Admin], aud=sonarr}` → `GET /api/auth/me` → `200 {username:akadmin, role:Admin, groups:[authentik Admins,homarr-admins]}` ✓
  - `pirates (T1)` → `seekarr` `allow-admins` blocks at Authentik (no code), Sonarr `Resolve([pirates])=null` would be `403 insufficient_group` if token reached (unit-tested)
  - `ValidIssuers` fix confirmed: `http://auth.piracyhub.win/application/o/seekarr/` (internal token request) now accepted alongside `https://`

Stock `:8989` untouched; test cuts over by `docker stop sonarr && docker run -p 8989:8989` with same image when ready. `seekarr` provider left on `authorization_code+refresh_token` (password grant added for test then reverted).
