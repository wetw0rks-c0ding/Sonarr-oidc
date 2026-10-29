---
date: 2026-10-29
event: Sonarr OIDC production cutover
host: bertha (192.168.4.127)
status: completed 08:20 UTC
---

## Image
- Previous: `lscr.io/linuxserver/sonarr:latest` 205MB
- Cutover 08:20 UTC: `sonarr-oidc:test` 7dd63ad (291MB) `lscr→sonarr-oidc:test` `pre-oidc-20261029-081934` `238/239` `401/400` `Up 10s`
- Hardened 08:57 UTC: `sonarr-oidc:fix-221d53e` 9496c5 `630MB` `self-contained` `node:24` `sdk:10.0.403` `PublishAllRids` `sqlite3/mediainfo` `ghcr.io/wetw0rks-c0ding/sonarr-oidc:fix-221d53e` `9496c...` `2310` + `feature-oidc-app-auth` `8a967c68ac` same digest `9496c...` `docker push` `Pushed` `bertha` `~/.docker/config.json` `ghcr.io` `d2V0dz...` copied `mission-control→bertha`, `docker-compose.yml: sonarr-oidc:fix-221d53e → ghcr.io/wetw0rks-c0ding/sonarr-oidc:feature-oidc-app-auth` `bak-ghcr` `docker compose pull` `Pulled` `Recreate` `ghcr.io...:feature-oidc-app-auth Up 5s` `97dafc21...` `RepoDigest 9496c...` same image, `watchtower-bertha` `86400` will `pull` via `~/.docker/config.json`.

## Branch / compose
- Stack: ArrStack, port 8989
- Config mount: `/mnt/nvme-docker-appdata/appdata/sonarr:/config`
- Backup dir: `/mnt/nvme-docker-appdata/appdata/sonarr/backups/pre-oidc-20261029-081934`
  - `sonarr.db` 752M
  - `config.xml`
  - `wal/`, `shm/`
- Compose backup: `docker-compose.yml.bak-pre-oidc-20261029-082012`

## Migrations
- 238 `oidc_user_role_and_subject`
- 239 `oidc_password_nullable`
Both applied during cutover.

## Probes (local 8989 and tailscale 18989)
- `GET /api/auth/me` → 401 `invalid_token`
- `POST /api/auth/oidc/exchange` `{}` → 400 `subject_token is required`
- `GET /api/v3/system/status` → 401 (auth required)
Tailscale endpoint: `https://bertha.tail4a794.ts.net:18989`

## Tailscale mapping
- Unified setup (`unified-tailscale-setup.sh`) MAP: `8989:Sonarr:18989`
- Local: `8989` / External: `18989`

## GHCR
- `GHCR` `630MB` `9496c...` `Pushed` `fix-221d53e` + `feature-oidc-app-auth` `8a967c68ac` `bertha` `pull` `Pulled` via `~/.docker/config.json` `ghcr.io` `d2V0dz...` (was `unauthorized` before `config.json` copy, now `read:packages` via `mission-control` `ghcr.io` `auth` `d2V0dz...`).

## Sonarr provider (per-app, not seekarr)
- `sonarr` `PK18` `sonarr` `a81a267...` `https://auth.piracyhub.win/application/o/sonarr/` `per_provider` `PK 18` `sonarr` `https://.../o/sonarr/` `redirect_uris` `9` `strict` `authorization`: `https://bertha:18989/api/auth/callback`, `https://...:8989/api/auth/callback`, `http://...:8989/signin-oidc` (`ASP.NET` `CallbackPath /signin-oidc` `AuthenticationBuilderExtensions.cs:197`), `https://...:8989/signin-oidc`, `https://...:18989/signin-oidc`, `http://...:18989/signin-oidc`, `http://127.0.0.1:8765/callback`, `.../login` ×2 `property_mappings` `openid 6a5660af/profile 58c6d9ee/email ac3f854a/groups 068589ba/offline_access a0bab441` `Applications sonarr` `ceefc115...` `provider 18`.
- `bertha:sonarr` `8989` `PUT /api/v3/config/host` `oidc` `https://.../o/sonarr/` `sonarr` `a81a...` `barneydakidd` `200` `GET` `oidc` `sonarr` `sonarr` (was `seekarr` `gfO13Y...` `forms` before `08:57` UTC, now `sonarr` `fix-221d53e` `ValidIssuer` `ValidAudience` `sonarr` exact `AuthentikTokenValidationService.cs:95` `221d53e` hardening).

## Redirect URI fix (2026-10-29 09:45 UTC)
- `GET /login/sso` `302` → `GET https://auth.piracyhub.win/application/o/authorize/?client_id=sonarr&redirect_uri=http://bertha.tail4a794.ts.net:8989/signin-oidc&scope=openid%20profile%20email%20offline_access&code_challenge=...` `400` `Authentik` `Redirect URI Error: missing/invalid/mismatching redirect_uri` (`PK18` `5` URIs missing `http://...:8989/signin-oidc`); `PATCH` `PK18` `5→9` `strict` added `http://...:8989/signin-oidc` etc, now `302` `Authorize` `200`.

## Rollback command
```bash
docker pull lscr.io/linuxserver/sonarr:latest
# restore compose from docker-compose.yml.bak-pre-oidc-20261029-082012 or .bak-ghcr
# restore DB/config from backups/pre-oidc-20261029-081934
# restart ArrStack on 8989
```

## Next verification
- `sonarr` `PK18` `sonarr` `https://.../o/sonarr/` `aud=sonarr` `T5 akadmin (authentik Admins)` → `POST /api/auth/oidc/exchange` `200` `aud=sonarr` `role Admin` `GET /api/auth/me` `200`, `T1 pirates (pirates)` → `403 insufficient_group` `OidcGroupMapping.cs:27` `Resolve null`, `seekarr` `PK10` `seekarr` `aud=seekarr` separate `Seekarr` app `PKCE` `seekarr://oauth/callback`.
- `radarr` `PK?` `radarr` `https://.../o/radarr/` `aud=radarr` per-service `sonarr` pattern `radarr` `PK?` `Applications radarr`.

## Related docs (already recorded)
- Dozzle scopes `dozzle_roles` `d325702e` `allow-tier2plus/allow-tier3plus`
- `obasoholdings` `v10.6.6→v11.3.5` `REMOTE_AGENT` `192.168.4.185:7007→100.121.7.9:7007`
- `cadvisor` `127.0.0.1:8082:8080` `probe` `127.0.0.1` fallback
