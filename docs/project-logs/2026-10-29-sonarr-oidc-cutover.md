---
date: 2026-10-29
event: Sonarr OIDC production cutover
host: bertha (192.168.4.127)
status: completed 08:20 UTC
---

## Image
- Previous: `lscr.io/linuxserver/sonarr:latest` 205MB
- Cutover: `sonarr-oidc:test` 7dd63ad (291MB)
- Tags on 7dd63ad: `ghcr.io/wetw0rks-c0ding/sonarr-oidc:feature-oidc-app-auth`, `:8a967c68ac` (291MB same)
- GHCR `ghcr.io/wetw0rks-c0ding/sonarr-oidc:feature-oidc-app-auth` 630MB (same code) — private; bertha has no `~/.docker/config.json`; needs `read:packages` or make public. Local tag `sonarr-oidc:test` is sufficient for this host.

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

## GHCR unauthorized
- `GHCR` 630MB image is same build; `docker pull` fails `unauthorized` / `Head unauthorized` on bertha (no config). Resolve via `read:packages` or public visibility before relying on GHCR tag.

## Rollback command
```bash
docker pull lscr.io/linuxserver/sonarr:latest
# restore compose from docker-compose.yml.bak-pre-oidc-20261029-082012
# restore DB/config from backups/pre-oidc-20261029-081934
# restart ArrStack on 8989
```

## Next verification
- `seekarr` provider `10`
- `T5 Admin` → 200, audit `aud=sonarr`
- `T1 pirates` → 403 (expected denial for unscoped/pirate role under OIDC)
- Confirm probes return expected auth responses after provider/auth setup complete.

## Related docs (already recorded)
- Dozzle scopes
- `obasoholdings` v11.3.5
- `cadvisor` 127.0.0.1
