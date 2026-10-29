# 2026-10-29 — GHCR Image Secret/URL Audit (`sonarr-oidc:feature-oidc-app-auth`)

Question: do the pushed images contain hardcoded secrets, credentials,
or server URLs?

## Method
- `docker inspect` Env: only runtime defaults (`PATH`, `TZ=Etc/UTC`,
  `ASPNETCORE_HTTP_PORTS`, `DOTNET_*`). No secrets.
- `docker history`: no `secret|password|key=|token=` steps.
- Leak check on `/app`: no `.env`, `.git`, `config.xml`, `sonarr.db`.
- Extracted `Sonarr.Http.dll` + `Sonarr.Core.dll`, decoded .NET string heaps,
  scanned for URLs and `password|secret|apikey|connectionstring` assignments.
- Note: `strings` isn't in the slim runtime; used UTF-16 metadata decode
  on host-copied DLLs.

## Result: CLEAN
- **Secrets/credentials: none.** Zero secret-like assignments, no private
  keys, no API keys, no connection strings in either assembly.
- **Server URLs present (all expected, none secret):**
  - Upstream third-party endpoints (pre-existing Sonarr behavior):
    notification providers (Pushover/Telegram/Slack/etc.), indexer/search
    APIs (Trakt/TVDB/TMDB/newznab), `auth.servarr.com` (upstream OAuth relay).
  - `https://auth.piracyhub.win/application/o/seekarr/` (+ `http://`
    variant): the spec-mandated Authentik issuer constant
    (`AuthentikTokenValidationService.Issuer`). Public IdP endpoint,
    intentionally hardcoded per pilot spec — not a credential.
  - `https://localhost`: OIDC fallback default when IdP is unconfigured.
  - `http://schemas.microsoft.com/...` claim-type URNs (framework constants).

## Conclusion
Safe to distribute. No rotation or rebuild needed on secrecy grounds.
