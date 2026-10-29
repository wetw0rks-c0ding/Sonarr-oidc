# Sonarr (OIDC fork) runtime image — framework-dependent .NET 10 + prebuilt UI.
# Build: docker build -t ghcr.io/wetw0rks-c0ding/sonarr-oidc:<tag> .
# Run:   docker run -d -p 8989:8989 -v sonarr-config:/config ghcr.io/wetw0rks-c0ding/sonarr-oidc:<tag>

# ---------- Frontend ----------
FROM node:24-bookworm-slim AS frontend
WORKDIR /src
COPY package.json yarn.lock .yarnrc vite.config.ts tsconfig.json index.html ./
COPY frontend ./frontend
RUN yarn install --frozen-lockfile --network-timeout 600000 --network-concurrency 4 --network-retry-delay 5000 \
    && yarn build

# ---------- Backend ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0-bookworm-slim AS backend
WORKDIR /src
COPY global.json ./
COPY src ./src
RUN dotnet restore src/Sonarr.sln \
    && dotnet publish src/NzbDrone.Console/Sonarr.Console.csproj \
        -c Release \
        -r linux-x64 \
        --self-contained false \
        -p:Platform=Posix \
        -o /app/publish
COPY --from=frontend /src/_output/UI /app/publish/UI

# ---------- Runtime ----------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-bookworm-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false \
    TZ=Etc/UTC
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 mediainfo tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=backend /app/publish ./
EXPOSE 8989
VOLUME ["/config"]
ENTRYPOINT ["dotnet", "/app/Sonarr.dll", "-nobrowser", "-data=/config"]
