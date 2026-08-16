# syntax=docker/dockerfile:1.12@sha256:93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0@sha256:e1fc6e423f543119c406d24e2e687d67c569f18f04a37a8b0005d80ad0dcee80 AS build

ARG TARGETARCH
WORKDIR /source

COPY --link Directory.Build.props ./
COPY --link src/FmoCaTool/FmoCaTool.csproj src/FmoCaTool/
COPY --link src/FmoCaTool/packages.lock.json src/FmoCaTool/
RUN dotnet restore src/FmoCaTool/FmoCaTool.csproj \
    -a "$TARGETARCH" \
    --locked-mode \
    -p:SelfContained=true

COPY --link src/FmoCaTool/ src/FmoCaTool/
RUN dotnet publish src/FmoCaTool/FmoCaTool.csproj \
    -c Release \
    -a "$TARGETARCH" \
    --self-contained true \
    --no-restore \
    -p:PublishSingleFile=true \
    -p:DebugType=None \
    -p:DebugSymbols=false \
    -o /out \
    && mkdir --parents /work

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled@sha256:afd8faf9aca00ee69b44b33631665e654e2423e143b6362dffe52c006cd7c4e6 AS final

LABEL org.opencontainers.image.title="fmo-ca-tool" \
      org.opencontainers.image.description="Offline FMO V4 custom PKI certificate authority CLI" \
      org.opencontainers.image.source="https://github.com/bi9bbl/fmo-ca-tool" \
      org.opencontainers.image.licenses="GPL-3.0-only"

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 \
    DOTNET_EnableDiagnostics=0 \
    COMPlus_EnableDiagnostics=0

COPY --link --chown=1654:1654 --from=build /out/fmo-ca-tool /app/fmo-ca-tool
COPY --link --chown=1654:1654 --from=build /work /work
COPY --link LICENSE /licenses/fmo-ca-tool/LICENSE

WORKDIR /work
USER $APP_UID

ENTRYPOINT ["/app/fmo-ca-tool"]
