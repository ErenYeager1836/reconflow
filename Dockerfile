# ==============================================================================
# Multi-stage Dockerfile for reconflow
#
# Stage 1: Download and verify pinned reconnaissance tool binaries
# Stage 2: Minimal Python 3.12-slim runtime with non-root execution user
# ==============================================================================

FROM python:3.12-slim AS tools-installer

# TARGETARCH is populated by buildx for the image's target platform (e.g.
# "amd64" or "arm64"); it matches the arch suffix projectdiscovery and gau
# use in their release filenames, so it drives which binary gets fetched.
ARG TARGETARCH

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl unzip tar ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tools/bin

# Pinned toolchain versions.
# NAABU_VERSION is 2.7.0, not the previous 2.3.2: projectdiscovery only
# started publishing linux_arm64 naabu zips at 2.6.0, so the old pin has no
# arm64 asset to download.
ENV SUBFINDER_VERSION=2.6.8 \
    HTTPX_VERSION=1.6.9 \
    DNSX_VERSION=1.2.1 \
    NAABU_VERSION=2.7.0 \
    KATANA_VERSION=1.1.2 \
    NUCLEI_VERSION=3.3.8 \
    GAU_VERSION=2.2.3 \
    WAYBACKURLS_VERSION=0.1.0

# Download and extract all external binaries in a single layer to avoid layer bloat
RUN set -e && \
    curl -sSL --retry 5 --retry-delay 2 --retry-all-errors -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${TARGETARCH}.zip" && \
    unzip -q subfinder.zip subfinder && rm -f subfinder.zip && \
    curl -sSL --retry 5 --retry-delay 2 --retry-all-errors -o httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip" && \
    unzip -q httpx.zip httpx && rm -f httpx.zip && \
    curl -sSL --retry 5 --retry-delay 2 --retry-all-errors -o dnsx.zip "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${TARGETARCH}.zip" && \
    unzip -q dnsx.zip dnsx && rm -f dnsx.zip && \
    curl -sSL --retry 5 --retry-delay 2 --retry-all-errors -o naabu.zip "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip" && \
    unzip -q naabu.zip naabu && rm -f naabu.zip && \
    curl -sSL --retry 5 --retry-delay 2 --retry-all-errors -o katana.zip "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${TARGETARCH}.zip" && \
    unzip -q katana.zip katana && rm -f katana.zip && \
    curl -sSL --retry 5 --retry-delay 2 --retry-all-errors -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" && \
    unzip -q nuclei.zip nuclei && rm -f nuclei.zip && \
    curl -sSL --retry 5 --retry-delay 2 --retry-all-errors -o gau.tar.gz "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    tar -xzf gau.tar.gz gau && rm -f gau.tar.gz && \
    chmod +x /tools/bin/*

# waybackurls' last release (v0.1.0) only ever shipped a linux_amd64 binary,
# so arm64 needs its own stage that compiles it from source instead of
# downloading a prebuilt zip. Cross-compiles from the build host (any arch)
# to TARGETARCH, same as the rest of this file.
FROM golang:1.23-bookworm AS waybackurls-builder
ARG TARGETARCH
ENV WAYBACKURLS_VERSION=0.1.0
RUN GOARCH=${TARGETARCH} GOOS=linux CGO_ENABLED=0 \
    go install "github.com/tomnomnom/waybackurls@v${WAYBACKURLS_VERSION}"

# ==============================================================================
# Stage 2: Runtime Container
# ==============================================================================
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/reconuser/.local/bin:/usr/local/bin:$PATH"

# Install minimal OS dependencies for network tools
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libpcap-dev \
        bind9-host \
        dnsutils && \
    rm -rf /var/lib/apt/lists/*

# Copy external binaries from the earlier stages
COPY --from=tools-installer /tools/bin/ /usr/local/bin/
COPY --from=waybackurls-builder /go/bin/waybackurls /usr/local/bin/waybackurls

# Create unprivileged system user
RUN groupadd -g 10001 recongroup && \
    useradd -u 10001 -g recongroup -s /bin/bash -m -d /home/reconuser reconuser && \
    mkdir -p /app/output && \
    chown -R reconuser:recongroup /home/reconuser /app

WORKDIR /app

# Copy and install reconflow package
COPY --chown=reconuser:recongroup pyproject.toml README.md ./
COPY --chown=reconuser:recongroup reconflow ./reconflow

RUN pip install --no-cache-dir .

USER reconuser

ENTRYPOINT ["reconflow"]
CMD ["doctor"]
