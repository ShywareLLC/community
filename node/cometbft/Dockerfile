# CometBFT Node Dockerfile

FROM ubuntu:22.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    jq \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# CometBFT version
ARG COMETBFT_VERSION=0.38.5

# Download and install CometBFT
RUN wget "https://github.com/cometbft/cometbft/releases/download/v${COMETBFT_VERSION}/cometbft_${COMETBFT_VERSION}_linux_amd64.tar.gz" && \
    tar -xzf "cometbft_${COMETBFT_VERSION}_linux_amd64.tar.gz" && \
    mv cometbft /usr/local/bin/ && \
    chmod +x /usr/local/bin/cometbft && \
    rm "cometbft_${COMETBFT_VERSION}_linux_amd64.tar.gz"

# Create non-root user
RUN useradd -m -u 1000 cometbft

# Create CometBFT home directory
RUN mkdir -p /opt/cometbft && \
    chown -R cometbft:cometbft /opt/cometbft

# Copy initialization scripts
COPY --chown=cometbft:cometbft ./scripts /opt/cometbft/scripts

# Copy config templates
COPY --chown=cometbft:cometbft ./config /opt/cometbft/config-templates

# Switch to non-root user
USER cometbft

# Set working directory
WORKDIR /opt/cometbft

# Set CometBFT home
ENV CMTHOME=/opt/cometbft

# Expose ports
# P2P
EXPOSE 26656
# RPC
EXPOSE 26657
# Prometheus metrics
EXPOSE 26660

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:26657/health || exit 1

# Volume for data persistence
VOLUME ["/opt/cometbft"]

# Entry point script
ENTRYPOINT ["/opt/cometbft/scripts/start.sh"]

# Default command
CMD ["start", "--home", "/opt/cometbft"]
