# =========================================================
# Dockerfile — EasyWAF
#
# A runtime image around an already-built binary rather than
# a from-source build. The release workflow compiles x86_64
# and aarch64 in its build matrix, and this image copies the
# result in, so the container ships the exact binary that was
# released and tested — and the arm64 image does not have to
# be compiled under QEMU emulation.
#
# It therefore expects the binaries to be in the build
# context:
#
#   dist/easywaf-amd64
#   dist/easywaf-arm64
#
# Build one locally with:
#   cargo build --release
#   mkdir -p dist && cp target/release/easywaf dist/easywaf-amd64
#   docker build -t easywaf .
# =========================================================

FROM debian:bookworm-slim

# ca-certificates is needed for outbound TLS to upstreams; the binary is
# otherwise static apart from glibc.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Set by buildx per platform — "amd64" or "arm64".
ARG TARGETARCH
COPY dist/easywaf-${TARGETARCH} /usr/bin/easywaf
RUN chmod 755 /usr/bin/easywaf

# EasyWAF resolves templates, static assets, rules and config.toml relative to
# its working directory, so they live together and the workdir is set below.
WORKDIR /opt/easywaf
COPY templates/ templates/
COPY static/    static/
COPY rules/     rules/

# The container's config differs from the package's in one way: the database
# goes to /data so it survives the container, rather than into the image's
# working directory where it would be lost on the next `docker run`.
COPY docker/config.toml config.toml

# Persist the database. Mount a named volume or host directory here, or the
# data is lost with the container.
#
# The path is an environment variable rather than a config setting: config.toml
# is baked into the image, so a container that needs its database somewhere else
# would otherwise have to replace a file to say so.
ENV DATABASE_URL=sqlite:///data/easywaf.db
VOLUME ["/data"]

# 8443 is the management GUI over TLS; 8080 redirects to it. Proxy listeners
# come from the ports configured on each site, so publish whichever of those
# you use — commonly 80.
EXPOSE 8443 8080 80

CMD ["/usr/bin/easywaf"]
