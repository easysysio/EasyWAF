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

# The account EasyWAF runs as, as the packages do: not root. A fixed id, so a
# volume or a host directory can be given to it by number.
RUN groupadd --system --gid 10001 easywaf \
 && useradd --system --uid 10001 --gid easywaf --home-dir /opt/easywaf \
            --no-create-home --shell /usr/sbin/nologin easywaf

# Set by buildx per platform — "amd64" or "arm64".
ARG TARGETARCH
COPY dist/easywaf-${TARGETARCH} /usr/bin/easywaf

# Sites listen on ports below 1024 — 80 at least, which Let's Encrypt
# validates on. Docker lets an unprivileged process bind them inside a
# container already; the capability on the binary covers a runtime that does
# not. setcap is installed for this and removed again.
RUN chmod 755 /usr/bin/easywaf \
 && apt-get update \
 && apt-get install -y --no-install-recommends libcap2-bin \
 && setcap cap_net_bind_service=+ep /usr/bin/easywaf \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# Templates and static assets are compiled into the binary, so only the rule
# sets and config.toml are read from the working directory. rules/ stays a
# directory because it is data an operator can look at and a build refreshes
# from the published channel — and because rules/key.gpg, the key every update
# is verified against, belongs somewhere it can be inspected.
WORKDIR /opt/easywaf
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

# What EasyWAF writes: the database with its caches and backups beside it, and
# the audit log. Owned by its account before the volume is declared, so a new
# volume starts out owned by it too.
RUN mkdir -p /data /var/log/easywaf \
 && chown easywaf:easywaf /data /var/log/easywaf
VOLUME ["/data"]

# 8443 is the management GUI over TLS; 8080 redirects to it. Proxy listeners
# come from the ports configured on each site, so publish whichever of those
# you use — commonly 80.
EXPOSE 8443 8080 80

USER easywaf
CMD ["/usr/bin/easywaf"]
