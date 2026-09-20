# The build needs a C compiler: rusqlite carries SQLite's source and compiles
# it here rather than looking for a system copy.
FROM rust:1.98-slim-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/manapds /manapds

FROM debian:trixie-slim
# Resolving a handle or reaching the PLC directory is an outbound TLS call, so
# the roots have to come from somewhere.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /manapds /usr/local/bin/manapds

# A repository is only ever read and written by its own account, so nothing in
# here wants a group or a world bit. A bind mount from the host has to be owned
# by this id to be writable at all.
RUN useradd --system --uid 10001 --user-group --no-create-home manapds \
    && install --directory --owner manapds --group manapds --mode 700 /data
VOLUME /data
USER manapds
ENV PDS_DATA_DIRECTORY=/data
EXPOSE 2583

# Split so that `docker run <image> secret` reaches the same binary without
# having to know where it lives.
ENTRYPOINT ["manapds"]
CMD ["serve"]

LABEL org.opencontainers.image.source=https://github.com/eth0net/manapds
LABEL org.opencontainers.image.description="A minimal atproto Personal Data Server, on SQLite."
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
