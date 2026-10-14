# manapds

A small [atproto](https://atproto.com) Personal Data Server, written in Rust on
SQLite. It hosts accounts, keeps each one's repository, and serves what a
relay or another server comes to read.

Built to sign up and serve [manaweb](https://github.com/eth0net/manaweb)
users, and to be a second implementation to test against — the reference server
is the thing almost everyone runs, and a client tested against only one server
has untested assumptions rather than none.

## Status

Early. An account can be created against the real PLC directory, signed in to,
resolved by handle, and written to: records go in and come back out, and blobs
with them. App passwords work, and a relay or another server can read the
repository back. There is no OAuth yet and nothing is broadcast to the
network.
[`docs/roadmap.md`](docs/roadmap.md) is the order of work and
[`docs/`](docs/architecture.md) carries the reasoning.

## Running it

Rust stable, and nothing else — no runtime, no database server.

```sh
export PDS_JWT_SECRET=$(cargo run -- secret)
export PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX=$(cargo run -- rotation-key)
export PDS_ADMIN_PASSWORD=whatever-you-like
export PDS_INVITE_REQUIRED=false
cargo run -- serve
```

An invite is required by default, as it is on the reference server, and the
line above is what turns that off for a server you are only trying out.
`createInviteCode` mints one against the admin password where you want to keep
it on. `cargo run -- reconcile` is the other command: it walks each account's
blob files against its rows, which `serve` does for itself after an unclean
stop.

Or as the container, which is how a server that is not this one gets run.
`compose.yaml` holds the same thing for `docker compose up -d`:

```sh
docker run --rm ghcr.io/eth0net/manapds:edge secret
docker run --rm ghcr.io/eth0net/manapds:edge rotation-key
docker run --env-file pds.env --volume manapds:/data --publish 2583:2583 \
  ghcr.io/eth0net/manapds:edge
```

Images are `linux/amd64` and `linux/arm64`. A release is `X.Y.Z`, `X.Y` and
`latest`, and `edge` is the tip of main; those are the four worth pinning.
Nothing updates itself — [watchtower's fork](https://github.com/nicholas-fedor/watchtower)
or [diun](https://github.com/crazy-max/diun) will do it or tell you about it,
and following `X.Y` is the point at which that is a safe thing to leave running
overnight.

Configuration is environment variables under the same names the reference
server uses, so an existing `pds.env` works unedited. Two have no counterpart
there at all: `PDS_BLOB_UNCLAIMED_HOURS` and `PDS_RESERVED_HANDLES`. Three
have no default and
none of them can be invented at startup: `PDS_JWT_SECRET` signs sessions, so a
new one each time would sign every client out; `PDS_ADMIN_PASSWORD` is what the
admin endpoints check; and `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` is the
only key that can ever update the identity of an account created here, so
losing it strands every one of them. The secret has to be at least 24
characters. Keep all three somewhere before they scroll away.

## Layout

```
manapds/
  docs/                  the reasoning behind each decision
  src/                   the server
  tests/                 interop vectors, and the checks that aren't unit tests
  tools/                 fixtures generated against the reference
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a DCO sign-off
(`git commit -s`); there's no CLA.

## License

`MIT OR Apache-2.0`, at your option — [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE). It matches the rest of the atproto server
ecosystem, which is what makes a piece of this worth lifting into something
else.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
