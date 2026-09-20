# manapds

A small [atproto](https://atproto.com) Personal Data Server, written in Rust on
SQLite. It hosts accounts, keeps each one's repository, and issues the OAuth
tokens a browser client writes with.

Built to sign up and serve [manaweb](https://github.com/eth0net/manaweb)
users, and to be a second implementation to test against — the reference server
is the thing almost everyone runs, and a client tested against only one server
has untested assumptions rather than none.

## Status

Early. Repositories, storage and the request surface are built; nothing here
hosts an account yet. [`docs/roadmap.md`](docs/roadmap.md) is the order of work
and [`docs/`](docs/architecture.md) carries the reasoning.

## Running it

Rust stable, and nothing else — no runtime, no database server.

```sh
PDS_JWT_SECRET=$(cargo run -- secret) cargo run -- serve
```

Or as the container, which is how a server that is not this one gets run.
Nothing is published yet, so the image is still built here:

```sh
docker build --tag manapds .
docker run --rm manapds secret
docker run --env-file pds.env --volume manapds:/data --publish 2583:2583 manapds
```

Configuration is environment variables under the same names the reference
server uses, so an existing `pds.env` works unedited. The secret sessions are
signed under is the one variable with no default, since inventing one at each
startup would sign every client out on every restart. It has to be at least 24
characters, and changing it later signs everyone out once, so put the generated
one somewhere before it scrolls away.

## Layout

```
manapds/
  docs/                  the reasoning behind each decision
  src/                   the server
  tests/                 interop vectors, and the checks that aren't unit tests
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
