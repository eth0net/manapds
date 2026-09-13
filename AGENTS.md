# manapds

An atproto PDS in Rust on SQLite, built so that
[manaweb](https://github.com/eth0net/manaweb) has somewhere of its own to sign
users up, and so its client has a second implementation to be tested against.
Minimal by intent: the reference server does a great deal this one will not.

`docs/` carries the reasoning, one file per subject — `roadmap.md` for the
order of work and what v0 leaves out, `architecture.md` for the process and
storage shape, `repo.md` for the MST and the crypto, `oauth.md` for the
authorization server. This file is the orientation for picking the project back
up; read the doc before changing anything it covers.

## Shape

- One binary. axum, `/xrpc/<nsid>`, SQLite, blobs on disk.
- A SQLite file per account, plus one for accounts and one for the event log.
- Handlers stay thin; the repository and account layers hold the logic and are
  testable without a socket.
- Compatibility is judged against the reference implementation's behavior, not
  against the specs alone — the specs leave out limits that clients depend on.
  `bluesky-social/atproto` (`packages/pds`) is the source of truth when the two
  disagree, and `blacksky-algorithms/rsky` (`rsky-pds`) is a second reading,
  not an authority.

## Prose

Reasoning lives in `docs/`; a comment carries the one fact the code can't.
Write it short the first time rather than trimming later — one line is usually
enough and two is a lot. That cap is on `//` notes; `///` and `//!` are the
cargo docs and earn more room.

`cargo test` fails on any eight words shared between a comment and a doc, or
between two docs. One fact, one owner, a pointer from anywhere else.

Deferred work is marked at the line it affects: `todo(<thing>)` waits on
something that doesn't exist yet, `todo(eth0net)` names a person, and a bare
`todo:` is a fix nobody owns.

Spelling is American, enforced by `typos`.

## Conventions

Conventional commits, DCO sign-off (`git commit -s`), one logical change per
commit. `prek install` enforces both. Never `git add -A` — read `git status`
and stage named paths.
