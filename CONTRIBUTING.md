# Contributing

Early days: more design than code. The useful contribution right now is a
second opinion on anything in [`docs/`](docs/roadmap.md) that reads as a wrong
call, and later, a repository this server builds that some other implementation
refuses.

## Getting set up

Rust, stable, 2024 edition. The MSRV is in `Cargo.toml` and CI enforces it.

```sh
git clone https://github.com/eth0net/manapds
cd manapds
prek install
cargo test
```

[prek](https://github.com/j178/prek) runs what CI runs — `cargo fmt`, a
warning-free `cargo clippy --all-targets`, `cargo test`, `typos` and the
sign-off check — on commit and push, so a red build costs no round trip. The
compiling hooks wait for push; the rest run on commit. CI itself also runs on
macOS and Windows.

[just](https://github.com/casey/just) holds the workflow: `just check` runs
every check CI does on one machine, and `just --list` shows the rest. It can't
cover the OS matrix or the MSRV job.

Spelling is American, because the vocabulary already is: `color`, `license`,
`serialize`. `typos` enforces it, and `typos.toml` says what it skips.

Reasoning lives in `docs/`, one file per subject, and a comment carries the one
fact the code can't. A comment that restates a paragraph from a doc is the
failure case — the two drift apart silently — and `cargo test` fails on any
eight words the two share.

## Commits

Conventional commits. The subject carries it; explain *why* in the body only
when the diff doesn't. One logical change per commit.

Commits need a [DCO](https://developercertificate.org) sign-off, which
`git commit -s` adds:

```
Signed-off-by: Your Name <you@example.com>
```

It certifies you wrote the contribution, or that it came from somewhere
compatibly licensed and you have the right to submit it. No CLA, no copyright
assignment. Git has no config for it, so `prek install` adds a `commit-msg`
check; merge commits are exempt.

## Attribution

Developed with [Claude Code](https://claude.com/claude-code).

## Licensing

Contributions are dual licensed under MIT and Apache-2.0, matching the project.
By submitting a pull request you agree to that.
