# The whole workflow, so `just --list` beats remembering which tool each step
# wants. Every recipe is a plain command underneath.

[private]
default:
    @just --list

# every check CI runs that can run on one machine — not the OS matrix or MSRV
[group('checks')]
check: fmt-check lint test spell deny

# format in place
[group('checks')]
fmt:
    cargo fmt --all

[private]
fmt-check:
    cargo fmt --all --check

# clippy, warnings denied as CI denies them
[group('checks')]
lint:
    cargo clippy --locked --all-targets --all-features -- -D warnings

# the test suite, optionally filtered: `just test mst`
[group('checks')]
test filter="":
    cargo test --locked --all-targets {{ filter }}

# spelling, at the version prek pins (needs prek)
[group('checks')]
spell:
    prek run --all-files typos

# advisories, licenses, duplicate versions and crate sources (needs cargo-deny)
[group('checks')]
deny:
    cargo deny check

# run the server, reading configuration from the environment
[group('dev')]
run:
    cargo run
