# Fixtures

Test vectors copied from [`bluesky-social/atproto`][atproto], compared byte for
byte and so left exactly as they arrive. Refresh them by copying again rather
than by editing.

`syntax/` is `interop-test-files/syntax/`. A line starting with `#` is a
comment, and the reference test harness drops it — which quietly excludes one
AT-URI vector that begins with a fragment.

`crypto/` is `interop-test-files/crypto/`. The two `w3c_didkey_*` files write
the private scalar differently: hex for K-256, base58 for P-256.

`car/` is `packages/repo/tests/`, where a CAR file sits beside the blocks it
was written from.

`mst/` is `packages/repo/tests/commit-proof-fixtures.json`. Upstream reads it
for covering proofs, which nothing here serves; the roots before and after each
commit are pinned regardless, and two of the six apply an add and a delete
together, which is the only published vector that reaches a merge and a split
inside one commit.

`schema/` is what each of the reference's four databases looks like once its
own migrator has run: `sqlite3 <db> .schema`, sorted, with `sqlite_sequence`
dropped because SQLite writes that one itself. Regenerating it means running
those migrations, which needs `kysely` and `better-sqlite3` and a copy of
`packages/pds/src/*/db/migrations/`; the account set also imports two runtime
values that only a data-cleanup `where` clause uses, so they can be stubbed.

Copied at `7a23156ef`. Check that against the pin in [`docs/porting.md`](../../docs/porting.md)
before trusting any of this to be current: a fixture that has quietly gone
stale is the one thing here that cannot fail loudly.

Those files are under the same `MIT OR Apache-2.0` terms as this repository.

[atproto]: https://github.com/bluesky-social/atproto
