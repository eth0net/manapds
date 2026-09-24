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

`commit/` is a fixture upstream does not publish: a signed commit block, built
by `@ipld/dag-cbor` and `@atproto/crypto` rather than by anything in this
repository. Both sides sign deterministically, so the whole block matches and
not merely its shape. Regenerating it means encoding
`{did, version, data, rev, prev}`, signing that with the K-256 scalar from
`crypto/`, encoding the result and taking a CIDv1 over it with the dag-cbor
codec.

`plc/` is another: a genesis operation built by `@did-plc/lib`, from the K-256
scalar in `crypto/` and a second scalar the file carries so the rotation key is
reproducible too, and the tombstone that retires it. Regenerating them means
calling `createOp` with those two keys, the handle and the endpoint recorded
beside them, then `tombstoneOp` over the CID of what that returns.

`password/` is node's `crypto.scrypt` with every parameter left at its
default, which is the one thing about how the reference stores a password that
its source does not state. Regenerating it means hashing the two passwords in
the file under the salts beside them, one of which is the first sixteen bytes
of the sha-256 of a DID.

`schema/` is what each of the reference's four databases looks like once its
own migrator has run, plus `account-004.sql`, which is where that migrator
stops one short of the migration that moves data rather than only tables: `sqlite3 <db> .schema`, sorted, with `sqlite_sequence`
dropped because SQLite writes that one itself. Regenerating it means running
those migrations, which needs `kysely` and `better-sqlite3` and a copy of
`packages/pds/src/*/db/migrations/`; the account set also imports two runtime
values that only a data-cleanup `where` clause uses, so they can be stubbed.

Copied at `7a23156ef`. Check that against the pin in [`docs/porting.md`](../../docs/porting.md)
before trusting any of this to be current: a fixture that has quietly gone
stale is the one thing here that cannot fail loudly.

Those files are under the same `MIT OR Apache-2.0` terms as this repository.

[atproto]: https://github.com/bluesky-social/atproto
