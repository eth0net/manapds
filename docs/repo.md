# Repositories

An account's data is a Merkle search tree of records, committed under a
signature, addressed by CID, and shipped as a CAR file. That structure is the
protocol — a relay verifies it, another server rebuilds from it, and getting it
subtly wrong produces a repository nothing else will accept.

## Written here, not borrowed

`rsky-repo` is Apache-2.0 on crates.io and would save the work. It pulls
`rsky-lexicon`, `rsky-common`, `anyhow` and the C `libsecp256k1` bindings with
it, sits at 0.0.x, and is maintained against someone else's server. The tree
we would inherit is larger than the code it replaces.

So: `ipld-core` for the data model, `serde_ipld_dagcbor` for the encoding,
`cid` for addressing, and the tree itself here. The MST is a few hundred lines
against a specification that pins every detail, and atproto publishes interop
vectors, so "did we get it right" is a test rather than a judgment call.

## The pieces

- **dag-cbor** for every block. Canonical encoding, so the same data always
  produces the same CID.
- **CIDv1**, dag-cbor codec, sha-256 multihash.
- **The MST** keys on `<collection>/<rkey>`, with a node's depth set by the
  count of leading zero bits in the sha-256 of its key. That rule is what makes
  the tree deterministic: two servers holding the same records must produce the
  same root, or nothing can diff them.
- **A commit** carries the DID, the tree root, a `rev` (a TID), the previous
  commit's CID, and a signature over the dag-cbor of the rest.
- **CAR v1** for export and for the firehose, carrying the blocks a consumer
  needs and nothing more.

## Crypto

`k256` and `p256`, both pure Rust. atproto wants compact 64-byte signatures
with a low-S value — DER and high-S are both rejected by verifiers — and public
keys travel as `did:key` multibase strings with a compressed point.

secp256k1 is what account signing keys use. P-256 is accepted on the verifying
side because the protocol allows it and other implementations issue it.

Pure Rust over the C library so the build stays a build: no `cc`, no system
library, and a static musl binary remains possible.
