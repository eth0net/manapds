# Architecture

One binary, one axum router, SQLite underneath. Nothing else runs beside it —
no Redis, no Postgres, no object store, no mail service.

## The request surface

Everything atproto is XRPC: `GET /xrpc/<nsid>` for a lexicon query, `POST` for
a procedure, errors as `{"error": "...", "message": "..."}`. The OAuth
endpoints and the two well-known documents are ordinary HTTP, because the
OAuth spec says where they live and it is not under `/xrpc/`.

A lexicon declares whether a method is a query or a procedure, so the router
holds each one to the verb that implies and answers the wrong verb with the
right one named. A path under `/xrpc/` that no route claims is a 501 rather
than a 404: the method exists somewhere, just not here.

Handlers stay thin. A handler validates input, names the account it acts for,
and calls into the store; the interesting code is the repository layer and the
account layer, both testable without a socket.

## Budgets

Every caller gets a fixed number of points per window, counted in this process
and keyed by address. Off unless asked for, because a server behind a proxy is
usually already counted there and one counting twice is worse than one counting
nowhere.

Whoever runs the server can be let past, by a key in a header or by address.
That is what makes a bulk import possible without turning the budgets off for
everyone.

Every repository read is blocking SQLite, so a handler does the whole
operation inside one blocking task rather than holding a store across an await.
That is why the store trait needs no `Sync` bound: an account's connection is
moved into the task that uses it and moved back, never shared.

## Storage is split three ways

- **One SQLite file per account**, holding that account's repository blocks,
  record index, preferences and blob metadata.
- **One account database**, holding identities, handles, passwords, app
  passwords, tokens, invite codes and OAuth state.
- **One sequencer database**, holding the outgoing event log.

SQLite takes one writer at a time, so a single file would queue every
account's writes behind whichever account is busiest — and the workload this
server exists for is a bulk import running for hours. Per-account files also
make exporting or deleting an account a file operation rather than a
transaction that has to find every row.

The reference implementation splits the same way, so the shapes are worth
reading across where a table is unclear.

Blobs are files on disk, addressed by CID under a per-account directory. A
blob is immutable and content-addressed, so there is nothing a database gives
it but overhead.

## Keys

Two kinds, and conflating them is the way to lose an account permanently.

- **The rotation key** signs PLC operations. One per server, shared by every
  account it creates, and the only thing that can ever update those DID
  documents. It is configuration, it belongs in a password manager, and losing
  it strands every account anchored to it.
- **A signing key** signs one account's commits. One per account, generated at
  signup, stored beside the account, and replaceable by a PLC operation — the
  old key stays in the audit log so old commits still verify.
- **The token secret** signs sessions. One per server, symmetric, and nothing
  outside this process ever needs it. Changing it signs everyone out, which is
  the only revocation that reaches every client at once.

## Configuration

Environment variables, named as the reference names them — `PDS_HOSTNAME`,
`PDS_DATA_DIRECTORY`, `PDS_JWT_SECRET`, `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX`
and the rest. The names are the compatibility surface: `bsky-pds`'s compose
file, its `pdsadmin` scripts and every self-hosting guide already use them, so
matching them costs nothing and buys the whole existing operational toolkit.

Variables for features this server does not have are read and ignored rather
than rejected, so a reference `pds.env` starts it unedited.
