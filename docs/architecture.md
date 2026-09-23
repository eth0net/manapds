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

## Talking out

The server calls out for two things: registering an identifier at the PLC
directory, and later resolving one somebody else minted. Both go through hyper
with rustls on top, rather than a client library — the connection stack is
already linked in for the server side, so what a higher-level client would add
is a second copy of it.

The certificate authorities are the compiled-in Mozilla set. A server behind a
proxy that reissues certificates therefore has nothing to point at, which is
the cost of not reading a store the container would have to be given.

Signing up writes every local thing first and registers the identifier last,
bar the log entries, which wait for the directory to answer. That order is
chosen rather than inherited: the reference registers first and tombstones what
it registered if the rest fails, and until this server can write a tombstone,
undoing rows is the only undo it has. Against a refusal that undo is complete —
nothing is left and the name is free again — and it runs on a dropped request
too, since hanging up is the likeliest way out of a signup.

It stops where the operation goes out, and what happens there turns on whether
the directory said anything. A refusal is something said: nothing landed, the
rows come out and the name is free again. Silence is not, and neither is a
request the caller dropped while it was in flight, so under both the account
stays — deleting one the network can already resolve cannot be undone. A name
nobody holds can be taken again; an identity left behind cannot be reclaimed.
Nothing collects what that leaves. Doing so means asking the directory about
an account that never heard back, and freeing it only where the directory has
nothing under it — which is what a caller retrying the same name is waiting on.
That is one account on a bad day and every account during an outage, so it is
the collection that decides how much an outage costs rather than the keeping.

What no ordering covers is an answer lost on the way back, which a timeout
cannot be told apart from. So the directory is asked what is filed under the
identifier before the operation goes a second time, and again afterwards: an
identifier is a hash of the operation that mints it, so a document filed there
naming it back is that operation and no other, and a second attempt refused as
a duplicate says the same in the shape of a refusal. Half the budget goes to
the first attempt and the rest is split three ways, because an attempt that
spent everything is the one most worth asking about.

A read nobody answers settles nothing by itself. What settles it then is
whether the operation ever got onto a connection: one that did not cannot be
in there, and one that did has to be treated as though it were.

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

The data directory needs a POSIX filesystem. An account's files sit under its
DID, a DID has colons in it, and Windows will not have a colon in a path
component — so this runs where the reference runs and not on Windows, which
could not have written that layout either.

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

One is not the reference's. `PDS_RESERVED_HANDLES` takes a comma-separated
list, and every name in it joins the built-in list rather than standing in for
it, so setting it can only ever refuse more. A server that leaves it alone
hands out precisely what upstream would, which is why there is no matching way
to un-reserve a name: an operator who could would be running something that
answers a signup differently while claiming to be the same server.

Each entry is the label before a service domain, not a whole handle, and one
carrying a dot or a space stops the server rather than being skipped: both are
ways of writing something that looks like a list and holds nothing back. Those
are the only shapes refused, and not because they are the only ones that cannot
match. The built-in list carries names the length floor and the character set
already put out of reach — `ad` is shorter than the three characters a signup
needs, `contact_us` has an underscore no label may hold — so refusing every
entry that cannot match would throw out names upstream ships.
