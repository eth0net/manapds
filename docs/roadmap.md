# Roadmap

The target for v0 is an account on this server signing in to
[manaweb](https://github.com/eth0net/manaweb) through OAuth and writing records
to its own repository. Everything below is ordered by what the next step needs,
not by what is interesting.

## Getting there

1. **Syntax and crypto.** DIDs, handles, NSIDs, AT-URIs, record keys, TIDs.
   Key generation, signing, verification, `did:key` encoding. Checked against
   atproto's interop vectors.
2. **The repository layer.** dag-cbor, CIDs, the MST, commits, CAR reading and
   writing. See [`repo.md`](repo.md).
3. **Storage.** The three databases and their migrations, plus blobs on disk,
   arranged the way the reference arranges them — see
   [Taking over a running server](#taking-over-a-running-server) for why that
   is a constraint rather than a convenience.
4. **The XRPC skeleton.** Routing, the error shape, request authentication,
   rate limits.
5. **Accounts and sessions.** `createAccount` with a real `did:plc` registered
   at the directory, handle resolution, password and app-password sessions,
   refresh tokens.
6. **Records.** `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`,
   `getRecord`, `listRecords`, `describeRepo`, `uploadBlob`, `getBlob`.
7. **OAuth.** The authorization server. See [`oauth.md`](oauth.md).
8. **Sync reads.** `getRepo`, `getLatestCommit`, `getRecord`, `getBlocks`,
   `listRepos`, `getRepoStatus` — what a relay or another server fetches,
   without yet holding a socket open.

The first tag waits for step 6. That is the earliest point another person can
start this and have a client sign in and read something back, and a version
number before then would be marking a library nobody can run. The README has to
say how to start it by the same commit, or the tag claims more than it delivers.

## The image

An operator runs this as a container, so the image is part of the work rather
than packaging bolted on at the end, and `serve` and `secret` are both shaped
around an entrypoint that takes a command. Both architectures are built on
their own runner and published to ghcr, `edge` from main and the three release
names from a `v` tag — the second half of which nothing has exercised, since
the first tag waits for step 6.

Moving an account belongs on that command line too. Both halves are promised
already, the endpoints below and the tool that reads a rewritten directory back,
and neither is something a running server can be asked for — one of them has to
open the files while nothing else is holding them.

Three things are owed to steps that have not started. `getRepo` may not be
served before the per-method budgets exist, or the one exemption in the global
budget becomes a hole. `createAccount` needs `reserved_keys/` and the `did-op`
file beside an actor's key, since both are part of reading a directory the
reference left behind. And whatever first verifies a service token has to allow
a malleable signature on that path alone — upstream issues them, account
commits stay strict, and conflating the two would loosen the wrong one.

Rate limits land with step 6 rather than later, at the reference's numbers:
`applyWrites` capped at 200 operations, and the hourly and daily point budgets
that decide how long a large import takes. An importer tuned against limits
this server does not enforce would fall over on any other one.

## After v0

Three things the reference server doesn't do, wanted for the PDS manaweb signs
users up on. Each is built so that upstream adopting its own version costs us a
deletion rather than an unpicking: defaults stay the reference's defaults, and
a server that configures none of this behaves exactly as it did.

### Rate limits worth configuring

Today the reference offers one switch and compiled-in numbers. The budgets
themselves want to be settable, because the honest duration of a long import is
a number this server chooses rather than inherits.

Two extensions past that, both earning their keep here:

- **Per scope.** A token holding one granular `repo:` scope is a different risk
  from one holding `transition:generic`, so they have no reason to draw on the
  same budget.
- **Per account.** Raising a limit is how a donor or an admin gets the headroom
  they paid for or need, and lowering one is the only honest way to test what a
  client does when it runs out.

### Structured configuration

Environment variables are a flat map of strings, and per-scope budgets are a
tree, so the two above need a file. TOML, read from the data directory.

The environment still wins where both speak, so a deployment that already sets
something keeps controlling it and a file dropped in beside it can't silently
take over. The file's job is to say what the environment has no way to express.

### Taking over a running server

Stop the reference server, start this one on the same directory, and have
nothing notice: no export, no PLC operation, no client re-authenticating, and
no configuration written. Porting to a mana-shaped configuration is then a
separate step somebody chooses, not a toll on the way in.

That is what makes the on-disk layout a constraint. `account.sqlite`,
`sequencer.sqlite`, `did_cache.sqlite`, the sharded actor directories with
their raw `key` files, and `blocks/` all have to be read as they are, which
means adopting the reference's schema rather than one merely shaped like it.

The sequencer is the sharp edge: its numbers have to continue rather than
restart, or every consumer decides it missed something and refetches.

Staying in that format is the default afterwards, not only on the way in. A
structure of our own would have to earn the divergence, and the first thing to
try is translating at the serialization boundary — read and write what is
already there, hold it differently in memory — rather than rewriting the files.

If something ever does have to be written differently, that rewrite is an
admin's explicit choice, shaped like the configuration port, and it ships with
the tool that converts back.

## Not in v0

- **The firehose.** `subscribeRepos` and the sequencer behind it. The event log
  is written from step 3 so that turning it on later is a reader rather than a
  migration, but nothing consumes it yet and the first accounts here do not
  need to be crawled.
- **Account migration.** `importRepo`, `getServiceAuth`, PLC operation signing,
  activation and deactivation.
- **AppView proxying.** Serving `app.bsky.*` by forwarding to Bluesky, which is
  what makes the official client work against a PDS. Cheap to add and useless
  until wanted.
- **Email.** Confirmation, password reset, and everything that needs SMTP.
- **Moderation.** Reports, takedowns, labelers.
