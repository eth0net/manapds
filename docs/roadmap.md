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
3. **Storage.** The three databases and their migrations, plus blobs on disk.
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

Rate limits land with step 6 rather than later, at the reference's numbers:
`applyWrites` capped at 200 operations, and the hourly and daily point budgets
that decide how long a large import takes. An importer tuned against limits
this server does not enforce would fall over on any other one.

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
