# Porting

Which version of the reference this server was written against, and how to
tell what has changed since.

## The pin

    @atproto/pds@0.5.32

Every behavior here was read at that tag. Move it in the same commit as the
catch-up work, never ahead of it — a pin that runs early is worse than none,
because it claims ground nobody checked.

## Seeing what moved

Upstream history answers this better than any summary kept here:

    git log @atproto/pds@0.5.32..@atproto/pds@<newer> -- \
      packages/pds/src packages/repo/src packages/oauth-provider/src lexicons/

Read the commits rather than the releases. A patch version is usually nothing
but dependency bumps, and `packages/pds/CHANGELOG.md` is best used as an index
into the pull requests.

Copy the interop files in `tests/fixtures` again while you are there. A vector
that upstream changed is the cheapest possible notice that a rule did too.

What is already built is deliberately not tracked here. [`roadmap.md`](roadmap.md)
holds the plan and the test suite holds the truth; a third list would be the
one that goes quietly wrong.

## Divergences

Places where both servers do the thing and do it differently on purpose. This
is the part a catch-up has to re-argue, so each entry says what the difference
buys.

### AT-URIs parse strictly or not at all

A trailing slash, a query string, and a record key no repository could hold
are all refused. Upstream still accepts them through entry points it has
marked deprecated. Nothing current emits any of the three, so refusing them
costs a caller that was already living on borrowed time, and it buys an
`AtUri` that prints back exactly what it parsed.

### The OAuth tables exist before the OAuth server does

Nothing here serves OAuth yet, but the account database is migrated all the way
to 007 regardless. A database half-migrated is one neither server can open: the
reference would refuse to run migrations it thinks are applied, and this one
would refuse a schema it does not recognize. The tables cost a few hundred bytes
and being the shape the other server expects is the whole point of matching it.

### Commits are version 3 and parsed all the way down

The DID and the `rev` in a stored commit become a `Did` and a `Tid` as the
block is read, so a commit naming neither is caught where it is read instead
of somewhere later that assumed. Version 2 is rejected outright where upstream
still lifts it; every repository old enough to hold one was migrated years
before this server existed.

### CAR files name one root and prove every block

Upstream takes any number of roots and will skip the hash check on request.
Here a file has exactly one root and each block is hashed against the CID it
arrived under, which is what stops an import quietly installing a block that
is not what it claims.

### TIDs use the whole clock id

Ten bits are reserved for it and upstream randomizes five of them. Filling the
field costs nothing and pushes out the point where two servers minting in the
same microsecond land on the same TID.

### SQLite is left to do its own waiting

Upstream opens every connection with no busy timeout and retries around the
lock in its own loop. Here the timeout is set on the connection and SQLite
blocks on it. Both wait for the same writer to finish, but one of them is a
retry loop that has to be right about which errors are worth retrying.

### A signing key is readable by nobody else

Upstream writes the key file at whatever the umask allows, which on a normal
system means everyone on the box can read it. Here it is set to owner-only
after the write. An account's key is the one thing that cannot be reissued
without a PLC operation, so the cost of being strict is a permissions error on
a badly restored backup and the cost of not being is the account.
