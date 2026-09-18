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

### The foreign keys the schema declares are enforced

SQLite leaves them off per connection and the reference sets no pragma for
them, but it opens its databases through better-sqlite3, which turns them on
as it connects. So upstream's cascades fire and a schema matched byte for byte
would still have behaved differently here. The pragma goes on at open for the
same reason the schema is copied: it is the shape the other server left the
data in.

### SQLite is left to do its own waiting

Upstream opens every connection with no busy timeout and retries around the
lock in its own loop. Here the timeout is set on the connection and SQLite
blocks on it. Both wait for the same writer to finish, but one of them is a
retry loop that has to be right about which errors are worth retrying.

### A signing key is readable by nobody else

Upstream writes the key file at whatever the umask allows, which on a normal
system means everyone on the box can read it. Here the mode is set as the file
is made, the write refuses a path already holding one, and every directory
under the data directory is made owner-only. An account's key is the one thing
that cannot be reissued without a PLC operation, so the cost of being strict is
a permissions error on a badly restored backup and the cost of not being is the
account.

### An XRPC path is an NSID or it is nothing

Upstream checks the path against a hand-written scan that accepts a two-part
name, so `/xrpc/com.example` reaches the method table and comes back 501. Here
the same path is parsed as an NSID and comes back 400. Both are refusals and no
client depends on which; parsing it once means the handler that eventually
serves it is handed a name rather than a string.

### Nothing shared is kept outside the process

Upstream can be pointed at Redis, and where it is, two instances agree: they
draw rate limit budgets from one pool and catch a proof replayed against
either. Without one it falls back to memory, which is all this server offers.

Budgets, and the short-lived `jti` and code-challenge checks the authorization
server makes, are the whole of what Redis holds for it — nothing durable — so
the cost falls entirely on running a second instance, where each would allow a
full budget and a proof spent on one would be fresh to the other. The limits to
configure are the ones a single instance should allow.

### Only a private address may name someone else

Both servers read `X-Forwarded-For` only from a caller that could not have come
from the internet. Upstream also trusts a configured list of public addresses,
for the entryway in front of a hosted deployment. Nothing here runs behind an
entryway, so the list is the private ranges and loopback, and a proxy elsewhere
would have to be reached over a private network to be believed.

Carrier-grade NAT counts here and does not upstream, and an address arriving as
an IPv4-mapped IPv6 one is read as the address it maps to. Both are what a
hosting front-end actually turns up as, and missing either puts every caller
behind it on one budget.

### A stored tree is refused rather than walked

Upstream follows whatever a node says its children are: no depth limit, and no
record of where the walk has already been. Here a traversal counts its levels
and the nodes it has read, and refuses a tree deeper than a key's hash could
put it or one that reaches the same node twice.

Neither can happen in a tree built by the rules, and both are a few lines to
build by hand. The second is the one that matters: nodes pointing at each other
double the walk per level, so a few kilobytes unfold into millions of leaves,
which no limit on the size of a file can catch. The cost is a ceiling of 256
levels on a rule that cannot reach past 128.
