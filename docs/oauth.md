# OAuth

The whole point of v0, and the largest piece of it. A browser client holds no
secret and talks to this server directly, so every write manaweb makes arrives
under an OAuth token this server issued — there is no path to the data that
skips it.

Nothing off the shelf implements it. The reference is TypeScript, and the one
Rust implementation is unpublished and written against another server's
internals, so this is written here.

## What has to be built

- **The two metadata documents**, at
  `/.well-known/oauth-authorization-server` and
  `/.well-known/oauth-protected-resource`, plus a JWKS endpoint.
- **Pushed authorization requests.** Clients start at PAR, not at the
  authorization endpoint, and a request naming a scope the client's own
  metadata document does not declare is refused there.
- **Client metadata fetching.** A public client identifies itself by the URL of
  a JSON document, which this server fetches, validates, and holds the request
  against. `client_id` has to equal the URL it came from.
- **PKCE**, required, S256.
- **DPoP**, with server-issued nonces. Every token is bound to a key the client
  proves it holds, so a stolen token is not enough.
- **The authorization and consent screens.** Server-rendered HTML — sign in,
  pick an account, see what is being asked for, approve. The one part of this
  server a person looks at.
- **The token endpoint**, issuing short-lived access tokens and rotating
  refresh tokens.
- **Scopes.** `atproto` plus the granular `repo:`, `rpc:` and `blob:` family,
  and the transitional scopes for clients that predate them. A `repo:` value is
  either `*` or one exact NSID, and the enumeration is what lets a collection
  tracker ask for the collections it writes instead of the whole repository.

The scope granted is what the token response says, not what the request asked
for, and a client that assumes otherwise fails on its first write. So the
grant is recorded per token and enforced on every call.

## Loopback clients

A client at `http://localhost` registers no document: the server builds one
from the `client_id`, whose query parameters carry the redirect URIs and the
scope. Development depends on it, and the spec leaves it optional for the
server, so it is on here and stays on.
