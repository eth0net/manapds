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

Those files are under the same `MIT OR Apache-2.0` terms as this repository.

[atproto]: https://github.com/bluesky-social/atproto
