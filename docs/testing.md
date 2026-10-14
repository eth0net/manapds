# Testing

Where a test goes, and what the suite still owes.

## Where a test goes

Rust gives two places and they are not interchangeable. A `#[cfg(test)] mod
tests` compiles inside the crate and can reach private items; a file under
`tests/` compiles as its own crate and sees only what is public. So the
question is never style. It is what the test needs to name.

Anything that is a function of its inputs is tested beside itself. A rule like
the bytes a record key may hold lives in a private function, and a test that
cannot name that function has to approximate it through whatever public path
happens to run it — which is how a suite ends up asserting on something near
the code instead of the code.

`tests/` is for where the layers meet: a handler against a store, a store
against its files, a signup against the directory it registers with. Those
genuinely need the stack, and the cost of standing it up buys something.

Doc tests are the third place. They are the only kind that cannot go stale
against the signature above them, because they are compiled, and they are worth
adding where an example says it better than a sentence would.

## What the shape is worth

Four tests here planned SQL that had been pasted into the test file beside the
code that built its own. Reverting the fix they existed to guard left every one
of them green. The pull was not laziness: the builders were `pub(crate)`, so
from `tests/` a copy was the only thing within reach.

That is the failure the arrangement is against. A test that cannot reach the
thing it is about will find something adjacent and assert on that instead, and
it will look exactly like a real test while it does.

## What is out of place

`tests/syntax.rs`, `tests/crypto.rs`, `tests/car.rs` and `tests/config.rs` are
all parsing and encoding, pure in both directions, and all sit outside the
crate. They belong beside what they check, where they can also name the private
helpers that hold the actual rules.

`tests/xrpc.rs` is two suites in one file. The budget arithmetic and the scope
and authorization logic are pure; the router tests are not. Separating them is
worth more than moving either.

`tests/repo.rs` is the judgment call. The MST is pure logic, but its tests
need a store to hand, so they are unit tests with a fixture rather than
integration tests. Leave it until the clear cases are done.

`tests/store.rs`, `tests/records.rs` and `tests/account.rs` have each grown to
cover several subjects at once, which makes a failure name a file rather than a
place. Cargo builds `tests/<name>/main.rs` as one binary, so a directory with a
module per subject splits the reading without splitting the link.

## What nothing tests

A cursor added to a query as an extra comparison, rather than put in place of a
bound, produces a plan identical to the correct one. The index is searched
either way; only the number of rows read differs. Nothing in a plan shows it
and nothing in the suite catches it — what prevents it today is the shape of
the builder, which has one bound per end and no room for a third.

The technique that would catch it is already here. `tests/export.rs` installs a
counting allocator, takes a binary to itself so the measurement is undisturbed,
and asserts a relationship rather than a number: what a download holds does not
grow with the repository. A number would be a machine's number and would rot.

The same shape fits paging, and need not be timed. SQLite will call a progress
handler every so many instructions it runs, which counts work done rather than
time taken, so a deep page and a shallow one can be compared without asking how
fast the machine is. `rusqlite` exposes it behind a feature carrying no
dependencies, which a dev-dependency can turn on without the release build ever
seeing it.

## Order

1. Move the four pure suites in. Smallest, and it demonstrates the shape.
2. Split `xrpc.rs` by what its halves actually test.
3. Split the three oversized files by subject.
4. Measure paging cost, once there is appetite for a fourth kind of test.

One and three are independent of each other and of everything else.
