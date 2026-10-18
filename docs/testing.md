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

Which layer a test belongs to is the one that can break it, not the one it
tells a story about. A repository written to a CAR file and read back names a
repository in every line and proves nothing about one: the structure is only
the payload, and nothing but the framing around it can fail. It goes with the
framing.

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

`tests/config.rs` reads as a pure suite and is not one. It sets and clears
process environment variables, which no mutex inside one file can hold back
from the other tests in its binary, and doing that unsafely is only sound
because nothing else shares the process. A binary to itself is what keeps that
true, so it stays one.

## Moving one

Splitting a file is a move, not an edit, and what makes that worth saying is
how quietly it goes wrong. An attribute left behind turns a test into an unused
function, which is a warning rather than a failure; an item the move does not
recognize, a type alias between two functions, goes missing entirely. Counting
the tests that run catches the first and compiling catches the second. Comparing
the names catches neither, because the names are all still there.

## What a measurement is worth

Two queries can share a plan and read a thousand times the rows. A cursor
added as an extra comparison, rather than put in place of a bound, searches the
same index either way; only how far it walks before the page starts differs,
and nothing a plan prints shows it.

So the paged reads are measured as well as planned, and both measurements here
count rather than time and assert a relationship rather than a number, because
a number is one machine's and rots. `tests/export.rs` installs a counting
allocator and takes a binary to itself so nothing else allocates into what it
is measuring; the paged reads install SQLite's progress handler, which belongs
to one connection and needs no such room.

## What nothing tests

How long a read holds what it runs on. `getRepo` streams a repository out of
one transaction on one blocking thread, and a caller that stops reading leaves
both of them held for as long as it cares to. Neither measurement above says
anything about that, so it wants a third.
