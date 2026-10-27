# Contributing

Thanks for looking. Coalition Connection is a hobby project, vibe coded for fun and testing,
and it welcomes issues and pull requests.

## What gets merged before 1.0

Until 1.0 is stable, only fixes are merged from outside contributors: bug fixes,
test fixes, documentation corrections and build or CI repairs. New features follow the
[roadmap](docs/roadmap.md) in its order, one reviewed slice at a time. If you want a feature,
open an issue so it can be placed on the roadmap; a feature pull request will be closed with a
pointer to that issue.

Security problems never go in a public issue or pull request. Report them privately through
the repository's **Security** tab ("Report a vulnerability").

## Sign your commits (DCO)

Every commit must carry a Developer Certificate of Origin sign-off. By adding it you certify
the [DCO 1.1](https://developercertificate.org/): you wrote the change, or have the right to
submit it under the project's [Apache-2.0 license](LICENSE).

```sh
git commit -s -m "Fix the off-by-one in BoundedQueue.pop"
```

`-s` appends a line like `Signed-off-by: Your Name <you@example.com>`, using the name and
email in your git config. To sign commits you already made on your branch:

```sh
git rebase --signoff main
```

Pull requests with an unsigned commit are not merged.

### Commits written with AI tools

Some of the maintainer's own commits are written with AI coding tools. The maintainer directs
that work and certifies it under the DCO, so from 2026-10-23 on those commits are authored and
signed off under the maintainer's identity and carry a `Co-Authored-By` trailer naming the
tool, for example:

```text
Signed-off-by: gewnthar <122470689+gewnthar@users.noreply.github.com>
Co-Authored-By: Claude <noreply@anthropic.com>
```

A `Co-Authored-By` trailer gives credit; it is not a sign-off and certifies nothing. Earlier
commits signed off as the tool predate this rule. It covers only the maintainer's commits:
outside contributors sign off their own commits as described above, and the maintainer never
signs off a commit for someone else.

## Coding standards

Code follows the NASA [Power of 10](https://spinroot.com/gerard/pdf/P10.pdf) rules and
TigerBeetle's [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md).
[docs/architecture.md](docs/architecture.md#rules-every-component-follows) has the project's
version. In short:

1. **Simple control flow.** No recursion, no hidden control flow.
2. **Every loop has a fixed upper bound,** and an assertion checks it.
3. **No memory allocation after startup.** Every size comes from a limit in
   [`src/constants.zig`](src/constants.zig), with a comment giving its reason.
   `StartupAllocator` asserts if anything allocates later.
4. **Functions of at most 70 lines.**
5. **At least two assertions per function:** preconditions, postconditions and invariants,
   in both the positive and the negative space.
6. **Data lives in the smallest possible scope.**
7. **Every error is handled explicitly.** No `catch unreachable` unless an assertion proves
   it can't happen.
8. **comptime stays boring:** sizes and tables, not code generation.
9. **Minimal pointer indirection.** Function pointers only in a few reviewed places.
10. **Explicitly sized integers** (`u32`, not `usize`) wherever an interface allows.
11. **All I/O (network, clock, database) goes through the I/O boundary** in `src/io/`, so
    the simulator can replace it.
12. **ReleaseSafe builds, zero warnings,** and tests for everything you add.

Code targets the latest stable Zig release, pinned as `ZIG_VERSION` in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). Code written for older Zig versions
is not accepted.

## Running the checks

Install the Zig version CI pins, then run what CI runs, from the repository root:

```sh
zig fmt --check build.zig src fuzz sim   # formatting (zig fmt ... without --check fixes it)
zig build --release=safe                 # ReleaseSafe build, zero warnings
zig build test                           # unit tests in Debug
zig build test --release=safe            # unit tests in ReleaseSafe
zig build fuzz --release=safe -Dseed=1   # seeded fuzzer
zig build sim --release=safe -Dseed=1    # seeded deterministic simulation
```

Fuzzing and simulation are replayable: a failure prints its seed, and the same `-Dseed`
reproduces it exactly. Try a few seeds of your own before opening a pull request.
[docs/architecture.md](docs/architecture.md#testing) says which kind of test each component
needs.

## Pull requests

- Keep each pull request to one change, small enough to review in about 15 minutes.
- Say what it fixes, link the issue, and say how you tested it.
- Add or update tests for every change. A bug fix comes with a test that fails without it.
- CI must be green: formatting, the ReleaseSafe build, tests in Debug and ReleaseSafe, fuzz
  and simulation.
