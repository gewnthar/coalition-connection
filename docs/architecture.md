# Architecture

Coalition Connection is an auth server for EVE Online coalitions, meant as a drop-in
replacement for Alliance Auth. It's a hobby project, vibe coded for fun and testing.
Stability comes before features: a coalition's auth has to just work. The headline
upgrade is live updates: pages change the moment the data does, without reloads.

It runs as one Zig binary beside Postgres and Valkey, with nginx in front for TLS.

## Rules every component follows

- Safety first, then speed. Code follows the NASA Power of 10 rules and TigerBeetle's
  [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md).
- No recursion. Every loop has a fixed upper bound.
- No memory allocation after startup. All memory is sized once from the limits in
  [`src/constants.zig`](../src/constants.zig); `StartupAllocator` asserts if anything
  allocates later.
- Functions of at most 70 lines, with at least two assertions each.
- Every error is handled explicitly. Explicitly sized integers (`u32`, not `usize`) wherever
  an interface allows.
- All I/O (network, clock, database) goes through one boundary, so the deterministic
  simulator can replace it.
- Builds are ReleaseSafe and compile with zero warnings. Code targets the latest stable Zig.

## Version 1 components

| Component | Folder | Job |
| --- | --- | --- |
| SSO | `src/sso/` | EVE SSO login; one main and its alts per user; detects characters that changed hands |
| ESI client | `src/esi/` | Every call to EVE's API, within ESI's rate-limit buckets and error limit |
| Access | `src/access/` | States, groups and permissions that behave like Alliance Auth's |
| Storage | `src/storage/` | Postgres and Valkey wire protocols in Zig; the audit log |
| Live updates | `src/live/` | Server-rendered HTML plus a websocket that pushes changed fragments |
| Importer | `src/importer/` | Reads an Alliance Auth export; also drives the shadow run |
| Services | `src/services/` | Mumble and XMPP accounts and roles kept in step with access |
| Taxes | `src/taxes/` | Moon and mining taxes in a double-entry ledger |
| Audits | `src/audits/` | Character audits for vetting and spy-hunting |
| SRP | `src/srp/` | Alliance and corporation ship replacement with fit and skill checks |

Shared pieces live beside them: `src/constants.zig` (every limit and its reason),
`src/startup_allocator.zig`, `src/bounded_queue.zig` and `src/io/` (the I/O boundary and
its simulator). Each component's `root.zig` starts with a doc comment giving its job,
inputs, outputs and limits.

## Boundaries

Each component owns its data and talks to the others through plain function calls with
explicit inputs and outputs. The rules that keep it that way:

- **Only `io` touches the outside world.** Components take the I/O type as a
  `comptime IO: type` parameter. Production passes the real implementation; tests pass
  `io.sim.Sim`. Nothing else opens a socket or reads the clock.
- **Only `storage` speaks Postgres and Valkey.** Postgres is the source of truth. Valkey
  holds sessions, queues and pub/sub, and can be wiped without losing anything.
- **Only `esi` calls ESI.** Other components queue requests and get back a body or an
  error. The ESI client alone knows the rate-limit state, so no component can starve
  another or trip the error limit.
- **`access` decides; it does not act.** It computes each user's state, groups and
  permissions as a pure function of its inputs and emits change events. `services` and
  `live` act on those events.
- **Money moves only through the ledger.** Taxes and SRP payouts are double-entry ledger
  entries; neither edits a balance directly.
- **Sensitive reads are logged.** Every admin action and every view of a member's private
  audit data writes an audit-log entry through `storage`.

## Data flow

```
browser --HTTPS--> nginx --> live  <--------------.
                              |                    |  change events
                              v                    |  (Valkey pub/sub)
                             sso --> access -------+--> services --> Mumble, XMPP
                              |        ^
                              v        | affiliations
EVE SSO and ESI <---------- esi -------'
                              ^
                              | queued requests
                    audits, taxes, srp --> ledger entries

importer --> storage <-- every component (Postgres, Valkey, audit log)
```

1. **Login.** A browser goes through EVE SSO. `sso` verifies the token, links the
   character to a user as main or alt, and stores the refresh token through `storage`.
2. **Affiliation.** `esi` polls each character's corporation and alliance. `access`
   recomputes the user's state, groups and permissions and emits change events.
3. **Fan-out.** Change events go through Valkey pub/sub. `services` updates Mumble and XMPP
   in batches; `live` pushes the changed page fragment to every page watching it.
4. **Background reads.** `audits`, `taxes` and `srp` queue ESI requests (skills, wallets,
   mining ledgers, killmails) and store what comes back.
5. **Money.** `taxes` and `srp` write ledger entries; balances are read from the ledger.
6. **Import and shadow run.** `importer` loads an Alliance Auth export. During the shadow
   run it re-imports nightly, and the results of steps 2 and 5 are compared with Alliance
   Auth's without acting on them.

## Live updates

Pages are rendered as HTML in Zig on the server. When data changes, the server pushes the
changed part of the page over a websocket and a few dozen lines of JavaScript swap it in.
Every event has an id; a page that reconnects catches up from the last event it saw, or
reloads if it is further behind than `live_events_backlog_max`. Every page still works with
the websocket down.

## Testing

Every slice ships with its tests. Four kinds, all run by CI on every pull request:

| Kind | Command | What it covers |
| --- | --- | --- |
| Unit tests | `zig build test` | Each function's positive and negative space, in Debug and ReleaseSafe |
| Fuzzing | `zig build fuzz -Dseed=N` | Every parser and state machine against a simple model, with random input |
| Simulation | `zig build sim -Dseed=N` | Whole components against `io.sim.Sim`: random faults, slow peers, a down database, replayable by seed |
| Parity | (shadow run) | Access decisions and taxes compared with Alliance Auth's, to the ISK |

How each component is tested:

| Component | Unit | Fuzz | Simulation | Parity |
| --- | --- | --- | --- | --- |
| SSO | token checks, alt linking, owner-hash changes | callback and token parsing | SSO down, expired and revoked tokens | users and characters match |
| ESI client | bucket and error-limit accounting | header and page parsing | rate limits, 5xx bursts, Retry-After | - |
| Access | state and group rules, table-driven | rule evaluation vs a model | affiliation changes mid-run | every user's state and groups |
| Storage | message encode and decode | Postgres and Valkey protocol parsers | lost connections, timeouts, restarts | - |
| Live updates | fragment rendering, event ids | HTTP and websocket frame parsers | dropped sockets, catch-up | - |
| Importer | each model's mapping | export record parser | a truncated or corrupt export | record counts and contents |
| Services | change batching | Mumble and XMPP message parsers | a service down, retries | service access per user |
| Taxes | ledger and rate math | ledger invariants vs a model | wallet and price feed gaps | a month of taxes, to the ISK |
| Audits | per-route storage, alerts | ESI body parsers | partial and failed fetches | - |
| SRP | each check and outcome | killmail and fit parsers | late killmails, missing skill history | past decisions replayed |

## Status

This is the framework: every component is a stub that compiles and has a test. The build
order and its slices are in [roadmap.md](roadmap.md).
