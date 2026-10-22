# Architecture

Coalition Connection is an auth server for EVE Online coalitions, meant as a drop-in
replacement for Alliance Auth. It's a hobby project, vibe coded for fun and testing.
Stability comes before features: a coalition's auth has to just work. The headline
upgrade is live updates: pages change the moment the data does, without reloads.

It runs as one Zig binary beside Postgres and Valkey, as rootless Podman containers on
AlmaLinux 10 with SELinux enforcing, behind nginx and Cloudflare.
[Deployment](#deployment) has the details.

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
browser --> Cloudflare ---> nginx
                              |  TLS ends here; client IP in X-Real-IP
                              v  over a local socket
                             live  <--------------.
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

## Deployment

Version 1 runs on AlmaLinux 10 with SELinux enforcing, as rootless Podman Quadlets, behind
Cloudflare. Deployment is part of the core milestone, not an afterthought: the first slice
that serves a page already runs this way.

### Host

- **AlmaLinux 10, SELinux enforcing, always.** No setup step, script, doc or installer
  ever runs `setenforce 0`, edits `/etc/selinux/config`, or suggests either. If something
  is denied, the fix is a correct label or a small reviewed policy module, never turning
  SELinux off. A denial is a bug.
- **One unprivileged service user** owns the containers. `loginctl enable-linger` lets its
  units start at boot without a login session. Nothing runs as root except the host's own
  services (firewalld, sshd).
- **firewalld** opens the web port only to Cloudflare's published address ranges, held in
  an ipset. SSH is limited separately. Postgres and Valkey have no open port on the host.

### Containers

Each process is a Quadlet unit under the service user's `~/.config/containers/systemd/`,
which systemd turns into ordinary services. The units live in the repository under
`deploy/`. All four containers join one pod (a Quadlet `.pod` unit), so they share a
network namespace: nginx reaches the app on a local socket, the app reaches Postgres and
Valkey on `localhost`, and only nginx's web port is published.

| Unit | Runs | Reachable from |
| --- | --- | --- |
| `coalition-connection.pod` | The shared network namespace; publishes nginx's web port only | - |
| `nginx.container` | nginx: ends TLS, applies the Cloudflare rules, proxies to the app | Cloudflare, through the web port |
| `coalition-connection.container` | The Zig binary, listening only on a local socket | nginx only |
| `postgres.container` | Postgres, listening on `localhost` only | The app only |
| `valkey.container` | Valkey, listening on `localhost` only | The app only |

**The client's source address must survive the trip.** The Cloudflare checks below rely
on nginx seeing Cloudflare's address as its TCP peer. A rootless container on a Podman
bridge network gets its published ports from `rootlessport`, which replaces the source
address, so the pod does not use a bridge network. It uses `pasta`, the default rootless
network mode in Podman 5, whose port forwarding keeps the original source address. The
SELinux smoke test (roadmap 1.54) fails if nginx sees anything other than the real
peer.

Rules for every unit:

- Runs as the unprivileged service user, rootless, with a read-only root file system.
- Volumes carry SELinux labels (`:Z`). The containers in a pod share one SELinux label, so
  `:Z` makes a volume private to the pod, not to one container: the SELinux boundary is
  around the pod as a whole, and nginx, the app, Postgres and Valkey are not isolated from
  each other by it. Each container mounts only the volumes it needs. Never `--privileged`,
  never `SecurityLabelDisable=true` (`--security-opt label=disable`), never a host
  directory shared without a label.
- No extra Linux capabilities. Rootless containers can't bind ports below 1024 by default,
  so the pod publishes a high port and firewalld forwards the public port to it (a local
  redirect, which keeps the source address).
- The image is built from the ReleaseSafe binary and holds nothing else it doesn't need.

### Cloudflare

Cloudflare proxies every web request. Three rules follow from that:

1. **Websockets pass through.** Cloudflare proxies websocket upgrades. It also closes
   connections that sit idle, so the live-update socket sends pings well inside
   Cloudflare's idle timeout (roadmap 1.32), and a dropped socket reconnects and catches
   up from its last event id as it would after any other drop.
2. **Real client IPs only from Cloudflare.** nginx takes the client's address from the
   `CF-Connecting-IP` header only when the TCP peer is inside Cloudflare's published
   ranges (`set_real_ip_from` for each range, `real_ip_header CF-Connecting-IP`), and
   passes it to the app in `X-Real-IP`. The app uses `X-Real-IP` only on requests from
   nginx on its local socket; otherwise it ignores the header, uses the peer address, and
   logs the event. Without this, anyone could fake their address by sending the header.
3. **Web traffic only from Cloudflare.** firewalld opens the web port only to Cloudflare's
   ranges, nginx allows only those ranges and denies the rest, and the app listens only on
   a local socket inside the pod that only nginx reaches. The layers back each other up.

Cloudflare publishes its ranges at <https://www.cloudflare.com/ips/>, and they can change,
so they are kept as data, not in code. One list feeds both nginx's real-IP and allow rules
and firewalld's ipset (roadmap 1.49), so the two can't disagree. The app does no CIDR
matching of its own.

**Decided (roadmap 1.47, 2026-10-22): TLS from Cloudflare ends at nginx.** nginx runs in
the pod, ends TLS with a Cloudflare origin certificate, applies rules 2 and 3 with
firewalld behind it, and proxies to the app, which listens only locally (roadmap 1.48 to
1.51).

### Installer

After the core works (roadmap 1.55), one command sets up a host. It asks for the EVE
application's client ID and secret, the callback URL, the domain, the database and the
first admin character, then writes the config file and the Quadlet units, loads the
Cloudflare ranges into firewalld and nginx, and starts the services. It checks that SELinux is
enforcing and stops with a clear message if it isn't; it never changes the SELinux mode.

### How deployment is tested

| What | Test |
| --- | --- |
| nginx | CI runs `nginx -t` on the config, including the rules generated from the Cloudflare ranges |
| Real client IP | Unit tests for the `X-Real-IP` rule; simulation with spoofed headers |
| Local-only listener | Unit tests; simulation with a non-local peer refused |
| Cloudflare-only traffic | The SELinux smoke test sends a request from outside the ranges and expects it refused |
| Quadlet units | CI builds the image and runs Quadlet's dry-run generator on each unit |
| SELinux | On an AlmaLinux 10 machine with SELinux enforcing: start the units, send a smoke request, and fail on any AVC denial, if nginx sees a peer other than the real one, or if a request from outside the ranges gets through |

GitHub's hosted runners are Ubuntu and can't enforce SELinux, so the SELinux test runs
on a separate AlmaLinux machine; where it runs is an open decision (roadmap 1.53).

## Status

This is the framework: every component is a stub that compiles and has a test. The build
order and its slices are in [roadmap.md](roadmap.md).
