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
  allocates later. A memory table there adds up every startup buffer, and the build fails
  if the total exceeds `memory_budget_bytes`.
- Functions of at most 70 lines, with at least two assertions each.
- Every error is handled explicitly. Explicitly sized integers (`u32`, not `usize`) wherever
  an interface allows.
- All I/O (network, clock, database, random bytes) goes through one boundary, so the
  deterministic simulator can replace it.
- Builds are ReleaseSafe and compile with zero warnings. Code targets the latest stable Zig.

## 1.0 components

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
  `io.sim.Sim`. Nothing else opens a socket, reads the clock or draws random bytes.
- **Only `storage` speaks Postgres and Valkey.** Postgres is the source of truth. Valkey
  holds sessions, queues and pub/sub, and can be wiped without losing anything.
- **Only `esi` calls ESI.** Other components queue requests and get back a body or an
  error. The ESI client alone knows the rate-limit state, so no component can starve
  another or trip the error limit.
- **`access` decides; it does not act.** It computes each user's state, groups and
  permissions as a pure function of its inputs and emits change events. `services` and
  `live` act on those events.
- **Money moves only through the ledger.** Taxes and SRP payouts are double-entry ledger
  transfers; neither edits a balance directly. They reach the ledger only through one Zig
  interface, checked at compile time like the I/O contract ([Ledger](#ledger)).
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
                             sso --> access -------+--> services --> Mumble (voice server,
                              |        ^                  |          over WireGuard)
                              |        |                  '---------> XMPP (Openfire)
                              v        | affiliations
EVE SSO and ESI <---------- esi -------'
                              ^
                              | queued requests
                    audits, taxes, srp --> ledger transfers

importer --> storage <-- every component (Postgres, Valkey, audit log)
```

1. **Login.** A browser goes through EVE SSO. `sso` verifies the token, links the
   character to a user as main or alt, and stores the refresh token, encrypted
   ([Tokens at rest](#tokens-at-rest)), through `storage`.
2. **Affiliation.** `esi` polls each character's corporation and alliance. `access`
   recomputes the user's state, groups and permissions and emits change events.
3. **Fan-out.** Change events go through Valkey pub/sub. `services` updates Mumble and XMPP
   in batches; `live` pushes the changed page fragment to every page watching it.
4. **Background reads.** `audits`, `taxes` and `srp` queue ESI requests (skills, wallets,
   mining ledgers, killmails) and store what comes back.
5. **Money.** `taxes` and `srp` write ledger transfers; balances are read from the ledger.
6. **Import and shadow run.** `importer` loads an Alliance Auth export. During the shadow
   run it re-imports nightly, and the results of steps 2 and 5 are compared with Alliance
   Auth's without acting on them.

## Tokens at rest

Decided 2026-10-23, with the details below decided 2026-10-24 (roadmap core 38). Pilots' ESI
refresh tokens are encrypted before they reach the database, with XChaCha20-Poly1305 from
Zig's standard library, which is safe with random nonces.

- **The key** is 32 bytes, kept in its own file, mounted as a Podman secret that only the
  service account can read. It is never in the config file, the database or a log. The
  service reads the file once at startup into fixed arrays and refuses to start if it is
  missing or a key in it is the wrong size.
- **Each stored token** keeps a `u8` associated-data version, a `u8` key ID, a fresh random
  24-byte nonce and the 16-byte tag.
- **Associated data** has one fixed layout of 11 bytes: the version byte (currently 1), the
  key ID, the token kind as a `u8`, and the character ID as a little-endian `u64`. It binds
  each ciphertext to its row, so a ciphertext can't be moved to another character or token
  kind. A stored row with a version other than 1 is a named error.
- **Random bytes come through the I/O boundary,** like the clock and the network: the
  operating system's CSPRNG in production and the seeded PRNG in the simulator, so nonces
  never break replay. The seeded source can't be compiled into a production build.
- **Key rotation:** the key file holds at most two keys, the current and the previous one,
  each with its key ID. New and refreshed tokens are written under the current key. A
  bounded re-encrypt sweep moves at most a fixed number of token rows per tick from the
  previous key to the current one. The previous key is retired, and its check value
  deleted, only when no token row uses it; the rotation step refuses to drop a key that any
  token row still names.
- **Every key in use must be present.** At startup the service counts token rows per key ID
  with one grouped query, at most 256 result rows (one per `u8` key ID), parsed as outside
  data with named errors. It refuses to start, with a named error, when a key that token
  rows use is missing from the key file. Without this, a second rotation before the sweep
  finishes would strand rows.
- **Check values:** each key has a check value stored in the database, encrypted under that
  key with its own token kind and character ID 0 in the associated data, so a check row and
  a token row can't be swapped. Startup requires a check value for every key in the key
  file and every key that token rows name, decrypts each one, and refuses to start when one
  is missing or doesn't match; it never skips the check. Only key generation creates a
  check value: the installer's, and the rotation step's when it adds a new key.
- **Fixed sizes:** token buffers are fixed and sized by `token_size_max` in
  `src/constants.zig`; encrypt and decrypt work on one token at a time, and plaintext
  buffers are wiped with `std.crypto.secureZero` after use. The key never leaves the token
  module.
- **No key in crash dumps:** `main` clears the dumpable flag with
  `prctl(PR_SET_DUMPABLE, 0)` before any component starts and before the key file is read,
  and the app's Quadlet unit sets a core-dump limit of 0 ([Containers](#containers)).
- **Errors, not crashes:** a stored row is outside data, so an unknown key ID or version, a
  stored nonce or ciphertext of the wrong length, a tampered row or the wrong key each
  return a named error, and so does a token longer than `token_size_max` on the way in.
  Assertions cover only what the code itself controls, such as the loaded key's length and
  the length of a nonce it just generated.

This protects a leaked database or backup, not a server someone controls. That's why
opening mail or wallets still needs a fresh EVE login.

## Ledger

Decided 2026-10-23 (roadmap taxes 2). Taxes and SRP share one double-entry ledger, stored in
Postgres and shaped like [TigerBeetle](https://tigerbeetle.com)'s accounts and transfers, so
a later move to TigerBeetle is a backend swap rather than a redesign.

- **Transfers are append-only,** each with a 128-bit ID the app picks, so a retried request
  can't post twice. A reused ID whose other fields differ is refused with an error, never
  treated as a success.
- **Accounts keep running debit and credit totals,** pending and posted, as TigerBeetle's
  do.
- **Amounts are whole hundredths of an ISK,** stored as `numeric(39,0)` to match
  TigerBeetle's 128-bit amounts. A check constraint keeps every stored amount and total
  between 0 and the largest 128-bit value, and a transfer that would overflow a total is
  refused, as TigerBeetle refuses it.
- **Corrections are new reversing transfers.** Nothing is edited or deleted.
- **SRP approvals are two-phase:** a pending transfer that is later posted or voided, once,
  by a new transfer that references it.
- **All-or-nothing batches are linked,** so either every transfer in the batch posts or none
  does.

## Services: Mumble and XMPP

Decided 2026-10-23 (roadmap core 43 and core 44).

- **Mumble** login is written in Zig, with no bridge in another language. The service
  speaks the part of the ZeroC Ice protocol that Mumble's authenticator interface needs and
  registers itself as the authenticator. Before building it, roadmap core 43 confirms that
  Ice is still Mumble's server interface and lists the calls Alliance Auth's authenticator
  uses.
- **XMPP** accounts are managed on the coalition's existing server, Openfire,
  through its REST API plugin, unless a check of what most coalitions run finds something
  else. An XMPP server written in Zig, to the same rules, follows 1.0 and removes the
  Java dependency.
- **Their secrets** are Podman secrets like the token key (decided 2026-10-24): the Ice
  secret for Mumble and the Openfire REST API key, never in the config file, the database
  or a log. The installer generates the Ice secret and takes the Openfire API key
  ([Installer](#installer)).
- **Mumble runs on a voice server of its own** (decided 2026-10-26), not on the main
  server. The two servers talk over a private network in the same data center (a VPC).
  That network isn't encrypted, so Ice runs inside a WireGuard tunnel across it, and pilots'
  Mumble logins and the Ice secret never travel in the clear. Ice is reachable only on the
  tunnel's private address on each side, never on a public one, and each firewall lets Ice
  in only through the tunnel, from the other server's tunnel address. Every call into
  Mumble carries the Ice secret. The app's own Ice listener, which Mumble calls back as the
  authenticator, accepts connections only from the voice server's tunnel address; core 43
  confirms whether those callbacks carry the secret too. [Voice server](#voice-server) has
  the deployment.
- **Mumble's certificate** is its own self-signed one (decided 2026-10-26), made once by the
  installer and backed up with the token key, so a rebuilt voice server never shows players
  a new certificate. At cutover, the current Mumble's certificate, channels and permissions
  move over with it; if the current Mumble uses a public certificate, this is revisited
  before cutover.

## Member and admin spaces

Decided 2026-10-26 (roadmap core 36 and core 56 to 58). The site has two spaces:

- **The member space** at `/` is for every pilot whose state lets them in: their characters
  and token scopes, groups and requests, service logins, and later their tax balance and SRP
  requests. Its pages take the user from the session, never from the request, so no address
  or form field can point a page at someone else's data.
- **The admin space** at `/admin/` is for leaders: users, states, groups and requests,
  permissions, service sync, leave alerts, the importer, the audit log and settings.
  Audits (audits 11), taxes and SRP review (SRP 8) add their pages to it as they are built.
- **Deny by default.** Each admin page names the permission it needs, and the router checks
  it before the page runs; a page that names none is refused. Links a user can't use are
  left out of the menu.
- **Admin rights come from groups,** like every other permission, so a group leader or an
  SRP reviewer gets only their own pages.
- **The last full admin stays.** The installer's first admin starts with every admin
  permission, and the app refuses any admin action that would leave no one holding them
  all: removing that person from a group, dropping a permission from a group, or deleting
  a group. Leaving the corporation in game removes access automatically and can't be
  refused; what happens then is still an open decision.
- Every admin action is written to the audit log, as is every view of private data.

## Email

Decided 2026-10-26. Confirmed emails (release 0.4) mean the app has to send mail. It sends
it only through a sending service's HTTPS API, never through a mail server of its own:
large mail providers junk or reject mail from a new address with no sending reputation,
and hosts often block mail ports on new accounts. Brevo is the first service and Amazon SES
the fallback. Both sit behind one small mail interface, so switching is a setting and an
adapter. How the service's API key is stored is settled with the email slices.

## SRP skill checks

Decided 2026-10-23 (roadmap SRP 1). When a pilot in a skill-checked ship lacks a required
skill, the payout is the FC's call, recorded with the FC's name like a waiver.

## Live updates

Pages are rendered as HTML in Zig on the server. When data changes, the server pushes the
changed part of the page over a websocket and a few dozen lines of JavaScript swap it in.
Every event has an id; a page that reconnects catches up from the last event it saw, or
reloads if it is further behind than the backlog holds: `live_events_backlog_max` events or
`live_events_backlog_bytes_max` bytes, whichever is reached first. Every page still works
with the websocket down.

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
| Services | change batching | Ice messages and Openfire REST responses | a service down, retries | service access per user |
| Taxes | ledger and rate math | ledger invariants vs a model | wallet and price feed gaps | a month of taxes, to the ISK |
| Audits | per-route storage, alerts | ESI body parsers | partial and failed fetches | - |
| SRP | each check and outcome | killmail and fit parsers | late killmails, missing skill history | past decisions replayed |

## Deployment

1.0 runs on AlmaLinux 10 with SELinux enforcing, as rootless Podman Quadlets, behind
Cloudflare. Deployment is part of the core milestone, not an afterthought: the first slice
that serves a page already runs this way.

It uses two servers in the same data center, joined by a private network: the main server
runs the app and everything it needs, and a small [voice server](#voice-server) runs
Mumble. The main server's address is never published: the web reaches it only through
Cloudflare, and an attack on voice can't take auth down with it.

### Host

- **AlmaLinux 10, SELinux enforcing, always.** No setup step, script, doc or installer
  ever runs `setenforce 0`, edits `/etc/selinux/config`, or suggests either. If something
  is denied, the fix is a correct label or a small reviewed policy module, never turning
  SELinux off. A denial is a bug.
- **One unprivileged service user** owns the containers. `loginctl enable-linger` lets its
  units start at boot without a login session. Nothing runs as root except the host's own
  services (firewalld, sshd, WireGuard).
- **firewalld** opens the web port only to Cloudflare's published address ranges, held in
  an ipset. SSH is limited separately. Postgres and Valkey have no open port on the host.
  On the main server, nginx's web port is the only port published to the internet; Ice
  comes in only through the WireGuard tunnel from the voice server.

### Containers

Each process is a Quadlet unit under the service user's `~/.config/containers/systemd/`,
which systemd turns into ordinary services. The units live in the repository under
`deploy/`. All four containers join one pod (a Quadlet `.pod` unit), so they share a
network namespace: nginx reaches the app on a local socket, the app reaches Postgres and
Valkey on `localhost`, and only nginx's web port is published to the internet. The app's
Ice listener is published only on the main server's WireGuard tunnel address, never on a
public one, so Mumble on the voice server can reach it through the tunnel.

| Unit | Runs | Reachable from |
| --- | --- | --- |
| `coalition-connection.pod` | The shared network namespace; publishes nginx's web port only | - |
| `nginx.container` | nginx: ends TLS, applies the Cloudflare rules, proxies to the app | Cloudflare, through the web port |
| `coalition-connection.container` | The Zig binary: web requests only on a local socket, Ice only on the tunnel address | nginx; Mumble on the voice server, through the tunnel, for Ice |
| `postgres.container` | Postgres, listening on `localhost` only | The app only |
| `valkey.container` | Valkey, listening on `localhost` only | The app only |

**The client's source address must survive the trip.** The Cloudflare checks below rely
on nginx seeing Cloudflare's address as its TCP peer. A rootless container on a Podman
bridge network gets its published ports from `rootlessport`, which replaces the source
address, so the pod does not use a bridge network. It uses `pasta`, the default rootless
network mode in Podman 5, whose port forwarding keeps the original source address. The
SELinux smoke test (roadmap core 54) fails if nginx sees anything other than the real
peer.

Rules for every unit:

- Runs as the unprivileged service user, rootless, with a read-only root file system.
- Volumes carry SELinux labels (`:Z`). The containers in a pod share one SELinux label, so
  `:Z` makes a volume private to the pod, not to one container: the SELinux boundary is
  around the pod as a whole, and nginx, the app, Postgres and Valkey are not isolated from
  each other by it. Each container mounts only the volumes it needs. Never `--privileged`,
  never `SecurityLabelDisable=true` (`--security-opt label=disable`), never a host
  directory shared without a label.
- Secrets (the token key from [Tokens at rest](#tokens-at-rest), the origin certificate's
  key, the Ice secret and the Openfire API key) are mounted as Podman secrets readable only
  by the service user, never baked into an image or a unit.
- The app's unit sets `LimitCORE=0` in `[Service]` and `Ulimit=core=0` in `[Container]`, so
  a crash doesn't write the token key to a core dump.
- No extra Linux capabilities. Rootless containers can't bind ports below 1024 by default,
  so the pod publishes a high port and firewalld forwards the public port to it (a local
  redirect, which keeps the source address).
- The image is built from the ReleaseSafe binary and holds nothing else it doesn't need.

### Voice server

Mumble runs on a small server of its own. Its setup has no roadmap slices yet; the plan is
the same host rules as the main server (AlmaLinux 10 with SELinux enforcing, an
unprivileged service user), and its setup slices will settle the rest.

- **Published:** only Mumble's port (64738 by default, TCP and UDP), which firewalld opens
  to everyone. Its DNS record is DNS-only, not proxied by Cloudflare, so it shows the voice
  server's address and never the main server's.
- **Private:** a WireGuard tunnel to the main server across the data center's private
  network (a VPC). The tunnel's endpoints use private addresses, and its port is open only
  on the private network, never on the public interface, so neither server's config holds
  the other's public address. Ice is reachable only on the tunnel's address and is let in
  only from the main server's tunnel address, with the Ice secret on every call into
  Mumble. SSH is limited separately, as on the main server.
- **Its secrets:** the WireGuard keys on both servers, Mumble's certificate key and the
  voice server's copy of the Ice secret. Where each is made and kept is settled with the
  voice server's setup slices.
- **Disposable:** one command builds a replacement on a new address from the backed-up
  certificate, settings and channels, moves the DNS record and retires the old server.
  Mumble clients find it once the DNS change reaches them. The command runs from the
  administrator's own computer, which holds the hosting and Cloudflare API tokens, so no
  server keeps keys that could create servers or change DNS.

### Cloudflare

Cloudflare proxies every web request. Three rules follow from that:

1. **Websockets pass through.** Cloudflare proxies websocket upgrades. It also closes
   connections that sit idle, so the live-update socket sends pings well inside
   Cloudflare's idle timeout (roadmap core 32), and a dropped socket reconnects and catches
   up from its last event id as it would after any other drop.
2. **Real client IPs only from Cloudflare.** nginx takes the client's address from the
   `CF-Connecting-IP` header only when the TCP peer is inside Cloudflare's published
   ranges (`set_real_ip_from` for each range, `real_ip_header CF-Connecting-IP`), and
   passes it to the app in `X-Real-IP`. The app uses `X-Real-IP` only on requests from
   nginx on its local socket; otherwise it ignores the header, uses the peer address, and
   logs the event. Without this, anyone could fake their address by sending the header.
3. **Web traffic only from Cloudflare.** firewalld opens the web port only to Cloudflare's
   ranges. nginx refuses any connection whose original peer (`$realip_remote_addr`) is
   outside them. The check must use that variable, not `allow`/`deny`, because those run
   after the real-IP module has replaced the peer with the client's address. The app
   listens only on a local socket inside the pod that only nginx reaches. The layers back
   each other up.

Cloudflare publishes its ranges at <https://www.cloudflare.com/ips/>, and they can change,
so they are kept as data, not in code. One list feeds nginx's real-IP rules, its peer check
and firewalld's ipset (roadmap core 49), so they can't disagree. The app does no CIDR
matching of its own.

**Decided (roadmap core 47, 2026-10-22): TLS from Cloudflare ends at nginx.** nginx runs in
the pod, ends TLS with a Cloudflare origin certificate, applies rules 2 and 3 with
firewalld behind it, and proxies to the app, which listens only locally (roadmap core 48 to
core 51).

### Installer

After the core works (roadmap core 55), one command sets up a host. It asks for the EVE
application's client ID and secret, the callback URL, the domain, the database, the first
admin character, the Cloudflare origin certificate and its key, and Openfire's address and
REST API key. It writes the config file and the Quadlet units, generates the token key and
its check value, the Ice secret and Mumble's self-signed certificate, and stores the token
key, the origin key, the Ice secret and the Openfire API key as Podman secrets. Then it loads
the Cloudflare ranges into firewalld and nginx and starts the services. It checks that
SELinux is enforcing and stops with a clear message if it isn't; it never changes the
SELinux mode.

### How deployment is tested

| What | Test |
| --- | --- |
| nginx | CI runs `nginx -t` on the config, including the rules generated from the Cloudflare ranges |
| Real client IP | Unit tests for the `X-Real-IP` rule; simulation with spoofed headers |
| Local-only listener | Unit tests; simulation with a non-local peer refused |
| Cloudflare-only traffic | The SELinux smoke test sends a request from outside the ranges and expects it refused |
| Quadlet units | CI builds the image and runs Quadlet's dry-run generator on each unit |
| Voice link | No slice yet: with the voice server's setup, a check that Ice is refused from a public address and from a private address outside the tunnel |
| SELinux | On an AlmaLinux 10 machine with SELinux enforcing: start the units, send a smoke request, and fail on any AVC denial, if nginx sees a peer other than the real one, or if a request from outside the ranges gets through |

GitHub's hosted runners are Ubuntu and can't enforce SELinux, so the SELinux test runs
on a separate AlmaLinux machine. **Decided (roadmap core 53, 2026-10-23):** it runs on the
maintainer's AlmaLinux test server, through a GitHub runner attached to a separate private
repository. That repository's workflow builds only commits already merged to main
here, never a ref or source taken from an open pull request, so outside pull requests can
never run code on the server. It is set up by hand once the
server exists.

## Status

This is the framework: every component is a stub that compiles and has a test. The build
order and its slices are in [roadmap.md](roadmap.md).
