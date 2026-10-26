# Roadmap: version 1

Version 1 is drop-in parity with Alliance Auth, built in this order: the core, then taxes,
then audits, then SRP. Taxes come early because their rules are exact and easy to check
against the old app; audits come before SRP because SRP's skill checks need the audits'
skill history. There is one cutover, once everything matches.

Each slice is one pull request small enough to review in about 15 minutes, and ships with
the tests named beside it. **Decision** marks a slice that waits on a choice from the
maintainer; it is not started until that choice is written down. **Decided** marks one
whose choice is written down, with the date it was made.

## Milestone 0: framework (this pull request)

| Slice | Tests |
| --- | --- |
| Component folders with documented stubs; every limit in `src/constants.zig` | each stub's test |
| `StartupAllocator`: asserts on allocation after startup | phase and budget tests |
| I/O boundary contract and deterministic simulator | same-seed replay, fault-free run |
| `zig build test`, `fuzz` and `sim` steps; CI on every pull request | CI itself |

## Milestone 1: core

### Foundations

| # | Slice | Tests |
| --- | --- | --- |
| 1.1 | **Decided (2026-10-22):** the event loop is a hand-written io_uring loop of our own, not Zig's `std.Io`, so the core doesn't depend on the standard library's I/O interface while it keeps changing | - |
| 1.2 | Real I/O implementation: monotonic clock | unit; contract check |
| 1.3 | Real I/O: TCP accept, read and write with fixed buffers; the connection table and the response-buffer wait queue add their rows to the memory table in `src/constants.zig` | unit; simulation |
| 1.4 | Connection table sized from `http_connections_max` | unit; full-table simulation |
| 1.5 | HTTP/1.1 request parser, bounded by `http_request_size_max` | unit; fuzz |
| 1.6 | HTTP response writer and router | unit |
| 1.7 | Outgoing TLS client for EVE SSO and ESI | unit against recorded handshakes |
| 1.8 | Config file (ZON) loaded at startup into fixed limits | unit; fuzz the parser |

### Storage

| # | Slice | Tests |
| --- | --- | --- |
| 1.9 | Postgres message framing: encode and decode | unit; fuzz |
| 1.10 | Postgres startup and SCRAM-SHA-256 authentication | unit with RFC test vectors |
| 1.11 | Postgres simple and extended queries | unit; simulation with timeouts |
| 1.12 | Schema migrations, applied at startup | unit; simulation restart mid-migration |
| 1.13 | Valkey RESP3 encode and decode | unit; fuzz |
| 1.14 | Valkey commands for sessions and queues | unit; simulation |
| 1.15 | Valkey pub/sub | unit; simulation with a dropped connection |
| 1.16 | Audit log: append-only entries for admin actions and private-data views | unit |

### SSO, mains and alts

| # | Slice | Tests |
| --- | --- | --- |
| 1.17 | SSO authorization redirect with state and PKCE | unit |
| 1.18 | Token exchange and refresh; tokens are stored encrypted (needs 1.38) | unit; simulation with SSO down |
| 1.19 | JWT signature and claim checks against EVE's signing keys | unit; fuzz the JWT parser |
| 1.20 | Users, mains and alts; owner-hash change unlinks a character | unit |
| 1.21 | Sessions in Valkey, with logout and expiry | unit; simulation |

### ESI client

| # | Slice | Tests |
| --- | --- | --- |
| 1.22 | Request queue and scheduler bounded by `esi_requests_in_flight_max` | unit; simulation |
| 1.23 | Rate-limit group buckets read from response headers | unit; fuzz the header parser |
| 1.24 | Error-limit floor and Retry-After handling | unit; simulation with 5xx bursts |
| 1.25 | ETag caching and paged routes | unit; simulation |
| 1.26 | Character affiliation polling | unit; simulation |

### States, groups and permissions

| # | Slice | Tests |
| --- | --- | --- |
| 1.27 | States from corporation and alliance, matching Alliance Auth's rules | table-driven unit |
| 1.28 | Groups: open, request, approval and automatic membership | unit |
| 1.29 | Permissions from states and groups | unit; fuzz against a model |
| 1.30 | Change events on every access change | unit; simulation |

### Live updates

| # | Slice | Tests |
| --- | --- | --- |
| 1.31 | HTML rendering with escaping, into fixed buffers | unit; fuzz the escaper |
| 1.32 | Websocket handshake and frame parser | unit; fuzz |
| 1.33 | Event ids, the catch-up backlog (capped in events and in bytes, its index added to the memory table) and the fall-back reload | unit; simulation with dropped sockets |
| 1.34 | Fan-out from Valkey pub/sub to watching pages | simulation |
| 1.35 | The small client script that swaps fragments in | browser test |
| 1.36 | First pages: login, characters, groups (after the Deployment group below, so they run deployed from the start) | unit |
| 1.37 | Leave alerts | unit; simulation |

### Importer

| # | Slice | Tests |
| --- | --- | --- |
| 1.38 | **Decided (2026-10-23, details 2026-10-24):** ESI tokens are encrypted at rest with XChaCha20-Poly1305 from Zig's standard library, under a 32-byte key kept in its own file that only the service can read. This slice builds the token module: clear the dumpable flag with `prctl(PR_SET_DUMPABLE, 0)` in `main`, then load the key file (at most two keys) at startup; encrypt and decrypt one token at a time into fixed buffers sized by a new limit, `token_size_max`, with 11-byte associated data (version byte, key ID, `u8` token kind, little-endian `u64` character ID; the version is stored with each row) and nonces drawn through the I/O boundary; wipe plaintext with `std.crypto.secureZero` after use. At startup, count token rows per key ID in one bounded query and refuse to start when a key they use is missing from the key file, or when any key in the file or in use has a check value that is missing or doesn't match. A bounded re-encrypt sweep moves at most a fixed number of token rows per tick to the current key; the rotation step refuses to drop a key that token rows still name, and creates the check value for a key it adds. It is built before 1.18, which stores the first tokens, even though it is listed here, and needs a random-bytes source added to the I/O contract and Postgres queries (1.11, 1.12). The design is in [architecture.md](architecture.md#tokens-at-rest) | unit: missing key file, wrong-sized key, duplicate key ID, more than two keys, token longer than `token_size_max`, wrong key, unknown key ID, stored associated-data version other than 1, stored nonce or ciphertext of the wrong length, tampered row, row moved to another character or token kind, row under the previous key, plaintext buffer zeroed after use; a sweep tick moves no more than its bound, and the previous key and its check value are retired only once no token row uses it; the rotation step refuses to drop a key in use; on Linux, `PR_GET_DUMPABLE` reads 0 after startup; fuzz the key-file reader, and decrypt with random bytes expecting an error every time; simulation: at runtime, a token row under the wrong key or tampered returns an error without stopping the service; rows under key 1 with a key file holding keys 2 and 3 refuse to start and name key 1; a deleted check row refuses to start, also for a current key no token row uses yet; a check row copied into a token row fails to decrypt; same seed, same nonces |
| 1.39 | Streaming JSON reader for dumpdata exports, one record at a time | unit; fuzz |
| 1.40 | Users, characters and tokens; imported tokens are encrypted through 1.38 | unit with a sample export |
| 1.41 | States, groups and memberships | unit |
| 1.42 | Comparison report: every user's state and groups against Alliance Auth's | unit |

### Services

| # | Slice | Tests |
| --- | --- | --- |
| 1.43 | **Decided (2026-10-23):** Mumble login is written in Zig, with no bridge in another language. The service speaks the part of the ZeroC Ice protocol that Mumble's authenticator interface needs and registers itself as the authenticator. This slice first confirms that Ice is still Mumble's server interface and lists the calls Alliance Auth's authenticator uses, then encodes and decodes those Ice messages into fixed buffers | unit; fuzz the Ice message decoder |
| 1.44 | **Decided (2026-10-23):** version 1 manages accounts on the coalition's existing XMPP server, Openfire, through its REST API plugin, unless a check of what most coalitions run finds something else. An XMPP server written in Zig follows version 1 and removes the Java dependency | - |
| 1.45 | Mumble: register as the authenticator over the Ice messages from 1.43, then account and role sync | unit; simulation with Mumble down, a Mumble restart, and truncated or malformed Ice messages |
| 1.46 | XMPP account and role sync through Openfire's REST API (1.44) | unit; fuzz the Openfire response parser; simulation with Openfire down and with error or malformed replies |

### Deployment

Deployment comes with the core: the first slice that serves a page runs on AlmaLinux 10
with SELinux enforcing, as a rootless Podman Quadlet behind Cloudflare. So this group is
built before 1.36, the first pages, even though it is listed here. The requirements are in
[architecture.md](architecture.md#deployment).

| # | Slice | Tests |
| --- | --- | --- |
| 1.47 | **Decided (2026-10-22):** TLS from Cloudflare ends at nginx, in the pod. nginx and firewalld enforce the Cloudflare rules, and the app listens only locally | - |
| 1.48 | nginx Quadlet unit in the pod: TLS with a Cloudflare origin certificate (Full strict), websocket proxying with timeouts longer than the ping interval (1.32), proxy buffering on with room for a full `http_response_size_max` response, since the app's shared response buffers rely on it, SELinux-labeled volumes, proxying to the app's local socket (needs 1.3) | CI runs `nginx -t` on the config and Quadlet's dry-run generator on the unit; the smoke test in 1.54 |
| 1.49 | Cloudflare rules at nginx and firewalld: from one list of Cloudflare's published ranges, nginx gets `set_real_ip_from` for each range with `real_ip_header CF-Connecting-IP`, and passes the client address to the app in `X-Real-IP`. nginx also refuses any connection whose original peer, `$realip_remote_addr`, is outside the ranges (a `geo` map on that variable). Plain `allow`/`deny` can't do this check, because they run after the real-IP module has replaced the peer address with the client's. firewalld's ipset opens the web port only to the same ranges. No CIDR matching in the app (needs 1.48) | CI runs `nginx -t` on the generated config; the smoke test in 1.54 |
| 1.50 | Real client IP in the app: use `X-Real-IP` only on requests from nginx on the local socket; otherwise ignore the header, use the peer address and log it (needs 1.5, 1.51) | unit tests for the header rule; simulation with spoofed headers |
| 1.51 | The app listens only on a local socket inside the pod that only nginx reaches, never on a published port (needs 1.1, 1.3) | unit; simulation with a non-local peer refused |
| 1.52 | Rootless Podman Quadlet units in `deploy/`: one pod on `pasta` networking that publishes only nginx's port, unprivileged, read-only root, `:Z` volumes (private to the pod) mounted only where needed, the token key (1.38), the Ice secret and the Openfire API key mounted as Podman secrets readable only by the service user, `LimitCORE=0` and `Ulimit=core=0` in the app's unit, the service's Ice listener bound to 127.0.0.1 and never published, never privileged or unlabeled (needs a server binary from 1.2 and 1.3) | CI builds the image and runs Quadlet's dry-run generator on each unit; the app unit's dry-run output contains `LimitCORE=0` and `--ulimit core=0` |
| 1.53 | **Decided (2026-10-23):** the SELinux test runs on the maintainer's AlmaLinux test server, through a GitHub runner attached to a separate private repository whose workflow builds only commits already merged to main, never a ref or source from an open pull request, so outside pull requests can never run code on it. It is set up by hand once the server exists | - |
| 1.54 | SELinux enforcing smoke test: start the units on AlmaLinux 10, send a smoke request through Cloudflare's ranges and one from outside them, fail on any AVC denial, if nginx sees a peer other than the real one, or if the request from outside the ranges isn't refused (needs 1.48, 1.49, 1.52, 1.53) | the script itself |

### After the core works

| # | Slice | Tests |
| --- | --- | --- |
| 1.55 | Installer: one command that asks for the EVE app's client ID and secret, the callback URL, the domain, the database and the first admin character, then writes the config and Quadlet units, generates the token key (1.38) and its check value and stores the key as a Podman secret, loads the Cloudflare ranges into firewalld and nginx and starts the services; checks that SELinux is enforcing and never changes its mode | run on the SELinux test machine from 1.54 |

## Milestone 2: taxes

| # | Slice | Tests |
| --- | --- | --- |
| 2.1 | **Decision:** tax rules: rate per ore type, price source (Fuzzwork or Janice), all mining or only corporation moons, interest on unpaid tax | - |
| 2.2 | **Decided (2026-10-23):** the ledger lives in Postgres, shaped like TigerBeetle's accounts and transfers, so a later move to TigerBeetle is a backend swap. The shape is in [architecture.md](architecture.md#ledger) | - |
| 2.3 | Double-entry ledger in the shape from 2.2: accounts with running totals, append-only transfers with app-chosen IDs, pending transfers that post or void, linked batches, behind one Zig interface | unit; fuzz invariants (debits equal credits; a retried transfer posts once; a reused ID with different fields is refused; a pending transfer posts or voids once; a total that would overflow is refused); simulation with Postgres lost mid-batch |
| 2.4 | Price feed import | unit; simulation with the feed down |
| 2.5 | Mining ledger ingestion from ESI | unit |
| 2.6 | Tax calculation per ore type | table-driven unit |
| 2.7 | Payments matched from the corporation wallet by phrase | unit; fuzz the matcher |
| 2.8 | Credits and monthly interest | unit |
| 2.9 | Import balances and payment history | unit with a sample export |
| 2.10 | Unknown characters mining your moons | unit |
| 2.11 | Parity: a month of taxes matches the old app to the ISK | parity run |

## Milestone 3: audits

| # | Slice | Tests |
| --- | --- | --- |
| 3.1 | **Decision:** which audit app's data the importer reads (Member Audit or Corp Tools) | - |
| 3.2 | Skills and skill queue, with history | unit |
| 3.3 | Corporation history | unit |
| 3.4 | Contacts | unit |
| 3.5 | Wallet journal and transactions | unit; simulation with paged routes |
| 3.6 | Assets | unit; simulation |
| 3.7 | Contracts | unit |
| 3.8 | Mail headers and bodies | unit |
| 3.9 | Character finder | unit |
| 3.10 | "Registered every character" check and removal alerts | unit; simulation |
| 3.11 | Audit views, each logged in the audit log | unit |
| 3.12 | Import older audit records | unit with a sample export |

## Milestone 4: SRP

| # | Slice | Tests |
| --- | --- | --- |
| 4.1 | **Decided (2026-10-23):** when a pilot lacks a required skill in a skill-checked ship, the payout is the FC's call, recorded with the FC's name like a waiver | - |
| 4.2 | **Decision:** source for the one-time doctrine and skill-requirement import | - |
| 4.3 | Static data loader for ships, modules and their required skills | unit; fuzz the loader |
| 4.4 | Doctrines with fits and skill sets | unit |
| 4.5 | Programs: alliance and corporation, each with rules, budget and approvers | unit |
| 4.6 | Killmail ingestion from ESI | unit; fuzz the killmail parser |
| 4.7 | Checks: doctrine fit, skills at the moment of the loss (a missing skill goes to the FC, 4.1), ship rules | table-driven unit |
| 4.8 | Reviewer page: fit slot by slot, EFT copy, overrides with a reason, and the FC's call on a missing skill recorded with the FC's name (4.1) | unit |
| 4.9 | Payouts into the ledger: a pending transfer on approval, posted on payout or voided on rejection (needs 2.3) | unit; fuzz ledger invariants |
| 4.10 | Import SRP requests and payouts | unit with a sample export |

## Cutover

| # | Slice | Tests |
| --- | --- | --- |
| 5.1 | Nightly shadow run: re-import and compare without acting | parity run |
| 5.2 | Benchmark in CI: requests per second, p99 latency, memory | benchmark |
| 5.3 | Cutover runbook on the same EVE application, and the way back | dry run |

Version 1 is done when the shadow run shows matching access and a full month of taxes
matching to the ISK, followed by a clean cutover.
