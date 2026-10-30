# Coalition Connection

An open-source auth platform for EVE Online coalitions, written in Zig, meant to replace
Alliance Auth one day. It's a hobby project, vibe coded for fun and testing.

## Status

Not usable yet. The project is before 1.0, and nothing has been released. Between releases,
`main` is the next version with `-dev`, so today it is `0.1.0-dev`. The first release, 0.1,
is a page served through Cloudflare and nginx under SELinux; [docs/roadmap.md](docs/roadmap.md)
has the full release plan.

## Building and testing

You need exactly Zig 0.17.0, the latest stable release, which CI pins. Other versions aren't
supported. From the repository root:

```sh
zig fmt --check build.zig src fuzz sim   # formatting
zig build test                           # unit tests in Debug
zig build test --release=safe            # unit tests in ReleaseSafe
zig build fuzz --release=safe -Dseed=1   # seeded fuzzer
zig build sim --release=safe -Dseed=1    # seeded deterministic simulation
```

The last three compile every target in ReleaseSafe. A fuzz or simulation failure prints its
seed, and the same `-Dseed` replays it. [CONTRIBUTING.md](CONTRIBUTING.md#running-the-checks)
lists every check CI runs.

## Documentation

- [docs/architecture.md](docs/architecture.md): the components, the rules every one of them
  follows, and how each is tested.
- [docs/roadmap.md](docs/roadmap.md): the release plan and the work each release needs.
- [CONTRIBUTING.md](CONTRIBUTING.md): what gets merged, signing your commits, and the coding
  standards.
- [SECURITY.md](SECURITY.md): how to report a vulnerability privately, never in a public
  issue, pull request or discussion.

## License

[Apache-2.0](LICENSE).

EVE Online is a trademark of CCP hf. This project is not affiliated with or endorsed by CCP.
