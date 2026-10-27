# Security policy

Coalition Connection is a hobby project, vibe coded for fun and testing. It handles EVE Online
SSO logins and ESI tokens, so security reports are welcome and taken seriously.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Fill in the form.

Only the maintainer and you can see the report. Please include:

- what the problem is and what an attacker could do with it;
- the commit or branch you tested;
- steps to reproduce it, ideally a failing test or a seed for `zig build sim` or
  `zig build fuzz`;
- whether you have told anyone else.

You will get a reply in the report. This is a hobby project run in spare time, so there is no
guaranteed response time and no bug bounty. Once a fix is merged, the plan is to publish an
advisory that credits you, unless you ask not to be.

## Supported versions

There is no release yet. Until 1.0 ships, only the `main` branch gets security fixes;
older commits and branches do not. This section will say which releases get fixes once
1.0 is out.

## Scope

In scope: the code in this repository, for example

- logging in as a character you don't own, or linking an alt to someone else's main;
- reading or changing data that your states, groups or permissions shouldn't allow;
- leaking ESI tokens, session tokens or other secrets;
- getting around the deployment rules in [docs/architecture.md](docs/architecture.md), such as
  faking a client IP or reaching the origin without going through Cloudflare;
- crashes, hangs or memory-safety bugs triggered by network input.

Out of scope, please report these to their owners instead:

- EVE Online, its SSO and ESI (CCP Games);
- Cloudflare, Podman, Mumble, XMPP servers, Zig itself and other upstream software;
- problems that need an already compromised server or admin account;
- social engineering and denial of service by sheer traffic volume.
