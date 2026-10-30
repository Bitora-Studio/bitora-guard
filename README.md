# @bitora/guard

Server-side guard for web apps: it reads the requests and answers of your app (brute force, credential stuffing, enumeration,
scans, injection attempts) and reports them to [Bitora Security](https://security.bitora.es). It starts in `observe` mode, has no
runtime dependencies and fails open: if anything goes wrong, your app keeps serving.

**It needs an active Bitora Security subscription.** Without one it does nothing and lets all traffic through. See the
[licence section](pkg/README.md#licence-and-subscription).

```sh
npm i @bitora/guard
```

Usage, options and limits are in [`pkg/README.md`](pkg/README.md).

This repository is the public mirror of the package source: the code that is published to npm is built and published from here by
GitHub Actions (trusted publishing, with provenance). Licence: [Bitora Guard Licence](LICENSE) from 3.0.0 (the source is visible; use needs a subscription). Versions 2.0.0 to 2.1.2 were MIT and are no longer on npm.
