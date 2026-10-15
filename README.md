# Fungi host seam

Owns the Ed25519 request authentication protocol between the Hub and its on-box
hosts. Consumers import `@fungi.computer/seam`. The moved implementation and
replay/signature tests retain their original behavior. Keys remain with the
operator; no keys are stored in this package. The package ships the protocol and
replay guard; hosts own key provisioning.

Run `pnpm --filter @fungi.computer/seam test` for signature, audience, body and
replay laws. Computer and game-server host tests exercise its real consumers.

## Packed consumer readiness

Run `pnpm run build`, `pnpm run pack` and `pnpm run stranger` in this package.
The maintained stranger proof installs only package tarballs into a fresh npm
consumer, checks the exact shipped files, runs the public runtime fixture and
compiles every JavaScript entrypoint with strict NodeNext and no library-check
skip. This qualification does not publish npm releases or push a repository
split.

See [LICENSE](LICENSE) for the license and the package manifest for its public
repository destination.

## Quick start

```ts
import { SeamReplayGuard } from "@fungi.computer/seam";

const replay = new SeamReplayGuard();
const now = Date.now();
console.log(replay.admit("00112233445566778899aabbccddeeff", now));
console.log(replay.admit("00112233445566778899aabbccddeeff", now));
```

## Core concepts

The sender signs method, audience, path, timestamp, nonce and payload digest.
The receiver checks the signature, freshness and replay guard against its pinned
keys.

## Examples and checks

The packed runtime fixture at `test/stranger/runtime.mjs` exercises the public
API in a fresh consumer. Run `pnpm run stranger` after building the package.

## Install

Install the package tarball with npm. The manifest pins its runtime
dependencies.

## Contribute and license

See [LICENSE](LICENSE) for the MIT terms.
