# Fungi host seam

Owns the Ed25519 request authentication protocol between the Hub and its on-box
hosts. Consumers import `@fungi.computer/seam`. The moved implementation and
replay/signature tests retain their original behavior. Keys remain with the
operator; no keys are stored in this package. The package ships the protocol and
replay guard; hosts own key provisioning.

`@fungi.computer/seam/machine-link-protocol` owns the shared machine-link
audience/dial URL, bounded read/leave and Agent-operation grammar, Agent mail
address schema, and `createMachineLinkPostChannel`. The channel carries ordinary
Carrier Post envelopes and receipts; Carrier retains retries. Hosts own live
authorization, socket lifetime and durable replay storage. Delegation request
keys and execution policy remain with the delegation engine, not Seam.

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
const record = {
  nonce: "00112233445566778899aabbccddeeff",
  now,
  expiresAt: now + 120_000,
};
console.log(replay.admit(record)); // admitted
console.log(replay.admit(record)); // replayed
```

## Core concepts

The sender signs method, audience, path, timestamp, nonce and payload digest.
The receiver checks the signature, freshness and replay guard against its pinned
keys.

`verifySeamRequest` accepts one `SeamReplayStore`. It verifies the signature
before awaiting atomic admission, and supplies a deadline covering the complete
freshness window, including its last instant. The store must preserve that
deadline, record before reporting success, and refuse at its finite capacity
rather than evict still-live nonces. Its closed decisions are `admitted`,
`replayed`, `at-capacity`, and `unavailable`; all refusals fail verification.

`SeamReplayGuard` is the process-local implementation, with a private
10,000-record ceiling. It is not persistent. A durable receiver must bind one
store to its reconstruction-stable receiver namespace; storage and numeric
capacity are host implementation decisions. There is no memory fallback on
persistence failure. A record remains live when `expiresAt === now`; prune only
strictly older deadlines, without assuming insertion order is expiry order.

## Examples and checks

The packed runtime fixture at `test/stranger/runtime.mjs` exercises the public
API in a fresh consumer. Run `pnpm run stranger` after building the package.

## Install

Install the package tarball with npm. The manifest pins its runtime
dependencies.

## Contribute and license

See [LICENSE](LICENSE) for the MIT terms.
