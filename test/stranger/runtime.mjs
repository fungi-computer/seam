import assert from "node:assert/strict";
import {
  signSeamRequest,
  verifySeamRequest,
  SeamReplayGuard,
  unsignedPayload,
} from "@fungi.computer/seam";
const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
  "sign",
  "verify",
]);
const signer = { keyId: "stranger", key: pair.privateKey };
const pins = new Map([["stranger", pair.publicKey]]);
const replay = new SeamReplayGuard();
const now = Date.now();
const url = "https://local.invalid/probe";
const header = await signSeamRequest(
  signer,
  "stranger",
  "GET",
  url,
  unsignedPayload,
  now,
);
assert.equal(
  await verifySeamRequest(
    pins,
    "stranger",
    "GET",
    url,
    header,
    null,
    replay,
    now,
  ),
  "stranger",
);
await assert.rejects(
  verifySeamRequest(pins, "stranger", "GET", url, header, null, replay, now),
  /replayed nonce/u,
);
