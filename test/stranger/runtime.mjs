import assert from "node:assert/strict";
import * as Schema from "effect/Schema";
import {
  signSeamRequest,
  verifySeamRequest,
  SeamReplayGuard,
  unsignedPayload,
} from "@fungi.computer/seam";
import {
  agentMailAddressSchema,
  createMachineLinkPostChannel,
  decodeMachineLinkControlFrame,
  machineLinkAudience,
  machineLinkDialUrl,
  MachineLinkPostUnavailable,
} from "@fungi.computer/seam/machine-link-protocol";

const mailAddress = {
  scopeId: "team-stranger",
  agentId: "agent-stranger",
};
assert.deepEqual(
  Schema.decodeUnknownSync(agentMailAddressSchema)(mailAddress),
  mailAddress,
);
assert.equal(
  machineLinkAudience("team-stranger", "device-stranger"),
  "fungi-machine-link:team-stranger:device-stranger",
);
assert.equal(
  machineLinkDialUrl(
    "https://local.invalid",
    "team-stranger",
    "device-stranger",
  ).href,
  "https://local.invalid/api/teams/team-stranger/local/mesh/device-stranger/connect",
);
const controlFrame = { type: "leave", agentId: mailAddress.agentId };
assert.deepEqual(
  decodeMachineLinkControlFrame(JSON.stringify(controlFrame)),
  controlFrame,
);
assert.throws(
  () =>
    decodeMachineLinkControlFrame(
      JSON.stringify({ ...controlFrame, type: "unknown" }),
    ),
  Schema.isSchemaError,
);
const postChannel = createMachineLinkPostChannel({
  send: () => assert.fail("a closed channel must not send"),
  receive: async () => assert.fail("a closed channel must not deliver"),
  limits: {
    maxInFlight: 1,
    maxFrameBytes: 512 * 1024,
    acknowledgmentMs: 1_000,
  },
});
postChannel.close();
await assert.rejects(postChannel.receive("{}"), MachineLinkPostUnavailable);
assert.equal(
  new MachineLinkPostUnavailable({ reason: "closed" }).reason,
  "closed",
);

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

// JavaScript providers can return a value outside the TypeScript vocabulary.
// Verification must reject it, not resolve undefined to a no-throw caller.
for (const admit of [() => "unexpected", () => Promise.resolve("unexpected")]) {
  await assert.rejects(
    verifySeamRequest(
      pins,
      "stranger",
      "GET",
      url,
      header,
      null,
      { admit },
      now,
    ),
    {
      name: "SeamAuthError",
      message: "Seam request rejected: replay store unavailable",
    },
  );
}
