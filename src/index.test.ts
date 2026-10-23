import { Buffer } from "node:buffer";
import { generateKeyPairSync } from "node:crypto";
import { expect, it } from "vitest";
import {
  SeamReplayGuard,
  importSeamSigner,
  importSeamVerifiers,
  seamBodyDigest,
  signSeamRequest,
  unsignedPayload,
  verifySeamRequest,
  type SeamReplayAdmission,
  type SeamReplayRecord,
  type SeamReplayStore,
} from "./index.js";

function pair(keyId: string) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    secret: `${keyId}:${privateKey.export({ format: "der", type: "pkcs8" }).toString("base64")}`,
    raw: Buffer.from(
      publicKey.export({ format: "jwk" }).x ?? "",
      "base64url",
    ).toString("base64"),
  };
}

const signerPair = pair("game-host-1");
const wrongPair = pair("game-host-1");
const signer = await importSeamSigner(signerPair.secret);
const verifiers = await importSeamVerifiers({ "game-host-1": signerPair.raw });
const audience = "hub-game-servers";
const url = "https://hub.example/__game-servers/report?check=1";
const body = new TextEncoder().encode('{"teamId":"team_one"}');

it("verifies a signed report once and rejects a replayed nonce", async () => {
  const digest = await seamBodyDigest(body);
  const header = await signSeamRequest(signer, audience, "POST", url, digest);
  const replay = new SeamReplayGuard();
  await expect(
    verifySeamRequest(verifiers, audience, "POST", url, header, digest, replay),
  ).resolves.toBe("game-host-1");
  await expect(
    verifySeamRequest(verifiers, audience, "POST", url, header, digest, replay),
  ).rejects.toThrow(/replayed nonce/u);
});

it("refuses capacity without discarding still-live replay history", () => {
  const replay = new SeamReplayGuard();
  const now = Date.now();
  // Saturate the retained implementation's 10,000-entry private ceiling.
  for (let index = 0; index < 10_000; index += 1)
    expect(
      replay.admit({ nonce: String(index), now, expiresAt: now + 120_000 }),
    ).toBe("admitted");
  expect(
    replay.admit({ nonce: "overflow", now, expiresAt: now + 120_000 }),
  ).toBe("at-capacity");
  expect(replay.admit({ nonce: "0", now, expiresAt: now + 120_000 })).toBe(
    "replayed",
  );
});

it("remembers a nonce through the inclusive freshness boundary", async () => {
  const timestamp = 1_800_000_000_000;
  const header = await signSeamRequest(
    signer,
    audience,
    "GET",
    url,
    unsignedPayload,
    timestamp,
  );
  const replay = new SeamReplayGuard();
  await expect(
    verifySeamRequest(
      verifiers,
      audience,
      "GET",
      url,
      header,
      null,
      replay,
      timestamp - 60_000,
    ),
  ).resolves.toBe("game-host-1");
  await expect(
    verifySeamRequest(
      verifiers,
      audience,
      "GET",
      url,
      header,
      null,
      replay,
      timestamp + 60_000,
    ),
  ).rejects.toThrow(/replayed nonce/u);
});

it("awaits admission before exposing verification success", async () => {
  const now = 1_800_000_000_000;
  const header = await signSeamRequest(
    signer,
    audience,
    "GET",
    url,
    unsignedPayload,
    now,
  );
  const entered = Promise.withResolvers<SeamReplayRecord>();
  const admission = Promise.withResolvers<SeamReplayAdmission>();
  const store: SeamReplayStore = {
    admit: (record) => {
      entered.resolve(record);
      return admission.promise;
    },
  };
  let settled = false;
  const verified = verifySeamRequest(
    verifiers,
    audience,
    "GET",
    url,
    header,
    null,
    store,
    now,
  );
  const observation = verified.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  const record = await entered.promise;
  expect(record.now).toBe(now);
  expect(record.expiresAt).toBe(now + 120_000);
  await Promise.resolve();
  expect(settled).toBe(false);
  admission.resolve("admitted");
  await expect(verified).resolves.toBe("game-host-1");
  await observation;
});

it.each([
  ["replayed", /replayed nonce/u],
  ["at-capacity", /replay capacity/u],
  ["unavailable", /replay store unavailable/u],
] satisfies readonly [SeamReplayAdmission, RegExp][])(
  "fails closed when an asynchronous store answers %s",
  async (decision, diagnostic) => {
    const header = await signSeamRequest(
      signer,
      audience,
      "GET",
      url,
      unsignedPayload,
    );
    await expect(
      verifySeamRequest(verifiers, audience, "GET", url, header, null, {
        admit: () => Promise.resolve(decision),
      }),
    ).rejects.toThrow(diagnostic);
  },
);

it("binds audience, method, URL, body, pinned key, and timestamp", async () => {
  const digest = await seamBodyDigest(body);
  const header = await signSeamRequest(signer, audience, "POST", url, digest);
  const verify = (
    changes: Partial<{
      audience: string;
      method: string;
      url: string;
      digest: string | null;
      now: number;
    }>,
  ) =>
    verifySeamRequest(
      verifiers,
      changes.audience ?? audience,
      changes.method ?? "POST",
      changes.url ?? url,
      header,
      changes.digest === undefined ? digest : changes.digest,
      new SeamReplayGuard(),
      changes.now,
    );
  await expect(verify({ audience: "game-box-1" })).rejects.toThrow(
    /bad signature/u,
  );
  await expect(verify({ method: "GET" })).rejects.toThrow(/bad signature/u);
  await expect(
    verify({ url: "https://hub.example/__game-servers/other" }),
  ).rejects.toThrow(/bad signature/u);
  await expect(
    verify({ digest: await seamBodyDigest(new Uint8Array(1)) }),
  ).rejects.toThrow(/body digest/u);
  await expect(verify({ now: Date.now() + 120_000 })).rejects.toThrow(/skew/u);
  await expect(
    verifySeamRequest(
      await importSeamVerifiers({ "game-host-1": wrongPair.raw }),
      audience,
      "POST",
      url,
      header,
      digest,
      new SeamReplayGuard(),
    ),
  ).rejects.toThrow(/bad signature/u);
});

it("only accepts unsigned payloads for stream routes", async () => {
  const header = await signSeamRequest(
    signer,
    audience,
    "GET",
    url,
    unsignedPayload,
  );
  await expect(
    verifySeamRequest(
      verifiers,
      audience,
      "GET",
      url,
      header,
      null,
      new SeamReplayGuard(),
    ),
  ).resolves.toBe("game-host-1");
});
