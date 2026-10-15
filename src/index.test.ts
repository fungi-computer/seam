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
