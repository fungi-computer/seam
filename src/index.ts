/**
 * Mutual authentication for on-box host seams: every request in either
 * direction is signed with Ed25519 by its sender and verified against a
 * public key the receiver pins.
 *
 * - Down: the Hub signs with the platform seam key; the host pins its public key.
 * - Up: the host signs reports with its host key; the Hub pins it in the host registry.
 *
 * The signature covers an audience (so a request meant for one side cannot
 * be replayed at the other), the method, path and query, a timestamp, a
 * nonce and the body digest. Streaming bodies (forwarded guest traffic,
 * port previews, WebSocket upgrades) sign `UNSIGNED-PAYLOAD` and rely on the
 * TLS transport (Cloudflare Tunnel) for body integrity. Receivers reject a
 * timestamp outside the skew window and a nonce seen within it. Private keys
 * stay with their owner; projections and registries carry public data only.
 *
 * This module is plain Web Crypto so the Worker and the Node.js host share it.
 */
export const seamHeader = "x-fungi-seam";
export const unsignedPayload = "UNSIGNED-PAYLOAD";
const version = "fungi-seam-v1";
const maximumSkewMs = 60_000;
const maximumNonces = 10_000;

export type SeamSigner = Readonly<{ keyId: string; key: CryptoKey }>;
export type SeamVerifiers = ReadonlyMap<string, CryptoKey>;

class SeamAuthError extends Error {
  constructor(reason: string) {
    super(`Seam request rejected: ${reason}`);
    this.name = "SeamAuthError";
  }
}

const keyIdPattern = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const noncePattern = /^[0-9a-f]{32}$/;
const digestPattern = /^([0-9a-f]{64}|UNSIGNED-PAYLOAD)$/;
const signaturePattern = /^[A-Za-z0-9_-]{86}$/;

function bytesFromBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1)
    bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function base64url(bytes: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function bytesFromBase64url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  return bytesFromBase64(padded + "=".repeat((4 - (padded.length % 4)) % 4));
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

/** `keyId:base64(pkcs8)`, the form a Worker secret or key file holds. */
export async function importSeamSigner(secret: string): Promise<SeamSigner> {
  const at = secret.indexOf(":");
  const keyId = secret.slice(0, at);
  if (at < 1 || !keyIdPattern.test(keyId))
    throw new SeamAuthError("the signing key has no valid key id");
  const key = await crypto.subtle.importKey(
    "pkcs8",
    bytesFromBase64(secret.slice(at + 1)),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  return { keyId, key };
}

/** `{ keyId: base64(raw 32-byte public key) }`, the pinned peers. */
export async function importSeamVerifiers(
  publicKeys: Readonly<Record<string, string>>,
): Promise<SeamVerifiers> {
  const verifiers = new Map<string, CryptoKey>();
  for (const [keyId, raw] of Object.entries(publicKeys)) {
    if (!keyIdPattern.test(keyId))
      throw new SeamAuthError(`invalid pinned key id ${keyId}`);
    verifiers.set(
      keyId,
      await crypto.subtle.importKey(
        "raw",
        bytesFromBase64(raw),
        { name: "Ed25519" },
        false,
        ["verify"],
      ),
    );
  }
  return verifiers;
}

/** The body digest to sign: SHA-256 hex of buffered bytes, or unsigned. */
export async function seamBodyDigest(
  body: ArrayBuffer | Uint8Array<ArrayBuffer> | null,
): Promise<string> {
  if (body === null) return unsignedPayload;
  return hex(await crypto.subtle.digest("SHA-256", body));
}

function canonical(
  audience: string,
  keyId: string,
  method: string,
  pathAndQuery: string,
  timestamp: number,
  nonce: string,
  digest: string,
): Uint8Array<ArrayBuffer> {
  // A copy, so the bytes sit in a plain ArrayBuffer Web Crypto accepts.
  return new Uint8Array(
    new TextEncoder().encode(
      [
        version,
        audience,
        keyId,
        method.toUpperCase(),
        pathAndQuery,
        String(timestamp),
        nonce,
        digest,
      ].join("\n"),
    ),
  );
}

function pathAndQueryOf(url: string): string {
  const parsed = new URL(url);
  return `${parsed.pathname}${parsed.search}`;
}

/** The `x-fungi-seam` header value for one request. */
export async function signSeamRequest(
  signer: SeamSigner,
  audience: string,
  method: string,
  url: string,
  digest: string,
  now = Date.now(),
): Promise<string> {
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = hex(nonceBytes.buffer);
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    signer.key,
    canonical(
      audience,
      signer.keyId,
      method,
      pathAndQueryOf(url),
      now,
      nonce,
      digest,
    ),
  );
  return `v1 key=${signer.keyId} ts=${String(now)} nonce=${nonce} body=${digest} sig=${base64url(signature)}`;
}

/** Nonces seen inside the skew window, bounded. */
export class SeamReplayGuard {
  readonly #seen = new Map<string, number>();

  /** Record `nonce`; false if it was already seen and is still live. */
  admit(nonce: string, now: number): boolean {
    this.#prune(now);
    if (this.#seen.has(nonce)) return false;
    this.#makeRoom();
    this.#seen.set(nonce, now + 2 * maximumSkewMs);
    return true;
  }

  #prune(now: number): void {
    for (const [seen, expires] of this.#seen) {
      if (expires > now) break;
      this.#seen.delete(seen);
    }
  }

  #makeRoom(): void {
    if (this.#seen.size < maximumNonces) return;
    const oldest = this.#seen.keys().next();
    if (!oldest.done) this.#seen.delete(oldest.value);
  }
}

type ParsedSeamHeader = Readonly<{
  keyId: string;
  timestamp: number;
  nonce: string;
  digest: string;
  signature: string;
}>;

function seamFields(value: string | null): Map<string, string> {
  const fields = new Map<string, string>();
  const parts = (value ?? "").split(" ");
  if (parts[0] !== "v1") throw new SeamAuthError("missing or unknown version");
  for (const part of parts.slice(1)) {
    const [name, field] = seamField(part);
    fields.set(name, field);
  }
  return fields;
}

function seamField(part: string): readonly [string, string] {
  const at = part.indexOf("=");
  if (at < 1) throw new SeamAuthError("malformed header");
  return [part.slice(0, at), part.slice(at + 1)];
}

function requiredField(fields: Map<string, string>, name: string): string {
  return fields.get(name) ?? "";
}

function parseSeamHeader(value: string | null): ParsedSeamHeader {
  const fields = seamFields(value);
  const parsed = {
    keyId: requiredField(fields, "key"),
    timestamp: Number(fields.get("ts")),
    nonce: requiredField(fields, "nonce"),
    digest: requiredField(fields, "body"),
    signature: requiredField(fields, "sig"),
  };
  if (fields.size !== 5 || !validSeamHeader(parsed))
    throw new SeamAuthError("malformed header");
  return parsed;
}

function validSeamHeader(header: ParsedSeamHeader): boolean {
  return [
    keyIdPattern.test(header.keyId),
    Number.isSafeInteger(header.timestamp),
    noncePattern.test(header.nonce),
    digestPattern.test(header.digest),
    signaturePattern.test(header.signature),
  ].every(Boolean);
}

/**
 * Verify one request's seam header. `digest` is the receiver's own digest of
 * the buffered body, or `null` when the route accepts an unsigned stream.
 * Answers the sender's key id.
 */
export async function verifySeamRequest(
  verifiers: SeamVerifiers,
  audience: string,
  method: string,
  url: string,
  header: string | null,
  digest: string | null,
  replay: SeamReplayGuard,
  now = Date.now(),
): Promise<string> {
  const parsed = parseSeamHeader(header);
  const key = verifiers.get(parsed.keyId);
  if (key === undefined) throw new SeamAuthError("unknown key");
  assertSeamFreshness(parsed, digest, now);
  const valid = await crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    bytesFromBase64url(parsed.signature),
    canonical(
      audience,
      parsed.keyId,
      method,
      pathAndQueryOf(url),
      parsed.timestamp,
      parsed.nonce,
      parsed.digest,
    ),
  );
  if (!valid) throw new SeamAuthError("bad signature");
  if (!replay.admit(parsed.nonce, now))
    throw new SeamAuthError("replayed nonce");
  return parsed.keyId;
}

function assertSeamFreshness(
  parsed: ParsedSeamHeader,
  digest: string | null,
  now: number,
): void {
  if (Math.abs(now - parsed.timestamp) > maximumSkewMs)
    throw new SeamAuthError("timestamp outside the skew window");
  assertSeamDigest(parsed.digest, digest);
}

function assertSeamDigest(signed: string, digest: string | null): void {
  const expected = digest ?? unsignedPayload;
  if (signed === expected) return;
  throw new SeamAuthError(
    digest === null
      ? "route takes an unsigned stream only"
      : "body digest mismatch",
  );
}
