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
