import { SeamReplayGuard } from "@fungi.computer/seam";

const replay = new SeamReplayGuard();
const now = Date.now();
console.log(replay.admit("00112233445566778899aabbccddeeff", now));
console.log(replay.admit("00112233445566778899aabbccddeeff", now));
