import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";
import * as Schema from "effect/Schema";
import {
  agentMailAddressSchema,
  createMachineLinkPostChannel,
  decodeMachineLinkControlFrame,
} from "@fungi.computer/seam/machine-link-protocol";

test("Agent mail addresses preserve the bounded scope and Agent grammar", () => {
  const decode = Schema.decodeUnknownSync(agentMailAddressSchema, {
    onExcessProperty: "error",
  });
  const address = { scopeId: "team-one", agentId: "agent-one" };
  assert.deepEqual(decode(address), address);
  for (const field of ["scopeId", "agentId"]) {
    assert.equal(
      decode({ ...address, [field]: "a".repeat(256) })[field].length,
      256,
    );
    for (const value of ["", "a".repeat(257), undefined, null, 1]) {
      assert.throws(
        () => decode({ ...address, [field]: value }),
        Schema.isSchemaError,
      );
    }
  }
  assert.throws(
    () => decode({ ...address, callerRequestId: "not-address-policy" }),
    Schema.isSchemaError,
  );
});

test("a live transcript read preserves the Session owner's opaque before cursor", () => {
  const frame = {
    type: "read",
    requestId: "read-one",
    agentId: "agent-one",
    sessionId: "session-one",
    before: "owner:cursor/二",
    limit: 64,
  };
  assert.deepEqual(decodeMachineLinkControlFrame(JSON.stringify(frame)), frame);
});

test("a transcript read requires an integer page limit from one through 64", () => {
  const frame = {
    type: "read",
    requestId: "read-one",
    agentId: "agent-one",
    sessionId: "session-one",
  };
  for (const limit of [1, 64]) {
    const bounded = { ...frame, limit };
    assert.deepEqual(
      decodeMachineLinkControlFrame(JSON.stringify(bounded)),
      bounded,
    );
  }
  for (const limit of [0, -1, 1.5, 65, undefined, null, "1", true]) {
    assert.throws(
      () => decodeMachineLinkControlFrame(JSON.stringify({ ...frame, limit })),
      Schema.isSchemaError,
    );
  }
});

test("read identifies one Session without admitting extra authority or another cursor grammar", () => {
  const frame = {
    type: "read",
    requestId: "read-one",
    agentId: "agent-one",
    sessionId: "session-one",
    limit: 1,
  };
  assert.deepEqual(decodeMachineLinkControlFrame(JSON.stringify(frame)), frame);
  for (const field of ["requestId", "agentId", "sessionId"]) {
    const boundary = { ...frame, [field]: "a".repeat(256) };
    assert.deepEqual(
      decodeMachineLinkControlFrame(JSON.stringify(boundary)),
      boundary,
    );
    for (const value of ["", "a".repeat(257), undefined, null, 1]) {
      assert.throws(
        () =>
          decodeMachineLinkControlFrame(
            JSON.stringify({ ...frame, [field]: value }),
          ),
        Schema.isSchemaError,
      );
    }
  }
  for (const extra of [
    { cursor: "not-the-owner-before-option" },
    { commandId: "not-an-execution-request" },
    { includeSandboxFailures: true },
    { before: 1 },
    { before: null },
  ]) {
    assert.throws(
      () =>
        decodeMachineLinkControlFrame(JSON.stringify({ ...frame, ...extra })),
      Schema.isSchemaError,
    );
  }
});

test("an opaque read cursor remains subject to the shared UTF-8 frame ceiling", () => {
  const json = JSON.stringify({
    type: "read",
    requestId: "read-one",
    agentId: "agent-one",
    sessionId: "session-one",
    before: "é".repeat(256 * 1024),
    limit: 1,
  });
  assert.ok(json.length < 512 * 1024);
  assert.throws(() => decodeMachineLinkControlFrame(json), RangeError);
});

test("a machine's JSON leave frame names the Team Agent, not another delivery address", () => {
  const frame = { type: "leave", agentId: "agent-one" };
  assert.deepEqual(decodeMachineLinkControlFrame(JSON.stringify(frame)), frame);
});

test("the frame ceiling is 512 KiB of UTF-8, not JavaScript characters", () => {
  const frame = { type: "leave", agentId: "é" };
  const json = JSON.stringify(frame);
  const exact = json + " ".repeat(512 * 1024 - Buffer.byteLength(json, "utf8"));
  assert.deepEqual(decodeMachineLinkControlFrame(exact), frame);
  const tooLarge = json + " ".repeat(512 * 1024 - json.length);
  assert.equal(tooLarge.length, 512 * 1024);
  assert.equal(Buffer.byteLength(tooLarge, "utf8"), 512 * 1024 + 1);
  assert.throws(() => decodeMachineLinkControlFrame(tooLarge), RangeError);
});

test("leave cannot smuggle a command receipt or a different routing representation", () => {
  for (const extra of [
    { commandId: "not-an-accepted-command" },
    { deviceId: "not-an-attestation" },
    { sessionId: "not-a-session-operation" },
  ]) {
    assert.throws(
      () =>
        decodeMachineLinkControlFrame(
          JSON.stringify({ type: "leave", agentId: "agent-one", ...extra }),
        ),
      Schema.isSchemaError,
    );
  }
});

test("leave requires a bounded opaque Agent identity and valid JSON", () => {
  const boundary = { type: "leave", agentId: "a".repeat(256) };
  assert.deepEqual(
    decodeMachineLinkControlFrame(JSON.stringify(boundary)),
    boundary,
  );
  for (const frame of [
    null,
    [],
    {},
    { type: "leave" },
    { type: "leave", agentId: "" },
    { type: "leave", agentId: "a".repeat(257) },
    { type: "leave", agentId: 1 },
    { type: "mail", agentId: "agent-one" },
  ]) {
    assert.throws(
      () => decodeMachineLinkControlFrame(JSON.stringify(frame)),
      Schema.isSchemaError,
    );
  }
  assert.throws(() => decodeMachineLinkControlFrame("{"), Schema.isSchemaError);
});

const postLimits = {
  maxInFlight: 4,
  maxFrameBytes: 512 * 1024,
  acknowledgmentMs: 10_000,
};
const post = {
  key: "same-key",
  kind: "agentMail",
  address: { scopeId: "team", agentId: "a" },
  event: { text: "opaque cargo" },
};

test("Post receipts correlate by kind, address and key without rewriting cargo", async () => {
  const outbound = [];
  const receipts = [];
  const received = [];
  const sender = createMachineLinkPostChannel({
    limits: postLimits,
    send: (text) => outbound.push(text),
    receive: () => Promise.resolve("refused"),
  });
  const receiver = createMachineLinkPostChannel({
    limits: postLimits,
    send: (text) => receipts.push(text),
    receive: (envelope) => {
      received.push(envelope);
      return Promise.resolve({
        status: "accepted",
        cursor: received.length,
      });
    },
  });
  const other = { ...post, address: { scopeId: "team", agentId: "b" } };
  const first = sender.deliver(post);
  const second = sender.deliver(other);
  await receiver.receive(outbound[1]);
  await receiver.receive(outbound[0]);
  await sender.receive(receipts[0]);
  await sender.receive(receipts[1]);
  assert.deepEqual(await first, { status: "accepted", cursor: 2 });
  assert.deepEqual(await second, { status: "accepted", cursor: 1 });
  assert.deepEqual(received, [other, post]);
  sender.close();
  receiver.close();
});

test("disconnect cannot turn a pending send or late receipt into custody", async () => {
  const sent = [];
  const receipts = [];
  const channel = createMachineLinkPostChannel({
    limits: postLimits,
    send: (text) => sent.push(text),
    receive: () => Promise.resolve("refused"),
  });
  const peer = createMachineLinkPostChannel({
    limits: postLimits,
    send: (text) => receipts.push(text),
    receive: () => Promise.resolve({ status: "accepted", cursor: 1 }),
  });
  const pending = channel.deliver(post);
  assert.equal(sent.length, 1);
  await peer.receive(sent[0]);
  channel.close();
  await assert.rejects(pending, { reason: "closed" });
  await assert.rejects(channel.receive(receipts[0]), { reason: "closed" });
  await assert.rejects(channel.deliver(post), { reason: "closed" });
  peer.close();
});

test("an unsolicited receipt is not saved as a future delivery result", async () => {
  const sent = [];
  const receipts = [];
  const original = createMachineLinkPostChannel({
    limits: postLimits,
    send: (text) => sent.push(text),
    receive: () => Promise.resolve("refused"),
  });
  const peer = createMachineLinkPostChannel({
    limits: postLimits,
    send: (text) => receipts.push(text),
    receive: () => Promise.resolve({ status: "accepted", cursor: 1 }),
  });
  const pending = original.deliver(post);
  await peer.receive(sent[0]);
  original.close();
  await assert.rejects(pending, { reason: "closed" });
  const successor = createMachineLinkPostChannel({
    limits: postLimits,
    send: () => undefined,
    receive: () => Promise.resolve("refused"),
  });
  await successor.receive(receipts[0]);
  const retry = successor.deliver(post);
  successor.close();
  await assert.rejects(retry, { reason: "closed" });
  peer.close();
});

test("the private in-flight ceiling refuses I/O, not future durable work", async () => {
  const channel = createMachineLinkPostChannel({
    limits: { ...postLimits, maxInFlight: 1 },
    send: () => undefined,
    receive: () => Promise.resolve("refused"),
  });
  const pending = channel.deliver(post);
  await assert.rejects(channel.deliver({ ...post, key: "next-key" }), {
    reason: "busy",
  });
  channel.close();
  await assert.rejects(pending, { reason: "closed" });
});

test("an absent receipt expires without inventing an admission outcome", async () => {
  const channel = createMachineLinkPostChannel({
    limits: { ...postLimits, acknowledgmentMs: 1 },
    send: () => undefined,
    receive: () => Promise.resolve("refused"),
  });
  await assert.rejects(channel.deliver(post), { reason: "timed_out" });
  channel.close();
});

test("a failed native send preserves its cause instead of swallowing it", async () => {
  const cause = new Error("socket is no longer writable");
  const channel = createMachineLinkPostChannel({
    limits: postLimits,
    send: () => {
      throw cause;
    },
    receive: () => Promise.resolve("refused"),
  });
  await assert.rejects(channel.deliver(post), (error) => {
    assert.equal(error.reason, "send_failed");
    assert.equal(error.cause, cause);
    return true;
  });
  channel.close();
});

test("an asynchronous native authority refusal rejects pending delivery with its cause", async () => {
  const cause = new Error("native host no longer authorizes this connection");
  const channel = createMachineLinkPostChannel({
    limits: postLimits,
    send: async () => {
      throw cause;
    },
    receive: () => Promise.resolve("refused"),
  });
  await assert.rejects(channel.deliver(post), (error) => {
    assert.equal(error.reason, "send_failed");
    assert.equal(error.cause, cause);
    return true;
  });
  channel.close();
});

test("concurrent receiver applications are bounded and release their slot", async () => {
  const application = Promise.withResolvers();
  const receipts = [];
  const channel = createMachineLinkPostChannel({
    limits: { ...postLimits, maxInFlight: 1 },
    send: (text) => receipts.push(text),
    receive: () => application.promise,
  });
  const frame = JSON.stringify({ type: "post", envelope: post });
  const first = channel.receive(frame);
  await assert.rejects(channel.receive(frame), { reason: "busy" });
  application.resolve({ status: "accepted", cursor: 1 });
  await first;
  await channel.receive(frame);
  assert.equal(receipts.length, 2);
  channel.close();
});

test("a receiver failure is not rewritten into a permanent refusal", async () => {
  const receipts = [];
  const unavailable = new Error("receiver unavailable");
  const channel = createMachineLinkPostChannel({
    limits: postLimits,
    send: (text) => receipts.push(text),
    receive: () => Promise.reject(unavailable),
  });
  await assert.rejects(
    channel.receive(JSON.stringify({ type: "post", envelope: post })),
    (error) => error === unavailable,
  );
  assert.deepEqual(receipts, []);
  channel.close();
});

test("serialized Post frames use the maintained decoder and UTF-8 byte ceiling", async () => {
  let deliveries = 0;
  const channel = createMachineLinkPostChannel({
    limits: { ...postLimits, maxFrameBytes: 256 },
    send: () => undefined,
    receive: () => {
      deliveries += 1;
      return Promise.resolve("accepted");
    },
  });
  await assert.rejects(channel.receive("{"), Schema.isSchemaError);
  await assert.rejects(
    channel.receive('{"type":"post","envelope":null}'),
    Schema.isSchemaError,
  );
  const oversized = { ...post, event: "🌱".repeat(100) };
  await assert.rejects(channel.deliver(oversized), RangeError);
  await assert.rejects(
    channel.receive(JSON.stringify({ type: "post", envelope: oversized })),
    RangeError,
  );
  assert.equal(deliveries, 0);
  channel.close();
});
