import * as Data from "effect/Data";
import * as Schema from "effect/Schema";
import {
  PostDeliveryResultSchema,
  PostEnvelopeSchema,
  type PostDeliveryResult,
  type PostEnvelope,
} from "@fungi.computer/carrier/post";

const identitySchema = Schema.Struct({
  key: PostEnvelopeSchema.fields.key,
  kind: PostEnvelopeSchema.fields.kind,
  address: PostEnvelopeSchema.fields.address,
});
const frameSchema = Schema.Union([
  Schema.Struct({
    type: Schema.Literal("post"),
    envelope: PostEnvelopeSchema,
  }),
  Schema.Struct({
    type: Schema.Literal("receipt"),
    identity: identitySchema,
    result: PostDeliveryResultSchema,
  }),
]);
const positiveInteger = Schema.Int.check(
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(Number.MAX_SAFE_INTEGER),
);
const limitsSchema = Schema.Struct({
  maxInFlight: positiveInteger,
  maxFrameBytes: positiveInteger,
  acknowledgmentMs: Schema.Int.check(
    Schema.isGreaterThanOrEqualTo(1),
    // The maintained platform timer cannot represent a larger delay.
    Schema.isLessThanOrEqualTo(2_147_483_647),
  ),
});

/** No receiver receipt was obtained. Carrier, not Seam, retains retries. */
export class MachineLinkPostUnavailable extends Data.TaggedError(
  "MachineLinkPostUnavailable",
)<{
  /** Transient transport failure; none of these asserts command refusal. */
  readonly reason: "closed" | "busy" | "timed_out" | "send_failed";
  /** The native send failure, when the platform supplied one. */
  readonly cause?: unknown;
}> {}

function identity(envelope: Pick<PostEnvelope, "key" | "kind" | "address">) {
  return {
    key: envelope.key,
    kind: envelope.kind,
    address: envelope.address,
  };
}

/**
 * One connection's bounded Post I/O, without an outbox, dedupe store or RPC
 * capability table. Native socket ownership and authentication stay with the
 * host. Reconstruct after hibernation when idle; close on disconnect/restart
 * and let the existing Carrier outbox retry the same frozen envelope.
 *
 * Receipt payloads remain opaque. The Agent mail route still requires a real
 * Shiitake Accepted receipt; a generic Post acknowledgment is not one.
 */
export function createMachineLinkPostChannel(options: {
  send: (frame: string) => void | Promise<void>;
  receive: (envelope: PostEnvelope) => Promise<PostDeliveryResult>;
  limits: {
    maxInFlight: number;
    maxFrameBytes: number;
    acknowledgmentMs: number;
  };
}) {
  const limits = Schema.decodeUnknownSync(limitsSchema)(options.limits);
  const decode = Schema.decodeUnknownSync(Schema.fromJsonString(frameSchema), {
    onExcessProperty: "error",
  });
  type Pending = {
    resolve: (result: PostDeliveryResult) => void;
    reject: (error: MachineLinkPostUnavailable) => void;
    timer: ReturnType<typeof setTimeout>;
  };
  const pending = new Map<string, Pending>();
  let closed = false;
  let receiving = 0;

  function checkSize(text: string) {
    if (new TextEncoder().encode(text).byteLength > limits.maxFrameBytes)
      throw new RangeError("Machine link Post frame exceeds its byte ceiling");
  }

  async function send(text: string) {
    if (closed) throw new MachineLinkPostUnavailable({ reason: "closed" });
    checkSize(text);
    await options.send(text);
  }

  function take(key: string) {
    const entry = pending.get(key);
    if (entry !== undefined) {
      pending.delete(key);
      clearTimeout(entry.timer);
    }
    return entry;
  }

  return {
    /** Send now; never acknowledge custody before the receiver replies. */
    deliver: async (envelope: PostEnvelope): Promise<PostDeliveryResult> => {
      if (closed) throw new MachineLinkPostUnavailable({ reason: "closed" });
      const key = JSON.stringify(identity(envelope));
      if (pending.has(key) || pending.size >= limits.maxInFlight)
        throw new MachineLinkPostUnavailable({ reason: "busy" });
      const text = JSON.stringify({ type: "post", envelope });
      checkSize(text);
      return new Promise<PostDeliveryResult>((resolve, reject) => {
        const timer = setTimeout(() => {
          take(key)?.reject(
            new MachineLinkPostUnavailable({ reason: "timed_out" }),
          );
        }, limits.acknowledgmentMs);
        pending.set(key, { resolve, reject, timer });
        void send(text).catch((cause: unknown) => {
          take(key)?.reject(
            new MachineLinkPostUnavailable({
              reason: "send_failed",
              cause,
            }),
          );
        });
      });
    },
    /** Called only for a host-authenticated, current native socket. */
    receive: async (text: string): Promise<void> => {
      if (closed) throw new MachineLinkPostUnavailable({ reason: "closed" });
      checkSize(text);
      const frame = decode(text);
      if (frame.type === "receipt") {
        // Late receipts cannot create custody or a future successful send.
        take(JSON.stringify(identity(frame.identity)))?.resolve(frame.result);
        return;
      }
      if (receiving >= limits.maxInFlight)
        throw new MachineLinkPostUnavailable({ reason: "busy" });
      receiving += 1;
      try {
        const result = Schema.decodeUnknownSync(PostDeliveryResultSchema)(
          await options.receive(frame.envelope),
        );
        await send(
          JSON.stringify({
            type: "receipt",
            identity: identity(frame.envelope),
            result,
          }),
        );
      } finally {
        receiving -= 1;
      }
    },
    /** Forget only pending I/O. The durable sender still owns undelivered work. */
    close: (): void => {
      closed = true;
      for (const key of pending.keys())
        take(key)?.reject(new MachineLinkPostUnavailable({ reason: "closed" }));
    },
  };
}
