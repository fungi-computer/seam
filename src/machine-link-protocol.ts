import * as Schema from "effect/Schema";
export {
  createMachineLinkPostChannel,
  MachineLinkPostUnavailable,
} from "./machine-link-post.js";

/** Shared signature audience; neither names nor private Local selectors enter it. */
export function machineLinkAudience(teamId: string, deviceId: string): string {
  return `fungi-machine-link:${teamId}:${deviceId}`;
}

/** The exact GET path signed by Local and verified by its receiving link. */
export function machineLinkDialUrl(
  issuer: string,
  teamId: string,
  deviceId: string,
): URL {
  return new URL(
    `/api/teams/${encodeURIComponent(teamId)}/local/mesh/${encodeURIComponent(deviceId)}/connect`,
    issuer,
  );
}

const identitySchema = Schema.String.check(
  Schema.isMinLength(1),
  Schema.isMaxLength(256),
);

/** Post destination only; delegation keys and admission belong to their engine. */
export type AgentMailAddress = {
  /** Owning Team or standalone scope, a nonempty identity of at most 256 characters. */
  readonly scopeId: string;
  /** Destination Agent, a nonempty identity of at most 256 characters. */
  readonly agentId: string;
};

/** Maintained decoder for the shared Post address, not delegation authority. */
export const agentMailAddressSchema: Schema.Codec<AgentMailAddress> =
  Schema.Struct({
    scopeId: identitySchema,
    agentId: identitySchema,
  });

/** Idempotent Session creation requested through an authorized machine link. */
export type MachineAgentCreateSession = {
  /** Finite operation discriminator. */
  readonly type: "createSession";
  /** Caller-owned creation intent, a nonempty identity of at most 256 characters. */
  readonly requestId: string;
};

/** Read the destination owner's outcome for one previously accepted command. */
export type MachineAgentSettlement = {
  /** Finite operation discriminator. */
  readonly type: "settlement";
  /** Requesting Agent; the receiver still checks its relationship to the command. */
  readonly requesterAgentId: string;
  /** Recipient Session identity, nonempty and at most 256 characters. */
  readonly sessionId: string;
  /** Original Accepted command identity, nonempty and at most 256 characters. */
  readonly commandId: string;
};

/** Finite Agent operations, not an arbitrary HTTP/RPC tunnel. */
export type MachineAgentOperation =
  MachineAgentCreateSession | MachineAgentSettlement;

/** Decode operation grammar without granting access to an Agent or Session. */
export const machineAgentOperationSchema: Schema.Codec<MachineAgentOperation> =
  Schema.Union([
    Schema.Struct({
      type: Schema.Literal("createSession"),
      requestId: identitySchema,
    }),
    Schema.Struct({
      type: Schema.Literal("settlement"),
      requesterAgentId: identitySchema,
      sessionId: identitySchema,
      commandId: identitySchema,
    }),
  ]);
/** An operation plus its host-derived caller, still subject to receiver admission. */
export type MachineAgentRequest = {
  /** Calling Agent identity; syntax alone never authenticates this field. */
  readonly actorAgentId: string;
  /** The finite operation to admit at the destination. */
  readonly operation: MachineAgentOperation;
};

/** Decode the request representation, not caller authority. */
export const machineAgentRequestSchema: Schema.Codec<MachineAgentRequest> =
  Schema.Struct({
    actorAgentId: identitySchema,
    operation: machineAgentOperationSchema,
  });
/** One public Agent directory entry, without a private Local selector or path. */
export type MachineDirectoryAgent = {
  /** Team Agent identity, nonempty and at most 256 characters. */
  readonly agentId: string;
  /** Display label of at most 256 characters. */
  readonly name: string;
};

/** Bounded directory representation sent by an enrolled machine. */
export type MachineDirectory = {
  /** At most 256 public Agent entries; the host checks their enrollment. */
  readonly agents: readonly MachineDirectoryAgent[];
};

/** Decode the bounded directory representation without admitting its entries. */
export const machineDirectorySchema: Schema.Codec<MachineDirectory> =
  Schema.Struct({
    agents: Schema.Array(
      Schema.Struct({
        agentId: identitySchema,
        name: Schema.String.check(Schema.isMaxLength(256)),
      }),
    ).check(Schema.isMaxLength(256)),
  });

const leaveFrameSchema = Schema.Struct({
  type: Schema.Literal("leave"),
  agentId: identitySchema,
});

const readFrameSchema = Schema.Struct({
  type: Schema.Literal("read"),
  requestId: identitySchema,
  agentId: identitySchema,
  sessionId: identitySchema,
  // Session.read() pages before its opaque oldestCursor, not after a stream.
  before: Schema.optionalKey(Schema.String),
  limit: Schema.Int.check(
    Schema.isGreaterThanOrEqualTo(1),
    Schema.isLessThanOrEqualTo(64),
  ),
});

const controlFrameSchema = Schema.Union([leaveFrameSchema, readFrameSchema]);

/** Ask the owner to remove one enrolled Team Agent projection. */
export type MachineLinkLeaveFrame = {
  /** Finite control discriminator. */
  readonly type: "leave";
  /** Team Agent identity, nonempty and at most 256 characters. */
  readonly agentId: string;
};

/** Read one bounded transcript page through the Session owner's ordinary cursor. */
export type MachineLinkReadFrame = {
  /** Finite control discriminator. */
  readonly type: "read";
  /** Correlation identity, nonempty and at most 256 characters. */
  readonly requestId: string;
  /** Team Agent identity, nonempty and at most 256 characters. */
  readonly agentId: string;
  /** Session identity, nonempty and at most 256 characters. */
  readonly sessionId: string;
  /** Opaque older-page cursor from Session.read(), not a transport stream cursor. */
  readonly before?: string;
  /** Integer page bound from one through 64. */
  readonly limit: number;
};

/** Non-mail requests, not authenticated membership or admitted Session access. */
export type MachineLinkControlFrame =
  MachineLinkLeaveFrame | MachineLinkReadFrame;

/** Decode JSON only; the host still owns device, member and Agent admission. */
export function decodeMachineLinkControlFrame(
  text: string,
): MachineLinkControlFrame {
  if (new TextEncoder().encode(text).byteLength > 512 * 1024)
    throw new RangeError("Machine link frame exceeds 512 KiB");
  return Schema.decodeUnknownSync(Schema.fromJsonString(controlFrameSchema), {
    onExcessProperty: "error",
  })(text);
}
