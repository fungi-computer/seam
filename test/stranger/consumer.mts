/// <reference lib="es2023" />
/// <reference lib="dom" />
/// <reference lib="dom.iterable" />
/// <reference lib="esnext.disposable" />
import * as entry0 from "@fungi.computer/seam";
import * as entry1 from "@fungi.computer/seam/machine-link-protocol";
export { entry0, entry1 };

export const mailAddress: entry1.AgentMailAddress = {
  scopeId: "team-stranger",
  agentId: "agent-stranger",
};
export const controlFrame: entry1.MachineLinkControlFrame = {
  type: "leave",
  agentId: mailAddress.agentId,
};
export type MachineLinkPostChannel = ReturnType<
  typeof entry1.createMachineLinkPostChannel
>;
