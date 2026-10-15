# API reference

`signSeamRequest` signs the sender, audience, method, URL and payload digest. `verifySeamRequest` checks against pinned public keys and a `SeamReplayGuard`, returning the verified key ID. `unsignedPayload` marks a transport-protected stream. Key provisioning and secret storage remain with the host.

## Public entrypoints

- `@fungi.computer/seam`

Type declarations ship beside each JavaScript entrypoint. The README owns usage, lifetime rules and limitations.
