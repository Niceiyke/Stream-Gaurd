# StreamGuard V2 Security Boundaries

## Supported V2 Topology

The initial supported production topology is a privileged Windows client agent,
an unprivileged Windows desktop application, and a Linux gateway. The desktop
application never owns tunnel credentials, routes, firewall state, or TUN
handles. The agent and gateway communicate over mutually authenticated QUIC.

V1 launchers are excluded from this boundary. They are development-only and
must not be used as a production deployment path.

## Trust Domains

| Boundary | Required rule |
| --- | --- |
| Desktop UI to local agent | Local IPC credential and Windows named-pipe ACL authorize requests; UI credentials never authenticate gateways. |
| Client agent to gateway | Device mTLS succeeds before session admission or payload processing. |
| Gateway to controller | Gateway validates controller-signed short-lived admission tickets; gateways cannot mint tickets. |
| Gateway to Internet | Gateway forwards only traffic from addresses allocated to the authenticated session. |
| Agent to operating system | Route, DNS, WFP, and TUN changes are transactional, journaled, and recoverable. |

## Secret Classes

| Secret | Owner | V2 storage | Rotation/revocation | Logging rule |
| --- | --- | --- | --- | --- |
| Device private key | Device owner and StreamGuard enrollment service | Windows CNG/DPAPI-backed key storage or an equivalent OS-protected non-exportable store | Certificate renewal, device revocation, and local key replacement | Never log key material, export paths, or certificate DER. |
| Gateway server key | Gateway operator | Linux secret manager, HSM/KMS integration, or service-owned protected filesystem outside the repository | Operator-managed rotation with overlapping trust period | Never log key material or filesystem path. |
| Controller signing key | Controller operator | HSM, KMS, or isolated signing service only | Key ID based rotation and revocation | Never load into clients/gateways or log material. |
| Admission ticket | Controller issues; client presents; gateway consumes | Memory only, short-lived, audience-bound, single-session | Expiry, replay cache, device revocation, signing-key rotation | Never log token, claims containing identifiers, or full authorization header. |
| Local IPC credential | Local agent | Windows protected storage plus named-pipe ACL; separate from device credential and ticket | Regenerated on install/reset and invalidated on uninstall | Never send over network or log it. |

## Data Handling

- Packet payloads, full destination history, private keys, certificates,
  tickets, IPC credentials, and raw packet captures are excluded from default
  logs and telemetry.
- Diagnostic bundles require explicit user consent, redact identifiers, and
  never include payloads or credentials.
- Metrics use bounded, redactable session/device references and aggregate
  delivery information rather than packet content.

## V1 Development Exceptions

The following are V1 development-only and are explicitly prohibited in V2
production builds:

- `STREAMGUARD_SECRET` shared between client and gateway.
- Client-side admission-ticket minting.
- Generated self-signed `cert.der` and `key.der` in `sgcerts/`.
- Reuse of the status IPC token as a gateway credential.
- Feature flags or fallbacks that permit unauthenticated payload processing.
