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
| Device private key | Device owner and StreamGuard enrollment service | Windows Credential Manager generic credential containing DPAPI-encrypted certificate/key blobs; Linux service-account-owned, non-symlink, atomically replaced PEM bundle with no group/other permissions (`0600`-style, root-owned for the standard service installation) | Certificate renewal, device revocation, and atomic bundle replacement; providers reread backing storage on reload | Never log key material, Credential Manager targets, PEM paths, or certificate DER. |
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
- The V1 HS256 ticket implementation in `sg-auth`; it remains available only
  for V1 development tests and is not a V2 admission credential.
- Client-side admission-ticket minting.
- Generated self-signed `cert.der` and `key.der` in `sgcerts/`.
- Reuse of the status IPC token as a gateway credential.
- Feature flags or fallbacks that permit unauthenticated payload processing.

The `sg-auth/test-credentials` feature is test-only and disabled by default.
It supplies resolver-backed opaque credentials for deterministic rotation tests;
it neither exposes DER/key material nor bypasses mTLS or admission validation.

## V2 Admission Sequencing

V2 accepts no payload before a device mTLS handshake has verified a client
certificate against gateway-managed roots and non-expired CRLs. The gateway
extracts the enrolled device identity from that verified chain before it reads
the V2 control stream. WP-201 will add a controller-issued, asymmetric,
short-lived admission ticket validator. Its claims bind the verified peer
device identity to the V2 `ClientHello` device ID, gateway audience, session,
expiry, policy, nonce, and issuer key ID. This package does not mint tickets.
