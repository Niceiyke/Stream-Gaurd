//! V2 device identity and certificate trust contracts.
//!
//! Private keys stay behind rustls signing and resolver interfaces. Platform
//! implementations own secure-store details and return these opaque handles.

use std::fmt;
use std::sync::Arc;

use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer};
use rustls::server::ResolvesServerCert;
use sg_core::v2::DeviceId;
use thiserror::Error;

use crate::ticket::{ControllerTrustSnapshot, TicketVerificationError, VerifiedAdmissionTicket};

/// Maximum roots accepted for one V2 trust domain.
pub const MAX_TRUST_ANCHORS: usize = 32;
/// Maximum CRLs accepted for one V2 device trust domain.
pub const MAX_CERTIFICATE_REVOCATION_LISTS: usize = 32;
/// Maximum certificates presented in a V2 TLS chain.
pub const MAX_CERTIFICATE_CHAIN_LEN: usize = 8;
/// Maximum accepted DER certificate length.
pub const MAX_CERTIFICATE_DER_LEN: usize = 64 * 1024;
/// Maximum accepted DER CRL length.
pub const MAX_CRL_DER_LEN: usize = 1024 * 1024;
/// Maximum DNS gateway name length, excluding a trailing dot.
pub const MAX_GATEWAY_NAME_LEN: usize = 253;

/// Errors intentionally describe a failed operation without exposing secure
/// store identifiers, certificate bytes, key paths, or ticket contents.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DeviceCredentialError {
    #[error("V2 device credential is unavailable")]
    Unavailable,
    #[error("V2 device credential rotation failed")]
    RotationFailed,
    #[error("V2 gateway name is invalid")]
    InvalidGatewayName,
    #[error("V2 trust material is invalid")]
    InvalidTrustMaterial,
    #[error("V2 certificate chain is invalid")]
    InvalidCertificateChain,
    #[error("V2 verified peer identity could not be extracted")]
    PeerIdentityUnavailable,
    #[error("V2 verified peer identity does not match the requested device")]
    PeerIdentityMismatch,
    #[error("V2 admission validation failed")]
    AdmissionRejected,
}

/// An opaque V2 device credential. Implementations must not expose private
/// key DER; rustls asks the resolver to select a signing-capable credential.
pub trait DeviceCredential: fmt::Debug + Send + Sync {
    fn device_id(&self) -> DeviceId;
    fn client_cert_resolver(&self) -> Arc<dyn ResolvesClientCert>;
}

/// Loads the current device credential and reloads it after certificate/key
/// rotation. This is intentionally independent from local IPC credentials.
pub trait DeviceCredentialProvider: fmt::Debug + Send + Sync {
    fn load(&self) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError>;
    fn reload(&self) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError>;
}

/// Test-only credential provider that permits deterministic rotation tests
/// without exposing certificate or private-key bytes. It remains behind the
/// normal rustls resolver contract and is not an authentication bypass.
#[cfg(test)]
pub mod test_credentials {
    use std::fmt;
    use std::sync::{Arc, RwLock};

    use super::{DeviceCredential, DeviceCredentialError, DeviceCredentialProvider};

    pub struct InMemoryDeviceCredentialProvider {
        credential: RwLock<Arc<dyn DeviceCredential>>,
    }

    impl InMemoryDeviceCredentialProvider {
        #[must_use]
        pub fn new(credential: Arc<dyn DeviceCredential>) -> Self {
            Self { credential: RwLock::new(credential) }
        }

        /// Replaces the next credential returned by `load` and `reload`.
        pub fn replace(
            &self,
            credential: Arc<dyn DeviceCredential>,
        ) -> Result<(), DeviceCredentialError> {
            *self
                .credential
                .write()
                .map_err(|_| DeviceCredentialError::RotationFailed)? = credential;
            Ok(())
        }
    }

    impl fmt::Debug for InMemoryDeviceCredentialProvider {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("InMemoryDeviceCredentialProvider(REDACTED)")
        }
    }

    impl DeviceCredentialProvider for InMemoryDeviceCredentialProvider {
        fn load(&self) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError> {
            self.credential
                .read()
                .map(|credential| credential.clone())
                .map_err(|_| DeviceCredentialError::RotationFailed)
        }

        fn reload(&self) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError> {
            self.load()
        }
    }
}

/// Gateway server identity. The resolver encapsulates its signing key, which
/// may be backed by an HSM/KMS instead of exportable key material.
pub trait GatewayTlsIdentity: fmt::Debug + Send + Sync {
    fn server_cert_resolver(&self) -> Arc<dyn ResolvesServerCert>;
}

/// Validated DNS name used for gateway SNI and certificate verification.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GatewayName(String);

impl GatewayName {
    pub fn new(value: impl Into<String>) -> Result<Self, DeviceCredentialError> {
        let value = value.into();
        let value = value.strip_suffix('.').unwrap_or(&value);
        if value.is_empty()
            || value.len() > MAX_GATEWAY_NAME_LEN
            || !value.is_ascii()
            || value.parse::<std::net::IpAddr>().is_ok()
            || value.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(DeviceCredentialError::InvalidGatewayName);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GatewayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("GatewayName").field(&self.0).finish()
    }
}

/// Gateway trust anchors and CRLs used by V2 clients to authenticate gateway
/// servers. Revocation status is fail-closed in the V2 client TLS builder.
pub struct GatewayTrustAnchors {
    roots: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
}

impl GatewayTrustAnchors {
    pub fn new(
        roots: Vec<CertificateDer<'static>>,
        crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<Self, DeviceCredentialError> {
        validate_certificates(&roots, false)?;
        validate_crls(&crls)?;
        Ok(Self { roots, crls })
    }

    #[must_use]
    pub fn roots(&self) -> &[CertificateDer<'static>] {
        &self.roots
    }

    #[must_use]
    pub fn crls(&self) -> &[CertificateRevocationListDer<'static>] {
        &self.crls
    }
}

impl fmt::Debug for GatewayTrustAnchors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayTrustAnchors")
            .field("roots", &"REDACTED")
            .field("crls", &"REDACTED")
            .finish()
    }
}

/// Gateway trust material for mandatory V2 client authentication. A nonempty
/// CRL set is required so unknown revocation status never becomes an allow.
pub struct DeviceTrustAnchors {
    roots: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
}

impl DeviceTrustAnchors {
    pub fn new(
        roots: Vec<CertificateDer<'static>>,
        crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<Self, DeviceCredentialError> {
        validate_certificates(&roots, false)?;
        validate_crls(&crls)?;
        Ok(Self { roots, crls })
    }

    #[must_use]
    pub fn roots(&self) -> &[CertificateDer<'static>] {
        &self.roots
    }

    #[must_use]
    pub fn crls(&self) -> &[CertificateRevocationListDer<'static>] {
        &self.crls
    }
}

impl fmt::Debug for DeviceTrustAnchors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceTrustAnchors")
            .field("roots", &"REDACTED")
            .field("crls", &"REDACTED")
            .finish()
    }
}

/// Extracts the enrolled V2 device identity from a chain rustls has already
/// authenticated. Implementations must not be called for unauthenticated TLS.
pub trait VerifiedPeerDeviceIdentityExtractor: fmt::Debug + Send + Sync {
    fn extract(
        &self,
        verified_chain: &[CertificateDer<'_>],
    ) -> Result<DeviceId, DeviceCredentialError>;
}

/// Validates an admission ticket after mTLS. It has no issuance method by
/// design: WP-201 binds controller-signed ticket claims to the verified peer
/// identity and the V2 `ClientHello` device identity.
pub trait AdmissionTicketValidator: fmt::Debug + Send + Sync {
    fn validate(
        &self,
        ticket: &str,
        trust: Option<&ControllerTrustSnapshot>,
        now_unix_seconds: u64,
        verified_device: DeviceId,
        client_hello_device: DeviceId,
    ) -> Result<VerifiedAdmissionTicket, TicketVerificationError>;
}

/// Runs the WP-201 admission boundary after mTLS and `ClientHello` decoding.
/// The claimed device must equal the identity extracted from the verified peer
/// chain before a validator examines the opaque ticket.
pub fn validate_admission_ticket(
    validator: &dyn AdmissionTicketValidator,
    ticket: &str,
    trust: Option<&ControllerTrustSnapshot>,
    now_unix_seconds: u64,
    verified_device: DeviceId,
    client_hello_device: DeviceId,
) -> Result<VerifiedAdmissionTicket, TicketVerificationError> {
    if verified_device != client_hello_device {
        return Err(TicketVerificationError::DeviceIdentityMismatch);
    }
    validator.validate(ticket, trust, now_unix_seconds, verified_device, client_hello_device)
}

/// Validates limits before an authenticated peer chain reaches an extractor.
pub fn validate_verified_peer_chain(
    chain: &[CertificateDer<'_>],
) -> Result<(), DeviceCredentialError> {
    if chain.is_empty()
        || chain.len() > MAX_CERTIFICATE_CHAIN_LEN
        || chain.iter().any(|cert| cert.is_empty() || cert.len() > MAX_CERTIFICATE_DER_LEN)
    {
        return Err(DeviceCredentialError::InvalidCertificateChain);
    }
    Ok(())
}

fn validate_certificates(
    certificates: &[CertificateDer<'static>],
    allow_empty: bool,
) -> Result<(), DeviceCredentialError> {
    if (!allow_empty && certificates.is_empty())
        || certificates.len() > MAX_TRUST_ANCHORS
        || certificates
            .iter()
            .any(|cert| cert.is_empty() || cert.len() > MAX_CERTIFICATE_DER_LEN)
    {
        return Err(DeviceCredentialError::InvalidTrustMaterial);
    }
    Ok(())
}

fn validate_crls(
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<(), DeviceCredentialError> {
    if crls.is_empty()
        || crls.len() > MAX_CERTIFICATE_REVOCATION_LISTS
        || crls.iter().any(|crl| crl.is_empty() || crl.len() > MAX_CRL_DER_LEN)
    {
        return Err(DeviceCredentialError::InvalidTrustMaterial);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestClientResolver;

    impl ResolvesClientCert for TestClientResolver {
        fn resolve(
            &self,
            _root_hint_subjects: &[&[u8]],
            _sigschemes: &[rustls::SignatureScheme],
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }

        fn has_certs(&self) -> bool {
            false
        }
    }

    #[derive(Debug)]
    struct TestCredential(DeviceId);

    impl DeviceCredential for TestCredential {
        fn device_id(&self) -> DeviceId {
            self.0
        }

        fn client_cert_resolver(&self) -> Arc<dyn ResolvesClientCert> {
            Arc::new(TestClientResolver)
        }
    }

    #[derive(Debug)]
    struct AcceptingTicketValidator;

    impl AdmissionTicketValidator for AcceptingTicketValidator {
        fn validate(
            &self,
            _ticket: &str,
            _trust: Option<&ControllerTrustSnapshot>,
            _now_unix_seconds: u64,
            _verified_device: DeviceId,
            _client_hello_device: DeviceId,
        ) -> Result<VerifiedAdmissionTicket, TicketVerificationError> {
            unreachable!("identity mismatch must reject before validation")
        }
    }

    #[test]
    fn gateway_name_accepts_dns_and_rejects_untrusted_forms() {
        assert_eq!(GatewayName::new("IAD-1.example.test.").unwrap().as_str(), "iad-1.example.test");
        for invalid in ["", "-bad.example", "bad-.example", "a..b", "127.0.0.1", "bad name"] {
            assert_eq!(GatewayName::new(invalid), Err(DeviceCredentialError::InvalidGatewayName));
        }
    }

    #[test]
    fn trust_and_chain_debug_output_are_redacted_and_bounded() {
        let root = CertificateDer::from(vec![0x01]);
        let crl = CertificateRevocationListDer::from(vec![0x02]);
        let trust = DeviceTrustAnchors::new(vec![root], vec![crl]).unwrap();
        let debug = format!("{trust:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("1, 2"));
        assert_eq!(
            validate_verified_peer_chain(&[]),
            Err(DeviceCredentialError::InvalidCertificateChain)
        );
    }

    #[test]
    fn device_trust_requires_current_revocation_information() {
        assert_eq!(
            DeviceTrustAnchors::new(vec![CertificateDer::from(vec![1])], vec![]).err(),
            Some(DeviceCredentialError::InvalidTrustMaterial)
        );
    }

    #[test]
    fn admission_control_rejects_a_client_hello_identity_mismatch_before_validation() {
        let validator = AcceptingTicketValidator;
        assert_eq!(
            validate_admission_ticket(
                &validator,
                "test-only-ticket",
                None,
                1,
                DeviceId::from_bytes([1; 16]),
                DeviceId::from_bytes([2; 16]),
            ),
            Err(TicketVerificationError::DeviceIdentityMismatch)
        );
    }

    #[test]
    fn in_memory_provider_replaces_only_opaque_resolver_backed_credentials() {
        use test_credentials::InMemoryDeviceCredentialProvider;

        let provider = InMemoryDeviceCredentialProvider::new(Arc::new(TestCredential(DeviceId::from_bytes([3; 16]))));
        assert_eq!(provider.load().unwrap().device_id(), DeviceId::from_bytes([3; 16]));
        provider.replace(Arc::new(TestCredential(DeviceId::from_bytes([4; 16])))).unwrap();
        assert_eq!(provider.reload().unwrap().device_id(), DeviceId::from_bytes([4; 16]));
        assert_eq!(format!("{provider:?}"), "InMemoryDeviceCredentialProvider(REDACTED)");
    }
}
