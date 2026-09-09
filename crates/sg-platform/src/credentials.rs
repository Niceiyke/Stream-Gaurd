//! V2 device credential providers backed by operating-system storage.
//!
//! These providers are deliberately independent from local IPC credentials.

use std::fmt;
use std::sync::Arc;

use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sg_auth::device::{
    DeviceCredential, DeviceCredentialError, MAX_CERTIFICATE_CHAIN_LEN, MAX_CERTIFICATE_DER_LEN,
};
use sg_core::v2::DeviceId;

#[derive(Debug)]
struct FixedClientCertResolver(Arc<rustls::sign::CertifiedKey>);

impl ResolvesClientCert for FixedClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

struct PlatformDeviceCredential {
    device_id: DeviceId,
    resolver: Arc<dyn ResolvesClientCert>,
}

impl fmt::Debug for PlatformDeviceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlatformDeviceCredential(REDACTED)")
    }
}

impl DeviceCredential for PlatformDeviceCredential {
    fn device_id(&self) -> DeviceId {
        self.device_id
    }

    fn client_cert_resolver(&self) -> Arc<dyn ResolvesClientCert> {
        self.resolver.clone()
    }
}

/// Constructs the opaque rustls credential handle shared by platform stores.
/// The private key only reaches rustls' signing resolver and is never exposed
/// through [`DeviceCredential`].
fn build_device_credential(
    device_id: DeviceId,
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError> {
    if certificates.is_empty()
        || certificates.len() > MAX_CERTIFICATE_CHAIN_LEN
        || certificates
            .iter()
            .any(|certificate| certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_DER_LEN)
    {
        return Err(DeviceCredentialError::InvalidCertificateChain);
    }

    let certified_key = rustls::sign::CertifiedKey::from_der(
        certificates,
        private_key,
        &rustls::crypto::ring::default_provider(),
    )
    .map_err(|_| DeviceCredentialError::Unavailable)?;
    let resolver: Arc<dyn ResolvesClientCert> = Arc::new(FixedClientCertResolver(Arc::new(certified_key)));
    Ok(Arc::new(PlatformDeviceCredential { device_id, resolver }))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::OpenOptions;
    use std::io::{BufReader, Read};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use sg_auth::device::{DeviceCredential, DeviceCredentialError, DeviceCredentialProvider};
    use sg_core::v2::DeviceId;

    use super::build_device_credential;

    const MAX_PEM_FILE_LEN: u64 = 1024 * 1024;

    /// PEM-backed V2 credential provider for a Linux service account. The
    /// bundle must be atomically replaced as one regular, non-symlink file
    /// owned by the service account and inaccessible to group and other users.
    #[derive(Clone)]
    pub struct LinuxFileDeviceCredentialProvider {
        device_id: DeviceId,
        bundle_path: PathBuf,
    }

    impl std::fmt::Debug for LinuxFileDeviceCredentialProvider {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("LinuxFileDeviceCredentialProvider(REDACTED)")
        }
    }

    impl LinuxFileDeviceCredentialProvider {
        #[must_use]
        pub fn new(device_id: DeviceId, bundle_path: impl Into<PathBuf>) -> Self {
            Self { device_id, bundle_path: bundle_path.into() }
        }

        fn load_current(&self) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError> {
            // One read prevents certificate/key mixed-generation rotation.
            let bundle = read_secure_file(&self.bundle_path)?;
            let certificates = parse_certificates(&bundle)?;
            let private_key = parse_private_key(&bundle)?;
            build_device_credential(self.device_id, certificates, private_key)
        }
    }

    impl DeviceCredentialProvider for LinuxFileDeviceCredentialProvider {
        fn load(&self) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError> {
            self.load_current()
        }

        fn reload(&self) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError> {
            self.load_current()
        }
    }

    fn read_secure_file(path: &Path) -> Result<Vec<u8>, DeviceCredentialError> {
        let mut file = OpenOptions::new()
            .read(true)
            // Opening with O_NOFOLLOW closes the check-then-open symlink race.
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| DeviceCredentialError::Unavailable)?;
        let metadata = file.metadata().map_err(|_| DeviceCredentialError::Unavailable)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_PEM_FILE_LEN
        {
            return Err(DeviceCredentialError::Unavailable);
        }

        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take(MAX_PEM_FILE_LEN + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| DeviceCredentialError::Unavailable)?;
        if bytes.len() as u64 > MAX_PEM_FILE_LEN {
            return Err(DeviceCredentialError::Unavailable);
        }
        Ok(bytes)
    }

    fn parse_certificates(
        pem: &[u8],
    ) -> Result<Vec<CertificateDer<'static>>, DeviceCredentialError> {
        let mut reader = BufReader::new(pem);
        rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DeviceCredentialError::InvalidCertificateChain)
    }

    fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, DeviceCredentialError> {
        let mut reader = BufReader::new(pem);
        rustls_pemfile::private_key(&mut reader)
            .map_err(|_| DeviceCredentialError::Unavailable)?
            .ok_or(DeviceCredentialError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxFileDeviceCredentialProvider;

#[cfg(windows)]
mod windows {
    use std::fmt;
    use std::io::BufReader;
    use std::ptr;
    use std::sync::Arc;

    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use sg_auth::device::{DeviceCredential, DeviceCredentialError, DeviceCredentialProvider};
    use sg_core::v2::DeviceId;
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    use super::build_device_credential;

    const MAX_DPAPI_BLOB_LEN: usize = 1024 * 1024;

    /// Encrypted blobs read from a Windows credential store. Certificate data
    /// is PEM; the key data is DER PKCS#8. Neither blob implements `Debug`.
    pub struct DpapiCredentialBlobs {
        certificate_chain: Vec<u8>,
        private_key: Vec<u8>,
    }

    impl DpapiCredentialBlobs {
        #[must_use]
        pub fn new(certificate_chain: Vec<u8>, private_key: Vec<u8>) -> Self {
            Self { certificate_chain, private_key }
        }
    }

    impl fmt::Debug for DpapiCredentialBlobs {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("DpapiCredentialBlobs(REDACTED)")
        }
    }

    /// Supplies the two encrypted inner blobs consumed by the DPAPI provider.
    /// Implementations must not return plaintext key material.
    pub trait DpapiCredentialBlobSource: Send + Sync {
        fn load_blobs(&self) -> Result<DpapiCredentialBlobs, DeviceCredentialError>;
    }

    /// Reads a generic Credential Manager entry whose blob contains two
    /// DPAPI-encrypted values: a PEM certificate-chain blob and a PKCS#8 key
    /// blob. Credential Manager protects the outer generic credential at rest.
    pub struct WindowsCredentialManagerBlobSource {
        target_name: String,
    }

    impl WindowsCredentialManagerBlobSource {
        #[must_use]
        pub fn new(target_name: impl Into<String>) -> Self {
            Self { target_name: target_name.into() }
        }
    }

    impl fmt::Debug for WindowsCredentialManagerBlobSource {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("WindowsCredentialManagerBlobSource(REDACTED)")
        }
    }

    impl DpapiCredentialBlobSource for WindowsCredentialManagerBlobSource {
        fn load_blobs(&self) -> Result<DpapiCredentialBlobs, DeviceCredentialError> {
            let target_name = HSTRING::from(self.target_name.as_str());
            let mut allocation = CredentialAllocation(ptr::null_mut());
            // CredReadW allocates the returned CREDENTIALW and all nested data.
            // CredentialAllocation owns that allocation immediately after the
            // call and releases it with the documented CredFree function.
            unsafe {
                CredReadW(
                    &target_name,
                    CRED_TYPE_GENERIC,
                    None,
                    &mut allocation.0,
                )
                .map_err(|_| DeviceCredentialError::Unavailable)?;
            }
            let credential = allocation.as_ref()?;
            if credential.Type != CRED_TYPE_GENERIC
                || credential.CredentialBlob.is_null()
                || credential.CredentialBlobSize as usize > MAX_CREDENTIAL_MANAGER_BLOB_LEN
            {
                return Err(DeviceCredentialError::Unavailable);
            }
            // CredFree remains deferred to `credential` until after this copy.
            let blob = unsafe {
                std::slice::from_raw_parts(
                    credential.CredentialBlob,
                    credential.CredentialBlobSize as usize,
                )
            };
            parse_credential_manager_blob(blob)
        }
    }

    /// DPAPI-backed V2 device credential provider. Plaintext key bytes exist
    /// only while creating rustls' opaque signing resolver.
    pub struct WindowsDpapiDeviceCredentialProvider {
        device_id: DeviceId,
        source: Arc<dyn DpapiCredentialBlobSource>,
    }

    impl fmt::Debug for WindowsDpapiDeviceCredentialProvider {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("WindowsDpapiDeviceCredentialProvider(REDACTED)")
        }
    }

    impl WindowsDpapiDeviceCredentialProvider {
        /// Creates the production provider backed by a generic Credential
        /// Manager entry. This never accepts local IPC credentials.
        #[must_use]
        pub fn new(device_id: DeviceId, target_name: impl Into<String>) -> Self {
            Self::with_source(
                device_id,
                Arc::new(WindowsCredentialManagerBlobSource::new(target_name)),
            )
        }

        pub(super) fn with_source(
            device_id: DeviceId,
            source: Arc<dyn DpapiCredentialBlobSource>,
        ) -> Self {
            Self { device_id, source }
        }

        fn load_current(&self) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError> {
            let blobs = self.source.load_blobs()?;
            let certificate_pem = decrypt_dpapi(&blobs.certificate_chain)?;
            let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decrypt_dpapi(
                &blobs.private_key,
            )?));
            let mut reader = BufReader::new(certificate_pem.as_slice());
            let certificates = rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| DeviceCredentialError::InvalidCertificateChain)?;
            build_device_credential(self.device_id, certificates, private_key)
        }
    }

    impl DeviceCredentialProvider for WindowsDpapiDeviceCredentialProvider {
        fn load(&self) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError> {
            self.load_current()
        }

        fn reload(&self) -> Result<Arc<dyn DeviceCredential>, DeviceCredentialError> {
            self.load_current()
        }
    }

    fn decrypt_dpapi(encrypted: &[u8]) -> Result<Vec<u8>, DeviceCredentialError> {
        if encrypted.is_empty() || encrypted.len() > MAX_DPAPI_BLOB_LEN {
            return Err(DeviceCredentialError::Unavailable);
        }
        let input = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr().cast_mut(),
        };
        // DPAPI allocates `output.pbData` with LocalAlloc. Keep its guard in
        // scope across the API call too, including a potential error result.
        let mut output = LocalDpapiOutput(CRYPT_INTEGER_BLOB::default());
        unsafe {
            CryptUnprotectData(
                &input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
            .map_err(|_| DeviceCredentialError::Unavailable)?;
        }
        if output.0.pbData.is_null() || output.0.cbData as usize > MAX_DPAPI_BLOB_LEN {
            return Err(DeviceCredentialError::Unavailable);
        }
        // The DPAPI buffer is valid for the reported length until LocalFree.
        Ok(unsafe {
            std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec()
        })
    }

    struct LocalDpapiOutput(CRYPT_INTEGER_BLOB);

    impl Drop for LocalDpapiOutput {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // CryptUnprotectData documents LocalFree for this allocation.
                unsafe { LocalFree(Some(HLOCAL(self.0.pbData.cast()))) };
            }
        }
    }

    const CREDENTIAL_MANAGER_HEADER_LEN: usize = 8;
    const MAX_CREDENTIAL_MANAGER_BLOB_LEN: usize =
        CREDENTIAL_MANAGER_HEADER_LEN + (2 * MAX_DPAPI_BLOB_LEN);

    fn parse_credential_manager_blob(
        blob: &[u8],
    ) -> Result<DpapiCredentialBlobs, DeviceCredentialError> {
        if blob.len() < CREDENTIAL_MANAGER_HEADER_LEN || blob.len() > MAX_CREDENTIAL_MANAGER_BLOB_LEN {
            return Err(DeviceCredentialError::Unavailable);
        }
        let certificate_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        let private_key_len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        if certificate_len == 0
            || private_key_len == 0
            || certificate_len > MAX_DPAPI_BLOB_LEN
            || private_key_len > MAX_DPAPI_BLOB_LEN
            || certificate_len
                .checked_add(private_key_len)
                .and_then(|length| length.checked_add(CREDENTIAL_MANAGER_HEADER_LEN))
                != Some(blob.len())
        {
            return Err(DeviceCredentialError::Unavailable);
        }
        let private_key_start = CREDENTIAL_MANAGER_HEADER_LEN + certificate_len;
        Ok(DpapiCredentialBlobs::new(
            blob[CREDENTIAL_MANAGER_HEADER_LEN..private_key_start].to_vec(),
            blob[private_key_start..].to_vec(),
        ))
    }

    struct CredentialAllocation(*mut CREDENTIALW);

    impl CredentialAllocation {
        fn as_ref(&self) -> Result<&CREDENTIALW, DeviceCredentialError> {
            // Only CredReadW writes this pointer. On success its allocation
            // remains valid until this guard invokes CredFree on drop.
            unsafe { self.0.as_ref() }.ok_or(DeviceCredentialError::Unavailable)
        }
    }

    impl Drop for CredentialAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // CredReadW documents CredFree for this full allocation.
                unsafe { CredFree(self.0.cast()) };
            }
        }
    }
}

#[cfg(windows)]
pub use windows::{
    DpapiCredentialBlobSource, DpapiCredentialBlobs, WindowsCredentialManagerBlobSource,
    WindowsDpapiDeviceCredentialProvider,
};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rcgen::{CertificateParams, KeyPair};
    use sg_auth::device::DeviceCredentialProvider;
    use sg_core::v2::DeviceId;

    use super::LinuxFileDeviceCredentialProvider;

    struct TestFiles(PathBuf);

    impl TestFiles {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("streamguard-credentials-{nonce}"));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn bundle_path(&self) -> PathBuf {
            self.0.join("device.pem")
        }
    }

    impl Drop for TestFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_credential(path: &Path) {
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["device.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        fs::write(path, format!("{}{}", certificate.pem(), key.serialize_pem())).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn loads_a_service_owned_credential_bundle() {
        let files = TestFiles::new();
        write_credential(&files.bundle_path());
        let provider = LinuxFileDeviceCredentialProvider::new(DeviceId::from_bytes([7; 16]), files.bundle_path());

        let credential = provider.load().unwrap();
        assert_eq!(credential.device_id(), DeviceId::from_bytes([7; 16]));
        assert!(credential.client_cert_resolver().has_certs());
        assert_eq!(
            format!("{provider:?}"),
            "LinuxFileDeviceCredentialProvider(REDACTED)"
        );
    }

    #[test]
    fn rejects_group_readable_credential_files() {
        let files = TestFiles::new();
        write_credential(&files.bundle_path());
        fs::set_permissions(files.bundle_path(), fs::Permissions::from_mode(0o640)).unwrap();
        let provider = LinuxFileDeviceCredentialProvider::new(DeviceId::from_bytes([8; 16]), files.bundle_path());

        assert!(provider.load().is_err());
    }

    #[test]
    fn rejects_missing_and_symlinked_credential_files_without_paths_in_errors() {
        let files = TestFiles::new();
        let provider = LinuxFileDeviceCredentialProvider::new(DeviceId::from_bytes([10; 16]), files.bundle_path());
        let missing = provider.load().unwrap_err();
        assert_eq!(missing.to_string(), "V2 device credential is unavailable");

        write_credential(&files.bundle_path());
        let link_path = files.0.join("device-link.pem");
        std::os::unix::fs::symlink(files.bundle_path(), &link_path).unwrap();
        let provider = LinuxFileDeviceCredentialProvider::new(DeviceId::from_bytes([10; 16]), link_path);
        assert!(provider.load().is_err());
    }

    #[test]
    fn reload_rereads_bundle_and_redacts_failures() {
        let files = TestFiles::new();
        write_credential(&files.bundle_path());
        let provider = LinuxFileDeviceCredentialProvider::new(DeviceId::from_bytes([9; 16]), files.bundle_path());
        provider.load().unwrap();
        fs::write(files.bundle_path(), "not a credential bundle").unwrap();
        fs::set_permissions(files.bundle_path(), fs::Permissions::from_mode(0o600)).unwrap();

        let error = provider.reload().unwrap_err();
        assert_eq!(error.to_string(), "V2 device credential is unavailable");
    }

    #[test]
    fn reload_uses_an_atomically_replaced_credential_bundle() {
        let files = TestFiles::new();
        write_credential(&files.bundle_path());
        let provider = LinuxFileDeviceCredentialProvider::new(DeviceId::from_bytes([12; 16]), files.bundle_path());
        let original = provider.load().unwrap();

        let replacement = files.0.join("replacement.pem");
        write_credential(&replacement);
        fs::rename(&replacement, files.bundle_path()).unwrap();

        let reloaded = provider.reload().unwrap();
        assert_eq!(reloaded.device_id(), DeviceId::from_bytes([12; 16]));
        assert!(!Arc::ptr_eq(
            &original.client_cert_resolver(),
            &reloaded.client_cert_resolver(),
        ));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::sync::Arc;

    use rcgen::{CertificateParams, KeyPair};
    use sg_auth::device::{DeviceCredentialProvider, DeviceCredentialError};
    use sg_core::v2::DeviceId;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};

    use super::{
        DpapiCredentialBlobSource, DpapiCredentialBlobs, WindowsCredentialManagerBlobSource,
        WindowsDpapiDeviceCredentialProvider,
    };

    #[derive(Debug)]
    struct TestBlobSource {
        certificate_chain: Vec<u8>,
        private_key: Vec<u8>,
    }

    impl DpapiCredentialBlobSource for TestBlobSource {
        fn load_blobs(&self) -> Result<DpapiCredentialBlobs, DeviceCredentialError> {
            Ok(DpapiCredentialBlobs::new(
                self.certificate_chain.clone(),
                self.private_key.clone(),
            ))
        }
    }

    fn encrypt_for_current_user(plaintext: &[u8]) -> Vec<u8> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptProtectData(&input, PCWSTR::null(), None, None, None, 0, &mut output).unwrap();
            let encrypted = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(Some(HLOCAL(output.pbData.cast())));
            encrypted
        }
    }

    #[test]
    fn decrypts_dpapi_blobs_into_an_opaque_rustls_credential() {
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["device.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let source = Arc::new(TestBlobSource {
            certificate_chain: encrypt_for_current_user(certificate.pem().as_bytes()),
            private_key: encrypt_for_current_user(&key.serialize_der()),
        });
        let provider = WindowsDpapiDeviceCredentialProvider::with_source(DeviceId::from_bytes([11; 16]), source);

        let credential = provider.load().unwrap();
        assert_eq!(credential.device_id(), DeviceId::from_bytes([11; 16]));
        assert!(credential.client_cert_resolver().has_certs());
        assert_eq!(
            format!("{provider:?}"),
            "WindowsDpapiDeviceCredentialProvider(REDACTED)"
        );
    }

    #[test]
    fn credential_manager_source_redacts_target_and_maps_read_errors() {
        let target = format!("StreamGuard/V2/test/missing/{}", std::process::id());
        let source = WindowsCredentialManagerBlobSource::new(target);

        assert_eq!(
            format!("{source:?}"),
            "WindowsCredentialManagerBlobSource(REDACTED)"
        );
        assert!(matches!(
            source.load_blobs(),
            Err(DeviceCredentialError::Unavailable)
        ));
    }
}
