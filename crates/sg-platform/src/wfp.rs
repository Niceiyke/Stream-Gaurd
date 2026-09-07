//! User-mode Windows Filtering Platform (WFP) selected-app enforcement.
//!
//! Implements the engineering step 15 scaffold (spec 28 row 15, spec(6).md
//! line 819): "WFP `ALE_APP_ID` filters enforce selected-app protection".
//!
//! Spec 19 (spec(6).md lines 557-604) prescribes the mechanism: the WFP
//! user-mode API (`FwpmFilterAdd` + `FWPM_CONDITION_ALE_APP_ID`) matches
//! sockets by application image at the ALE auth-connect layers, requires no
//! kernel driver, and is the recommended approach for selected-app mode
//! (spec 19, lines 579-583). Example protected apps: OBS Studio, vMix,
//! Wordlyte Pro (spec 19, lines 563-567); OS updates are not in the selected
//! set in this scaffold's single semantics.
//!
//! Layout:
//! - [`SelectedApp`], [`Policy`], [`WfpAction`], [`InstallReport`] — the
//!   cross-platform policy surface (unit-tested against a [`MockBackend`]
//!   on ANY host).
//! - [`Backend`] — the trait seam that isolates the Windows-only WFP calls.
//! - [`FwpmEngine`] — the policy lifecycle wrapper around `Box<dyn Backend>`.
//! - `mod imp` (`#[cfg(windows)]`) — the real `FwpmEngineOpen0` /
//!   `FwpmFilterAdd0` / `FwpmFilterDeleteById0` / transaction code.
//!
//! The real WFP module compiles on Windows; the policy logic and all tests
//! are backend-agnostic so `cargo test -p sg-platform` passes on any host.

#![allow(clippy::module_name_repetitions)] // WfpAction/WfpSession echo the `wfp` module name by design (clippy::module_name_repetitions)

use std::path::PathBuf;

use sg_core::error::{Error, Result};

/// One application selected for StreamGuard protection (spec 19, lines 561-567).
///
/// `image_path` is the FULL Win32 image path of the executable, e.g.
/// `C:\Program Files\obs-studio\bin\64bit\obs64.exe`. The user-mode WFP
/// backend normalizes it to the NT device path the kernel compares against
/// (`\device\harddiskvolume1\program files\obs-studio\...`) via
/// `FwpmGetAppIdFromFileName0` (spec 19, user-mode API; MS docs
/// "FwpmGetAppIdFromFileName0" / "Filtering condition identifiers"): the
/// `ALE_APP_ID` comparison is case-insensitive and the two formats are
/// equivalent for matching, so the caller should pass the user-facing path
/// exactly as shown in file properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedApp {
    /// Full image path of the protected executable (see struct docs).
    pub image_path: PathBuf,
    /// Human-readable name used in filter display data, e.g. "OBS Studio".
    pub display_name: String,
}

impl SelectedApp {
    /// Constructs a selected-app entry from its full image path.
    pub fn new(image_path: impl Into<PathBuf>, display_name: impl Into<String>) -> Self {
        Self {
            image_path: image_path.into(),
            display_name: display_name.into(),
        }
    }
}

/// Selected-app protection policy: **deny-all-except-selected** (spec 19).
///
/// Exactly one semantics is implemented, keeping the scaffold minimal: every
/// selected app gets a `PERMIT` filter at the ALE auth-connect layer and
/// everything else is denied by one low-weight catch-all `BLOCK` filter.
/// Policy variations from spec 19 — OS-update bypass, browser "optional",
/// vMix/OBS per-interface routing — are follow-up work for the real WFP
/// milestone and are intentionally not modeled here.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Applications that keep network access while the policy is installed.
    pub selected: Vec<SelectedApp>,
}

impl Policy {
    /// Builds a policy from the list of protected applications.
    pub fn new(selected: Vec<SelectedApp>) -> Self {
        Self { selected }
    }
}

/// The action a WFP filter takes when its conditions match (spec 19).
///
/// `Permit` maps to `FWP_ACTION_PERMIT` (used for every selected app),
/// `Block` maps to `FWP_ACTION_BLOCK` (used for the catch-all). The
/// [`Backend`] trait transports this as a plain `permit: bool`; this enum is
/// the internal, self-documenting form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpAction {
    /// Allow the connection (selected applications).
    Permit,
    /// Deny the connection (everything else under the catch-all).
    Block,
}

impl From<bool> for WfpAction {
    fn from(permit: bool) -> Self {
        if permit {
            WfpAction::Permit
        } else {
            WfpAction::Block
        }
    }
}

/// Backend seam isolating the Windows-only WFP management calls.
///
/// The policy lifecycle in [`FwpmEngine`] drives exactly this surface, which
/// makes the whole install/uninstall logic cross-platform-testable: unit
/// tests inject [`MockBackend`]; the real Windows implementation is
/// `imp::WfpSession` (`#[cfg(windows)]`), a wrapper around `FwpmFilterAdd0`
/// / `FwpmFilterDeleteById0` in per-call `FwpmTransactionBegin0/Commit0`
/// transactions (spec 19, user-mode API).
pub trait Backend: Send + Sync {
    /// Adds one filter that matches a single app image path and returns its
    /// local WFP filter id. `permit == true` maps to `WfpAction::Permit`
    /// (`FWP_ACTION_PERMIT`), `false` to `WfpAction::Block`.
    fn add_app_filter(&mut self, image_path: &str, permit: bool) -> Result<u64>;

    /// Adds the single low-weight deny-all catch-all filter and returns its
    /// WFP filter id. It must arbitrate BELOW every per-app permit so that a
    /// selected app is never blocked by it.
    fn add_deny_all(&mut self) -> Result<u64>;

    /// Deletes the given filter ids. Implementations must be idempotent-safe:
    /// deleting an already-deleted id is handled by the caller ordering.
    fn delete_filters(&mut self, ids: &[u64]) -> Result<()>;

    /// Closes the underlying engine session. Real WFP sessions also drop any
    /// non-persistent filters added from them when the session closes, so
    /// this is the RAII backstop for the error paths in [`FwpmEngine`].
    fn close(&mut self);
}

/// Report from a successful [`FwpmEngine::install`], holding every filter id
/// the install created so [`FwpmEngine::uninstall`] can remove exactly them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    /// Per-app permit filter ids, one per selected application.
    pub app_filter_ids: Vec<u64>,
    /// The single deny-all catch-all filter id.
    pub denied_all_id: u64,
    /// Number of selected applications the policy was installed for.
    pub count: usize,
}

/// Selected-app WFP policy engine: owns a [`Backend`] and the install state.
///
/// # Construction
/// - Cross-platform / tests: [`FwpmEngine::with_backend`] with any
///   [`Backend`] (e.g. [`MockBackend`] in this crate's unit tests).
/// - Windows, real WFP: [`FwpmEngine::open`] (elevation-checked, fallible; an
///   [`Error::platform`] is returned when the process is not elevated). The
///   `Default` impl is a convenience alias for `open` that panics on failure
///   only because an unusable WFP session is a fatal configuration error for
///   selected-app mode — production callers should use [`FwpmEngine::open`].
///
/// # Lifecycle / semantics
/// - [`FwpmEngine::install`] is strict: it only accepts an empty (never
///   installed) engine and returns `Error::platform("...already installed")`
///   on a second call. Installing from an already-installed engine would
///   otherwise stack a second deny-all and double-balance weights.
/// - Every app permit is added before the catch-all; if any add fails, the
///   filters added so far are deleted immediately (no partial policy stays
///   live) and `Err` is returned. Drop additionally closes the backend:
///   real WFP sessions remove their non-persistent filters on close, so a
///   process exit can never leak filters ([`imp`] docs, spec 19).
/// - [`FwpmEngine::uninstall`] deletes every id in the [`InstallReport`]
///   exactly once and resets the engine so `install` can run again.
pub struct FwpmEngine {
    backend: Box<dyn Backend>,
    installed: bool,
    closed: bool,
}

impl FwpmEngine {
    /// Constructs an engine over any [`Backend`] (tests, mocks, future ports).
    pub fn with_backend(backend: Box<dyn Backend>) -> Self {
        Self {
            backend,
            installed: false,
            closed: false,
        }
    }

    /// Installs the deny-all-except-selected policy (spec 19).
    ///
    /// Adds one `PERMIT` filter per selected app and exactly one low-weight
    /// `BLOCK` catch-all, in that order. Partial installs are rolled back on
    /// error (already-added filter ids are deleted before returning). Calling
    /// this twice without an intervening [`FwpmEngine::uninstall`] is
    /// rejected with `Error::platform("...already installed...")`.
    ///
    /// # Errors
    /// - `Error::platform` if the engine already has a policy installed.
    /// - Any backend error from adding an app permit or the catch-all.
    pub fn install(&mut self, policy: &Policy) -> Result<InstallReport> {
        if self.installed {
            return Err(Error::platform(
                "selected-app WFP policy already installed; call uninstall() first",
            ));
        }
        if self.closed {
            return Err(Error::platform(
                "selected-app WFP engine already closed; create a new engine",
            ));
        }
        let mut app_filter_ids: Vec<u64> = Vec::with_capacity(policy.selected.len());
        for app in &policy.selected {
            let image = app.image_path.to_string_lossy();
            match self.backend.add_app_filter(&image, true) {
                Ok(id) => app_filter_ids.push(id),
                Err(err) => {
                    // Best-effort rollback of the partial install so no stray
                    // permit filters outlive a failed install (the Drop/RAII
                    // close is the second backstop, see struct docs).
                    let _ = self.backend.delete_filters(&app_filter_ids);
                    return Err(err);
                }
            }
        }
        let denied_all_id = match self.backend.add_deny_all() {
            Ok(id) => id,
            Err(err) => {
                let _ = self.backend.delete_filters(&app_filter_ids);
                return Err(err);
            }
        };
        self.installed = true;
        Ok(InstallReport {
            count: policy.selected.len(),
            app_filter_ids,
            denied_all_id,
        })
    }

    /// Removes a previously installed policy (spec 19, user-mode API).
    ///
    /// Deletes every app permit id and the deny-all id from the given report,
    /// then resets the engine so [`FwpmEngine::install`] may be called again.
    /// Strict like `install`: calling it before any install is an error.
    ///
    /// # Errors
    /// - `Error::platform` if no policy is currently installed.
    /// - Any backend error from deleting a filter.
    pub fn uninstall(&mut self, report: &InstallReport) -> Result<()> {
        if !self.installed {
            return Err(Error::platform(
                "no selected-app WFP policy installed; call install() first",
            ));
        }
        let mut ids: Vec<u64> = Vec::with_capacity(report.app_filter_ids.len() + 1);
        ids.extend_from_slice(&report.app_filter_ids);
        ids.push(report.denied_all_id);
        self.backend.delete_filters(&ids)?;
        self.installed = false;
        Ok(())
    }

    /// Closes the backend session deterministically (idempotent; Drop calls
    /// this again without effect). For the real WFP backend this closes the
    /// engine handle, which also removes any non-persistent filters the
    /// session added (MS docs "FwpmEngineClose0").
    pub fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.backend.close();
        }
    }
}

impl Drop for FwpmEngine {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(windows)]
impl FwpmEngine {
    /// Opens a session to the local WFP engine (spec 19, user-mode API).
    ///
    /// Requires an elevated process (token-elevation checked here; BFE also
    /// enforces access control at `FwpmEngineOpen0`). The session closes and
    /// its non-persistent filters are dropped when the returned engine is
    /// dropped (MS docs "FwpmEngineClose0").
    ///
    /// # Errors
    /// - `Error::platform` when the process is not elevated or `FwpmEngineOpen0`
    ///   reports a non-success status (e.g. `FWP_E_ACCESS_DENIED`).
    pub fn open() -> Result<Self> {
        let session = imp::WfpSession::open()?;
        Ok(Self::with_backend(Box::new(session)))
    }
}

#[cfg(windows)]
impl Default for FwpmEngine {
    /// `open()` convenience alias; panics only when the real WFP session
    /// cannot be opened (not elevated, BFE unavailable). See [`FwpmEngine::open`]
    /// for the fallible form — this Default is a convenience for callers that
    /// treat a missing elevated WFP session as fatal.
    fn default() -> Self {
        match Self::open() {
            Ok(engine) => engine,
            Err(err) => panic!("selected-app WFP engine unavailable: {err}"),
        }
    }
}

/// Real WFP backend (compiles on Windows; not part of non-Windows builds).
///
/// Every filter mutation runs inside its own `FwpmTransactionBegin0` /
/// `FwpmTransactionCommit0` pair; a failed add or a failed commit aborts the
/// transaction with `FwpmTransactionAbort0` (spec 19, user-mode API). Filters
/// are added with `FWPM_FILTER_FLAG_NONE` (non-persistent): BFE removes them
/// when this session closes, which is the RAII backstop behind
/// [`FwpmEngine`]'s error paths.
#[cfg(windows)]
pub(crate) mod imp {
    use std::ptr;

    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE};
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0,
        FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmTransactionAbort0, FwpmTransactionBegin0,
        FwpmTransactionCommit0, FWPM_CONDITION_ALE_APP_ID, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
        FWPM_FILTER_FLAG_NONE, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK,
        FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
        FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_UINT64,
        FWP_VALUE0, FWP_VALUE0_0,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ACCESS_MASK, TOKEN_ELEVATION, TOKEN_QUERY,
        TOKEN_INFORMATION_CLASS,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::wfp::{Backend, Result, WfpAction};
    use sg_core::error::Error as SgError;

    /// `RPC_C_AUTHN_WINNT` (10) — default authentication service for local
    /// WFP management calls (MS docs "Authentication-Service Constants").
    const RPC_C_AUTHN_WINNT: u32 = 10;

    /// `FWP_E_ACCESS_DENIED` — WFP error when the caller lacks
    /// `FWPM_ACTRL_OPEN` / write access to the BFE engine.
    const FWP_E_ACCESS_DENIED: u32 = 0x8032_0001;

    /// Filter layer for the scaffold. Only the IPv4 ALE auth-connect layer is
    /// covered; IPv6 (`FWPM_LAYER_ALE_AUTH_CONNECT_V6`) bookkeeping is part
    /// of the real WFP milestone (spec 19, table line 598).
    const LAYER_ALE_AUTH_CONNECT: GUID = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    /// Lowest-weight literal for the catch-all deny filter. WFP arbitrates
    /// filters by descending weight; app permits use auto-weight
    /// (`FWP_EMPTY`, 60-bit auto range) which always sorts above this literal
    /// `1`, so a selected app's permit is always evaluated first and the
    /// deny-all only catches everyone else (MS docs "Filter Weight Assignment").
    const DENY_ALL_WEIGHT: u64 = 1;

    /// One open session to the local WFP engine.
    pub(crate) struct WfpSession {
        engine: HANDLE,
    }

    // SAFETY: `HANDLE` is a kernel object pointer with no ownership
    // constraints per thread; all WFP calls take the handle by value and BFE
    // serializes session state. The Backend trait only ever reaches the
    // session through `&mut self`, so concurrent use is impossible here.
    // This mirrors how every Windows handle wrapper in the ecosystem (and the
    // windows crate's own handle helpers) treat handles as thread-safe values.
    unsafe impl Send for WfpSession {}
    unsafe impl Sync for WfpSession {}

    impl WfpSession {
        /// Opens an elevated session to the local filter engine.
        pub(crate) fn open() -> Result<Self> {
            if !is_elevated() {
                return Err(SgError::platform(
                    "WFP engine session requires an elevated process; \
                     restart StreamGuard as Administrator (spec 19, user-mode API)",
                ));
            }
            let mut engine = HANDLE::default();
            // servername=NULL = local engine, authn=RPC_C_AUTHN_WINNT (10).
            let status = unsafe {
                FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine)
            };
            if status != ERROR_SUCCESS.0 {
                let hint = if status == FWP_E_ACCESS_DENIED {
                    " (FWP_E_ACCESS_DENIED: retry from an elevated process)"
                } else {
                    ""
                };
                return Err(wfp_err("FwpmEngineOpen0", status, hint));
            }
            Ok(Self { engine })
        }

        fn begin_txn(&self) -> Result<()> {
            // flags=0: read/write transaction (MS docs "FwpmTransactionBegin0").
            let status = unsafe { FwpmTransactionBegin0(self.engine, 0) };
            if status != ERROR_SUCCESS.0 {
                return Err(wfp_err("FwpmTransactionBegin0", status, ""));
            }
            Ok(())
        }

        fn commit_txn(&self) -> Result<()> {
            let status = unsafe { FwpmTransactionCommit0(self.engine) };
            if status != ERROR_SUCCESS.0 {
                return Err(wfp_err("FwpmTransactionCommit0", status, ""));
            }
            Ok(())
        }

        /// Best-effort rollback; the primary error is reported by the caller.
        fn abort_txn(&self) {
            // Ignoring the abort status is deliberate: we are already on an
            // error path and the transaction auto-aborts when the session
            // closes (FwpmEngineClose0 aborts in-progress transactions).
            let _ = unsafe { FwpmTransactionAbort0(self.engine) };
        }

        /// Builds a filter for one `ALE_APP_ID` condition and adds it inside
        /// one transaction. `app_id_bytes` is the NT-device-path blob from
        /// `FwpmGetAppIdFromFileName0`; `None` builds a condition-less filter
        /// (used by the catch-all deny).
        ///
        /// # Safety
        /// Leaves `app_id_bytes`' buffer alive until `FwpmFilterAdd0` returns,
        /// which is the only moment the kernel reads the blob (MS docs).
        fn add_filter(
            &mut self,
            action: FWP_ACTION_TYPE,
            name: &str,
            description: &str,
            app_id_bytes: Option<&[u8]>,
            literal_weight: Option<u64>,
        ) -> Result<u64> {
            // Borrowed-by-call buffers: kept alive until FwpmFilterAdd0 returns.
            let mut name_wide = wide(name);
            let mut desc_wide = wide(description);
            let mut app_id_owned: Vec<u8> = app_id_bytes.map_or_else(Vec::new, ToOwned::to_owned);
            let mut app_blob = FWP_BYTE_BLOB {
                size: app_id_owned.len() as u32,
                data: if app_id_owned.is_empty() {
                    ptr::null_mut()
                } else {
                    app_id_owned.as_mut_ptr()
                },
            };
            let mut weight_value = literal_weight.unwrap_or(0);
            let weight = FWP_VALUE0 {
                r#type: if literal_weight.is_some() {
                    FWP_UINT64
                } else {
                    FWP_EMPTY // auto-weight for the app permits
                },
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut weight_value,
                },
            };
            let conditions: Vec<FWPM_FILTER_CONDITION0> = if app_id_bytes.is_some() {
                vec![FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            byteBlob: &mut app_blob,
                        },
                    },
                }]
            } else {
                Vec::new()
            };
            let filter = FWPM_FILTER0 {
                filterKey: GUID::zeroed(), // zero => BFE generates one (MS docs)
                displayData: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name_wide.as_mut_ptr()),
                    description: PWSTR(desc_wide.as_mut_ptr()),
                },
                flags: FWPM_FILTER_FLAG_NONE, // non-persistent => session close removes it
                providerKey: ptr::null_mut(),
                providerData: FWP_BYTE_BLOB::default(),
                layerKey: LAYER_ALE_AUTH_CONNECT,
                subLayerKey: GUID::zeroed(), // IID_NULL => default sublayer
                weight,
                numFilterConditions: conditions.len() as u32,
                filterCondition: if conditions.is_empty() {
                    ptr::null_mut()
                } else {
                    conditions.as_ptr() as *mut _
                },
                action: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0 {
                    r#type: action,
                    Anonymous: Default::default(),
                },
                Anonymous: Default::default(),
                reserved: ptr::null_mut(),
                filterId: 0,
                effectiveWeight: FWP_VALUE0::default(),
            };

            self.begin_txn()?;
            let mut filter_id: u64 = 0;
            let status =
                unsafe { FwpmFilterAdd0(self.engine, &filter, None, Some(&mut filter_id)) };
            if status != ERROR_SUCCESS.0 {
                self.abort_txn();
                return Err(wfp_err("FwpmFilterAdd0", status, ""));
            }
            if let Err(err) = self.commit_txn() {
                self.abort_txn();
                return Err(err);
            }
            Ok(filter_id)
        }
    }

    impl Backend for WfpSession {
        fn add_app_filter(&mut self, image_path: &str, permit: bool) -> Result<u64> {
            // Convert the Win32 path to the NT-device-path app-id the kernel
            // matches (MS docs "FwpmGetAppIdFromFileName0"); filters built
            // from a raw DOS path add successfully but never match.
            let path_wide = wide(image_path);
            let mut app_id_ptr: *mut FWP_BYTE_BLOB = ptr::null_mut();
            let status =
                unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path_wide.as_ptr()), &mut app_id_ptr) };
            if status != ERROR_SUCCESS.0 {
                return Err(wfp_err("FwpmGetAppIdFromFileName0", status, ""));
            }
            if app_id_ptr.is_null() {
                return Err(SgError::platform(format!(
                    "FwpmGetAppIdFromFileName0 returned a null app-id for `{image_path}`"
                )));
            }
            // Copy the blob bytes into Rust-owned memory so the BFE allocation
            // can be freed before the filter add uses the data.
            let blob = unsafe { *app_id_ptr };
            let bytes = unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) }.to_vec();
            unsafe {
                FwpmFreeMemory0(&mut app_id_ptr as *mut *mut FWP_BYTE_BLOB as *mut *mut core::ffi::c_void);
            }
            let action = match WfpAction::from(permit) {
                WfpAction::Permit => FWP_ACTION_PERMIT,
                WfpAction::Block => FWP_ACTION_BLOCK,
            };
            self.add_filter(
                action,
                "StreamGuard selected-app permit",
                "ALE_APP_ID permit (spec 19)",
                Some(&bytes),
                None,
            )
        }

        fn add_deny_all(&mut self) -> Result<u64> {
            self.add_filter(
                FWP_ACTION_BLOCK,
                "StreamGuard deny-all (selected-app mode)",
                "Catch-all block below app permits (spec 19)",
                None,
                Some(DENY_ALL_WEIGHT),
            )
        }

        fn delete_filters(&mut self, ids: &[u64]) -> Result<()> {
            for id in ids {
                self.begin_txn()?;
                let status = unsafe { FwpmFilterDeleteById0(self.engine, *id) };
                if status != ERROR_SUCCESS.0 {
                    self.abort_txn();
                    return Err(wfp_err("FwpmFilterDeleteById0", status, ""));
                }
                if let Err(err) = self.commit_txn() {
                    self.abort_txn();
                    return Err(err);
                }
            }
            Ok(())
        }

        fn close(&mut self) {
            if !self.engine.is_invalid() {
                // Also aborts any in-progress transaction (MS docs
                // "FwpmEngineClose0"); non-persistent filters are dropped by
                // BFE when the session closes.
                unsafe { FwpmEngineClose0(self.engine) };
                self.engine = HANDLE::default();
            }
        }
    }

    impl Drop for WfpSession {
        fn drop(&mut self) {
            self.close();
        }
    }

    /// UTF-16LE wide buffer with NUL terminator, capped at 255 units so the
    /// filter display strings stay well inside BFE's display-data limits.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().take(255).chain(std::iter::once(0)).collect()
    }

    /// Formats a WFP/UINT32 status into an [`SgError::platform`] message.
    fn wfp_err(op: &str, status: u32, hint: &str) -> SgError {
        SgError::platform(format!("{op} failed: 0x{status:08X}{hint}"))
    }

    /// True when the current process token is elevated.
    ///
    /// Uses `TokenElevation` via `GetTokenInformation` rather than
    /// `CheckTokenMembership` because a filtered (limited) admin token still
    /// contains the Administrators group — only the elevation class tells us
    /// the token can actually open the BFE engine for writes.
    fn is_elevated() -> bool {
        let mut token = HANDLE::default();
        // desiredaccess = TOKEN_QUERY (MS docs "OpenProcessToken").
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ACCESS_MASK(TOKEN_QUERY.0),
                &mut token,
            )
        };
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned: u32 = 0;
        let queried = if opened.is_ok() {
            unsafe {
                GetTokenInformation(
                    token,
                    TOKEN_INFORMATION_CLASS(TokenElevation.0),
                    Some(&mut elevation as *mut TOKEN_ELEVATION as *mut core::ffi::c_void),
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut returned,
                )
            }
            .is_ok()
        } else {
            false
        };
        if !token.is_invalid() {
            unsafe { let _ = CloseHandle(token); }
        }
        queried && elevation.TokenIsElevated != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    /// Recording backend used to assert install/uninstall call sequences.
    #[derive(Clone)]
    struct MockBackend {
        next_id: Arc<AtomicU64>,
        state: Arc<Mutex<MockState>>,
    }

    struct MockState {
        live: Vec<u64>,
        added: Vec<(u64, String, bool)>,
        deny_all: Option<u64>,
        deletes: Vec<u64>,
        closes: u32,
        /// Number of add calls that succeed before the next one fails.
        add_successes_before_failure: usize,
        fail_deny_all: bool,
    }

    impl Default for MockState {
        fn default() -> Self {
            Self {
                live: Vec::new(),
                added: Vec::new(),
                deny_all: None,
                deletes: Vec::new(),
                closes: 0,
                add_successes_before_failure: usize::MAX, // never fail by default
                fail_deny_all: false,
            }
        }
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                next_id: Arc::new(AtomicU64::new(1)), // first returned id is 1
                state: Arc::new(Mutex::new(MockState::default())),
            }
        }

        fn fail_next_add_count(self, successes: usize) -> Self {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .add_successes_before_failure = successes;
            self
        }

        fn fail_deny_all(self) -> Self {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .fail_deny_all = true;
            self
        }

        fn snapshot(&self) -> MockState {
            let guard = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            MockState {
                live: guard.live.clone(),
                added: guard.added.clone(),
                deny_all: guard.deny_all,
                deletes: guard.deletes.clone(),
                closes: guard.closes,
                add_successes_before_failure: usize::MAX, // snapshot consumers never branch on it
                fail_deny_all: guard.fail_deny_all,
            }
        }
    }

    impl Backend for MockBackend {
        fn add_app_filter(&mut self, image_path: &str, permit: bool) -> Result<u64> {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.add_successes_before_failure == 0 {
                return Err(Error::platform(format!(
                    "mock add failed for `{image_path}` (injected)"
                )));
            }
            state.add_successes_before_failure = state.add_successes_before_failure.saturating_sub(1);
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            state.live.push(id);
            state.added.push((id, image_path.to_owned(), permit));
            Ok(id)
        }

        fn add_deny_all(&mut self) -> Result<u64> {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.fail_deny_all {
                return Err(Error::platform("mock deny-all add failed (injected)"));
            }
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            state.deny_all = Some(id);
            state.live.push(id);
            Ok(id)
        }

        fn delete_filters(&mut self, ids: &[u64]) -> Result<()> {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            for id in ids {
                state.deletes.push(*id);
                state.live.retain(|live| live != id);
            }
            Ok(())
        }

        fn close(&mut self) {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            state.closes += 1;
        }
    }

    /// Spec 19 selected apps (spec(6).md lines 563-567).
    fn sample_policy() -> Policy {
        Policy::new(vec![
            SelectedApp::new(
                r"C:\Program Files\obs-studio\bin\64bit\obs64.exe",
                "OBS Studio",
            ),
            SelectedApp::new(r"C:\Program Files\vMix\vMix64.exe", "vMix"),
            SelectedApp::new(r"C:\Program Files\Wordlyte\wordlyte-pro.exe", "Wordlyte Pro"),
        ])
    }

    #[test]
    fn install_adds_one_permit_per_app_plus_one_deny_all() {
        let backend = MockBackend::new();
        let mut engine = FwpmEngine::with_backend(Box::new(backend.clone()));

        let report = engine.install(&sample_policy()).expect("install should succeed");

        let state = backend.snapshot();
        // One permit per selected app, all marked permit=true.
        assert_eq!(state.added.len(), 3);
        assert!(state.added.iter().all(|(_, _, permit)| *permit), "every app filter must be a PERMIT");
        assert_eq!(state.added[0].1, r"C:\Program Files\obs-studio\bin\64bit\obs64.exe");
        assert_eq!(state.added[1].1, r"C:\Program Files\vMix\vMix64.exe");
        assert_eq!(state.added[2].1, r"C:\Program Files\Wordlyte\wordlyte-pro.exe");
        // Exactly one catch-all, and its id is the last one issued.
        assert_eq!(state.deny_all, Some(4));
        assert_eq!(state.live, vec![1, 2, 3, 4]);
        // Report mirrors the actual ids.
        assert_eq!(report.app_filter_ids, vec![1, 2, 3]);
        assert_eq!(report.denied_all_id, 4);
        assert_eq!(report.count, 3);
        assert_eq!(state.deletes, Vec::<u64>::new());
    }

    #[test]
    fn install_with_empty_policy_still_denies_everything() {
        let backend = MockBackend::new();
        let mut engine = FwpmEngine::with_backend(Box::new(backend.clone()));

        let report = engine.install(&Policy::new(vec![])).expect("install should succeed");

        let state = backend.snapshot();
        assert_eq!(report.count, 0);
        assert!(report.app_filter_ids.is_empty());
        assert_eq!(state.added, Vec::<(u64, String, bool)>::new());
        assert_eq!(state.deny_all, Some(1));
        assert!(state.live.contains(&1));
    }

    #[test]
    fn uninstall_deletes_every_id_exactly_once() {
        let backend = MockBackend::new();
        let mut engine = FwpmEngine::with_backend(Box::new(backend.clone()));
        let report = engine.install(&sample_policy()).expect("install should succeed");

        engine.uninstall(&report).expect("uninstall should succeed");

        let state = backend.snapshot();
        // Every recorded id removed exactly once, in app-first-then-catch-all order.
        assert_eq!(state.deletes, vec![1, 2, 3, 4]);
        assert!(state.live.is_empty());
        assert_eq!(state.added.len(), 3);
    }

    #[test]
    fn double_install_is_rejected() {
        let backend = MockBackend::new();
        let mut engine = FwpmEngine::with_backend(Box::new(backend.clone()));
        let _ = engine.install(&sample_policy()).expect("first install should succeed");

        let err = engine.install(&sample_policy()).expect_err("second install must be rejected");
        assert!(err.to_string().contains("already installed"), "unexpected error: {err}");

        // The rejected install must not have touched the backend.
        let state = backend.snapshot();
        assert_eq!(state.live, vec![1, 2, 3, 4]);
        assert_eq!(state.deletes, Vec::<u64>::new());
    }

    #[test]
    fn add_failure_rolls_back_already_added_filters() {
        let backend = MockBackend::new().fail_next_add_count(1); // app #1 ok, app #2 fails
        let mut engine = FwpmEngine::with_backend(Box::new(backend.clone()));

        let err = engine.install(&sample_policy()).expect_err("add #2 must fail");
        assert!(err.to_string().contains("vMix"), "unexpected error: {err}");

        // Partial install (app #1) was rolled back; no deny-all was added.
        let state = backend.snapshot();
        assert_eq!(state.deletes, vec![1]);
        assert!(state.live.is_empty());
        assert_eq!(state.deny_all, None);

        // The engine is reusable after the failed install.
        let backend2 = MockBackend::new();
        let mut engine2 = FwpmEngine::with_backend(Box::new(backend2.clone()));
        let _ = engine2.install(&sample_policy()).expect("reinstall after failure should succeed");
        assert_eq!(backend2.snapshot().live, vec![1, 2, 3, 4]);
    }

    #[test]
    fn deny_all_failure_rolls_back_all_app_filters() {
        let backend = MockBackend::new().fail_deny_all();
        let mut engine = FwpmEngine::with_backend(Box::new(backend.clone()));

        let err = engine.install(&sample_policy()).expect_err("deny-all add must fail");
        assert!(err.to_string().contains("deny-all"), "unexpected error: {err}");

        let state = backend.snapshot();
        assert_eq!(state.deletes, vec![1, 2, 3]); // all three permits rolled back
        assert!(state.live.is_empty());
        assert_eq!(state.deny_all, None);
    }

    #[test]
    fn uninstall_without_install_is_rejected() {
        let backend = MockBackend::new();
        let mut engine = FwpmEngine::with_backend(Box::new(backend.clone()));
        let report = InstallReport {
            app_filter_ids: vec![1],
            denied_all_id: 2,
            count: 1,
        };

        let err = engine.uninstall(&report).expect_err("uninstall before install must fail");
        assert!(err.to_string().contains("call install() first"), "unexpected error: {err}");
        assert_eq!(backend.snapshot().deletes, Vec::<u64>::new());
    }

    #[test]
    fn drop_closes_backend_once() {
        let backend = MockBackend::new();
        {
            let _engine = FwpmEngine::with_backend(Box::new(backend.clone()));
        }
        assert_eq!(backend.snapshot().closes, 1, "Drop must close the backend exactly once");
    }

    #[test]
    fn explicit_close_then_drop_closes_backend_once() {
        let backend = MockBackend::new();
        {
            let mut engine = FwpmEngine::with_backend(Box::new(backend.clone()));
            engine.close();
            let err = engine.install(&sample_policy()).expect_err("closed engine must refuse install");
            assert!(err.to_string().contains("already closed"), "unexpected error: {err}");
        }
        assert_eq!(backend.snapshot().closes, 1, "close() and Drop must not double-close");
    }

    #[test]
    fn install_then_uninstall_then_reinstall_works() {
        let backend = MockBackend::new();
        let mut engine = FwpmEngine::with_backend(Box::new(backend.clone()));

        let first = engine.install(&sample_policy()).expect("first install");
        engine.uninstall(&first).expect("first uninstall");
        let second = engine.install(&sample_policy()).expect("second install");

        let state = backend.snapshot();
        assert_eq!(state.deletes, vec![1, 2, 3, 4]);
        // Second install re-uses fresh ids (5..=7 for apps, 8 for catch-all).
        assert_eq!(second.app_filter_ids, vec![5, 6, 7]);
        assert_eq!(second.denied_all_id, 8);
        assert_eq!(state.live, vec![5, 6, 7, 8]);
    }
}