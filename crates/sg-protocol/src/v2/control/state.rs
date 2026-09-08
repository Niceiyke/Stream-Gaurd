//! Pure per-connection V2 control sequencing.
//!
//! This module never validates tickets, instantiates production sessions or
//! paths, or touches a TUN. Until WP-200/WP-201 provides an authenticated
//! admission authority, the gateway admission seam remains crate-private so no
//! downstream production caller can forge identity claims or activate it.

use super::{ControlFrame, ControlMessage, PathId, RejectCode, SafeModePolicy, SessionId};
use std::collections::{BTreeMap, VecDeque};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRole {
    Client,
    Gateway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPhase {
    AwaitHello,
    AwaitAdmit,
    Active,
    Closed,
}

/// Claims returned by an external admission verifier. Constructing this value
/// does not verify a credential; the gateway must call it only after mTLS and
/// ticket verification complete in WP-200.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedAdmission {
    session_id: SessionId,
    expires_at_ms: u64,
    policy_epoch: u64,
    assigned_ipv4: [u8; 4],
    assigned_ipv4_prefix_len: u8,
    assigned_ipv6_prefix: [u8; 16],
    assigned_ipv6_prefix_len: u8,
    safe_mode_policy: SafeModePolicy,
}

impl VerifiedAdmission {
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_verified_claims(
        session_id: SessionId,
        expires_at_ms: u64,
        policy_epoch: u64,
        assigned_ipv4: [u8; 4],
        assigned_ipv4_prefix_len: u8,
        assigned_ipv6_prefix: [u8; 16],
        assigned_ipv6_prefix_len: u8,
        safe_mode_policy: SafeModePolicy,
    ) -> Result<Self, ControlStateError> {
        if is_zero(session_id.as_bytes())
            || expires_at_ms == 0
            || policy_epoch == 0
            || assigned_ipv4.iter().all(|byte| *byte == 0)
            || assigned_ipv4_prefix_len == 0
            || assigned_ipv4_prefix_len > 32
            || assigned_ipv6_prefix.iter().all(|byte| *byte == 0)
            || assigned_ipv6_prefix_len == 0
            || assigned_ipv6_prefix_len > 128
        {
            return Err(ControlStateError::InvalidAdmission);
        }
        Ok(Self {
            session_id,
            expires_at_ms,
            policy_epoch,
            assigned_ipv4,
            assigned_ipv4_prefix_len,
            assigned_ipv6_prefix,
            assigned_ipv6_prefix_len,
            safe_mode_policy,
        })
    }

    fn admit(&self, transaction_id: u64) -> ControlFrame {
        ControlFrame {
            transaction_id,
            message: ControlMessage::SessionAdmit {
                session_id: self.session_id,
                expires_at_ms: self.expires_at_ms,
                policy_epoch: self.policy_epoch,
                assigned_ipv4: self.assigned_ipv4,
                assigned_ipv4_prefix_len: self.assigned_ipv4_prefix_len,
                assigned_ipv6_prefix: self.assigned_ipv6_prefix,
                assigned_ipv6_prefix_len: self.assigned_ipv6_prefix_len,
                safe_mode_policy: self.safe_mode_policy.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateConfig {
    pub completed_request_capacity: usize,
    pub completed_request_ttl_ms: u64,
    pub attachment_capacity: usize,
    pub pending_attach_capacity: usize,
    pub pending_attach_ttl_ms: u64,
    pub pending_policy_update_capacity: usize,
    pub pending_policy_update_ttl_ms: u64,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            completed_request_capacity: 64,
            completed_request_ttl_ms: 60_000,
            attachment_capacity: 64,
            pending_attach_capacity: 64,
            pending_attach_ttl_ms: 10_000,
            pending_policy_update_capacity: 64,
            pending_policy_update_ttl_ms: 10_000,
        }
    }
}

/// A deterministic result the caller can serialize on its reliable stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlAction {
    None,
    Reply(ControlFrame),
    Replay(ControlFrame),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ControlStateError {
    #[error("V2 control state configuration has a zero capacity")]
    ZeroCapacity,
    #[error("V2 control local pending attach capacity is exhausted")]
    PendingAttachCapacity,
    #[error("V2 control local pending policy update capacity is exhausted")]
    PendingPolicyUpdateCapacity,
    #[error("V2 control local transaction {0} changed while pending")]
    ChangedLocalTransaction(u64),
    #[error("V2 control local operation is invalid in state {0:?}")]
    LocalInvalidState(ConnectionPhase),
    #[error("V2 control admission claims are invalid")]
    InvalidAdmission,
    #[error("V2 control admission has expired")]
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompletedRequest {
    request: ControlFrame,
    response: ControlFrame,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttachmentRecord {
    request: ControlMessage,
    response: ControlMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingAttach {
    request: ControlMessage,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingPolicyUpdate {
    policy_epoch: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingDetach {
    request: ControlMessage,
    path_id: PathId,
    path_epoch: u64,
    expires_at_ms: u64,
}

/// Bounded protocol bindings for one reliable control connection. Entries in
/// `protocol_paths` are not gateway path objects and cannot forward payloads.
#[derive(Debug)]
pub struct ControlConnectionState {
    role: ControlRole,
    phase: ConnectionPhase,
    config: StateConfig,
    verified_admission: Option<VerifiedAdmission>,
    session_id: Option<SessionId>,
    expires_at_ms: Option<u64>,
    policy_epoch: u64,
    protocol_paths: BTreeMap<u16, u64>,
    attachments: BTreeMap<[u8; 16], AttachmentRecord>,
    pending_attaches: BTreeMap<u64, PendingAttach>,
    pending_policy_updates: BTreeMap<u64, PendingPolicyUpdate>,
    pending_detaches: BTreeMap<u64, PendingDetach>,
    completed: VecDeque<CompletedRequest>,
    hello_transaction_id: Option<u64>,
    next_path_id: Option<u16>,
}

impl ControlConnectionState {
    pub fn client(config: StateConfig) -> Result<Self, ControlStateError> {
        Self::new(ControlRole::Client, config, None)
    }

    /// Creates only a V2 control sequencer after an external verifier accepted
    /// the peer. It does not create a production session, path, flow, or TUN.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn gateway_after_verified_admission(
        config: StateConfig,
        verified_admission: VerifiedAdmission,
    ) -> Result<Self, ControlStateError> {
        Self::new(ControlRole::Gateway, config, Some(verified_admission))
    }

    fn new(
        role: ControlRole,
        config: StateConfig,
        verified_admission: Option<VerifiedAdmission>,
    ) -> Result<Self, ControlStateError> {
        if config.completed_request_capacity == 0
            || config.attachment_capacity == 0
            || config.pending_attach_capacity == 0
            || config.pending_policy_update_capacity == 0
        {
            return Err(ControlStateError::ZeroCapacity);
        }
        Ok(Self {
            role,
            phase: ConnectionPhase::AwaitHello,
            config,
            verified_admission,
            session_id: None,
            expires_at_ms: None,
            policy_epoch: 0,
            protocol_paths: BTreeMap::new(),
            attachments: BTreeMap::new(),
            pending_attaches: BTreeMap::new(),
            pending_policy_updates: BTreeMap::new(),
            pending_detaches: BTreeMap::new(),
            completed: VecDeque::new(),
            hello_transaction_id: None,
            next_path_id: Some(1),
        })
    }

    pub const fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    pub const fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }

    pub const fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    pub fn path_epoch(&self, path_id: PathId) -> Option<u64> {
        self.protocol_paths.get(&path_id.get()).copied()
    }

    pub fn protocol_path_count(&self) -> usize {
        self.protocol_paths.len()
    }

    pub fn has_pending_attach(&self, transaction_id: u64) -> bool {
        self.pending_attaches.contains_key(&transaction_id)
    }

    /// Validates and records a local frame at an injected monotonic time. The
    /// caller sends the frame only after this method succeeds.
    pub fn on_outbound(
        &mut self,
        frame: &ControlFrame,
        now_ms: u64,
    ) -> Result<(), ControlStateError> {
        self.prune_pending_attaches(now_ms);
        self.prune_pending_policy_updates(now_ms);
        self.prune_pending_detaches(now_ms);
        if self.expire_if_needed(now_ms) {
            return Err(ControlStateError::Expired);
        }
        match self.role {
            ControlRole::Client => self.client_outbound(frame, now_ms),
            ControlRole::Gateway => self.gateway_outbound(frame, now_ms),
        }
    }

    /// Processes a peer frame at an injected monotonic time. Every malformed
    /// semantic request has already passed codec validation and gets a
    /// correlated serializable reject when the control direction permits one.
    pub fn on_inbound(
        &mut self,
        frame: ControlFrame,
        now_ms: u64,
    ) -> Result<ControlAction, ControlStateError> {
        self.prune_completed(now_ms);
        self.prune_pending_attaches(now_ms);
        self.prune_pending_policy_updates(now_ms);
        self.prune_pending_detaches(now_ms);
        if self.expire_if_needed(now_ms) {
            return Ok(ControlAction::Reply(reject(
                frame.transaction_id,
                RejectCode::Expired,
                "admission expired",
            )));
        }
        match self.role {
            ControlRole::Client => self.client_inbound(frame, now_ms),
            ControlRole::Gateway => self.gateway_inbound(frame, now_ms),
        }
    }

    fn client_outbound(&mut self, frame: &ControlFrame, now_ms: u64) -> Result<(), ControlStateError> {
        match &frame.message {
            ControlMessage::ClientHello { .. } if self.phase == ConnectionPhase::AwaitHello => {
                self.phase = ConnectionPhase::AwaitAdmit;
                self.hello_transaction_id = Some(frame.transaction_id);
                Ok(())
            }
            ControlMessage::PathAttach { session_id, .. } if self.active_session(*session_id) => {
                if let Some(pending) = self.pending_attaches.get(&frame.transaction_id) {
                    if pending.request != frame.message {
                        return Err(ControlStateError::ChangedLocalTransaction(frame.transaction_id));
                    }
                    return Ok(());
                }
                if self.pending_attaches.len() == self.config.pending_attach_capacity {
                    return Err(ControlStateError::PendingAttachCapacity);
                }
                self.pending_attaches.insert(
                    frame.transaction_id,
                    PendingAttach {
                        request: frame.message.clone(),
                        expires_at_ms: now_ms.saturating_add(self.config.pending_attach_ttl_ms),
                    },
                );
                Ok(())
            }
            ControlMessage::PathDetach {
                session_id,
                path_id,
                path_epoch,
                ..
            } if self.active_session(*session_id) && self.path_epoch(*path_id) == Some(*path_epoch) => {
                if let Some(pending) = self.pending_detaches.get(&frame.transaction_id) {
                    if pending.request != frame.message {
                        return Err(ControlStateError::ChangedLocalTransaction(frame.transaction_id));
                    }
                    return Ok(());
                }
                if self.pending_detaches.len() == self.config.pending_attach_capacity {
                    return Err(ControlStateError::PendingAttachCapacity);
                }
                self.pending_detaches.insert(
                    frame.transaction_id,
                    PendingDetach {
                        request: frame.message.clone(),
                        path_id: *path_id,
                        path_epoch: *path_epoch,
                        expires_at_ms: now_ms.saturating_add(self.config.pending_attach_ttl_ms),
                    },
                );
                Ok(())
            }
            ControlMessage::PathHealth {
                session_id,
                path_id,
                path_epoch,
                ..
            } if self.active_session(*session_id) && self.path_epoch(*path_id) == Some(*path_epoch) => Ok(()),
            ControlMessage::Ack | ControlMessage::Reject { .. } if self.phase == ConnectionPhase::Active => Ok(()),
            ControlMessage::Close { session_id, .. } if self.active_session(*session_id) => {
                self.phase = ConnectionPhase::Closed;
                Ok(())
            }
            _ => Err(ControlStateError::LocalInvalidState(self.phase)),
        }
    }

    fn gateway_outbound(&mut self, frame: &ControlFrame, now_ms: u64) -> Result<(), ControlStateError> {
        match &frame.message {
            ControlMessage::PolicyUpdate {
                session_id,
                policy_epoch,
                ..
            } if self.active_session(*session_id) && *policy_epoch > self.policy_epoch => {
                if let Some(pending) = self.pending_policy_updates.get(&frame.transaction_id) {
                    if pending.policy_epoch != *policy_epoch {
                        return Err(ControlStateError::ChangedLocalTransaction(frame.transaction_id));
                    }
                    return Ok(());
                }
                if self.pending_policy_updates.len() == self.config.pending_policy_update_capacity
                {
                    return Err(ControlStateError::PendingPolicyUpdateCapacity);
                }
                self.pending_policy_updates.insert(
                    frame.transaction_id,
                    PendingPolicyUpdate {
                        policy_epoch: *policy_epoch,
                        expires_at_ms: now_ms.saturating_add(self.config.pending_policy_update_ttl_ms),
                    },
                );
                Ok(())
            }
            ControlMessage::Ack | ControlMessage::Reject { .. } if self.phase == ConnectionPhase::Active => Ok(()),
            ControlMessage::Close { session_id, .. } if self.active_session(*session_id) => {
                self.phase = ConnectionPhase::Closed;
                Ok(())
            }
            _ => Err(ControlStateError::LocalInvalidState(self.phase)),
        }
    }

    fn client_inbound(
        &mut self,
        frame: ControlFrame,
        now_ms: u64,
    ) -> Result<ControlAction, ControlStateError> {
        match &frame.message {
            ControlMessage::SessionAdmit {
                session_id,
                expires_at_ms,
                policy_epoch,
                ..
            } if self.phase == ConnectionPhase::AwaitAdmit
                && self.hello_transaction_id == Some(frame.transaction_id) => {
                if *expires_at_ms <= now_ms {
                    return Ok(ControlAction::Reply(reject(
                        frame.transaction_id,
                        RejectCode::Expired,
                        "admission expired",
                    )));
                }
                self.session_id = Some(*session_id);
                self.expires_at_ms = Some(*expires_at_ms);
                self.policy_epoch = *policy_epoch;
                self.phase = ConnectionPhase::Active;
                Ok(ControlAction::None)
            }
            ControlMessage::PathAttached {
                session_id,
                path_id,
                path_epoch,
            } if self.active_session(*session_id) => {
                let Some(pending) = self.pending_attaches.get(&frame.transaction_id) else {
                    return Ok(ControlAction::Reply(reject(
                        frame.transaction_id,
                        RejectCode::InvalidState,
                        "no matching path attach",
                    )));
                };
                let ControlMessage::PathAttach {
                    session_id: expected_session,
                    path_epoch: expected_epoch,
                    ..
                } = &pending.request
                else {
                    return Ok(ControlAction::Reply(reject(
                        frame.transaction_id,
                        RejectCode::InvalidRequest,
                        "invalid pending path attach",
                    )));
                };
                if *expected_session != *session_id || *expected_epoch != *path_epoch {
                    return Ok(ControlAction::Reply(reject(
                        frame.transaction_id,
                        RejectCode::InvalidRequest,
                        "path attach reply mismatch",
                    )));
                }
                if self.path_epoch(*path_id).is_some_and(|current| *path_epoch <= current) {
                    return Ok(ControlAction::Reply(reject(
                        frame.transaction_id,
                        RejectCode::StaleEpoch,
                        "path attached epoch rejected",
                    )));
                }
                self.pending_attaches.remove(&frame.transaction_id);
                self.protocol_paths.insert(path_id.get(), *path_epoch);
                Ok(ControlAction::None)
            }
            ControlMessage::PolicyUpdate {
                session_id,
                policy_epoch,
                ..
            } if self.active_session(*session_id) => {
                if *policy_epoch <= self.policy_epoch {
                    return Ok(ControlAction::Reply(reject(
                        frame.transaction_id,
                        RejectCode::StaleEpoch,
                        "policy epoch rejected",
                    )));
                }
                self.policy_epoch = *policy_epoch;
                Ok(ControlAction::Reply(ack(frame.transaction_id)))
            }
            ControlMessage::Close { session_id, .. } if self.active_session(*session_id) => {
                self.phase = ConnectionPhase::Closed;
                Ok(ControlAction::Reply(ack(frame.transaction_id)))
            }
            ControlMessage::Ack if self.phase == ConnectionPhase::Active => {
                if let Some(pending) = self.pending_detaches.remove(&frame.transaction_id) {
                    if self.path_epoch(pending.path_id) == Some(pending.path_epoch) {
                        self.protocol_paths.remove(&pending.path_id.get());
                    }
                }
                Ok(ControlAction::None)
            }
            ControlMessage::Reject { .. } if self.phase == ConnectionPhase::Active => {
                self.pending_detaches.remove(&frame.transaction_id);
                Ok(ControlAction::None)
            }
            ControlMessage::SessionAdmit { .. }
            | ControlMessage::PathAttached { .. }
            | ControlMessage::PolicyUpdate { .. }
            | ControlMessage::Close { .. } => Ok(ControlAction::Reply(reject(
                frame.transaction_id,
                RejectCode::InvalidState,
                "message is invalid in this state",
            ))),
            _ => Ok(ControlAction::Reply(reject(
                frame.transaction_id,
                RejectCode::InvalidDirection,
                "message is invalid from this peer",
            ))),
        }
    }

    fn gateway_inbound(
        &mut self,
        frame: ControlFrame,
        now_ms: u64,
    ) -> Result<ControlAction, ControlStateError> {
        if let Some(action) = self.completed_action(&frame) {
            return Ok(action);
        }

        match &frame.message {
            ControlMessage::ClientHello { .. } => {
                if self.phase != ConnectionPhase::AwaitHello {
                    return Ok(self.reject_and_remember(
                        frame,
                        RejectCode::InvalidState,
                        "client hello is no longer allowed",
                        now_ms,
                    ));
                }
                let Some(admission) = &self.verified_admission else {
                    return Err(ControlStateError::InvalidAdmission);
                };
                if admission.expires_at_ms <= now_ms {
                    return Ok(self.reject_and_remember(
                        frame,
                        RejectCode::Expired,
                        "admission expired",
                        now_ms,
                    ));
                }
                self.session_id = Some(admission.session_id);
                self.expires_at_ms = Some(admission.expires_at_ms);
                self.policy_epoch = admission.policy_epoch;
                self.phase = ConnectionPhase::Active;
                let response = admission.admit(frame.transaction_id);
                self.remember(frame, response.clone(), now_ms);
                Ok(ControlAction::Reply(response))
            }
            ControlMessage::PathAttach {
                session_id,
                path_nonce,
                ..
            } => {
                if !self.active_session(*session_id) {
                    return Ok(self.reject_and_remember(
                        frame,
                        RejectCode::InvalidSession,
                        "session is not active on this connection",
                        now_ms,
                    ));
                }
                if let Some(existing) = self.attachments.get(path_nonce) {
                    if existing.request != frame.message {
                        return Ok(self.reject_and_remember(
                            frame,
                            RejectCode::InvalidRequest,
                            "path nonce replay changed",
                            now_ms,
                        ));
                    }
                    let response = ControlFrame {
                        transaction_id: frame.transaction_id,
                        message: existing.response.clone(),
                    };
                    self.remember(frame, response.clone(), now_ms);
                    return Ok(ControlAction::Replay(response));
                }
                if self.attachments.len() == self.config.attachment_capacity {
                    return Ok(self.reject_and_remember(
                        frame,
                        RejectCode::InvalidRequest,
                        "path attachment capacity exhausted",
                        now_ms,
                    ));
                }
                let Some(next_path_id) = self.next_path_id else {
                    return Ok(self.reject_and_remember(
                        frame,
                        RejectCode::InvalidRequest,
                        "path identifier space exhausted",
                        now_ms,
                    ));
                };
                let response_message = ControlMessage::PathAttached {
                    session_id: *session_id,
                    path_id: PathId::new(next_path_id),
                    path_epoch: path_attach_epoch(&frame.message)?,
                };
                self.next_path_id = next_path_id.checked_add(1);
                self.protocol_paths.insert(next_path_id, path_attach_epoch(&frame.message)?);
                self.attachments.insert(
                    *path_nonce,
                    AttachmentRecord {
                        request: frame.message.clone(),
                        response: response_message.clone(),
                    },
                );
                let response = ControlFrame {
                    transaction_id: frame.transaction_id,
                    message: response_message,
                };
                self.remember(frame, response.clone(), now_ms);
                Ok(ControlAction::Reply(response))
            }
            ControlMessage::PathDetach {
                session_id,
                path_id,
                path_epoch,
                ..
            } => {
                let (session_id, path_id, path_epoch) = (*session_id, *path_id, *path_epoch);
                self.gateway_path_request(frame, session_id, path_id, path_epoch, now_ms, true)
            }
            ControlMessage::PathHealth {
                session_id,
                path_id,
                path_epoch,
                ..
            } => {
                let (session_id, path_id, path_epoch) = (*session_id, *path_id, *path_epoch);
                self.gateway_path_request(frame, session_id, path_id, path_epoch, now_ms, false)
            }
            ControlMessage::Close { session_id, .. } => {
                if !self.active_session(*session_id) {
                    return Ok(self.reject_and_remember(
                        frame,
                        RejectCode::InvalidSession,
                        "session is not active on this connection",
                        now_ms,
                    ));
                }
                let response = ack(frame.transaction_id);
                self.remember(frame, response.clone(), now_ms);
                self.phase = ConnectionPhase::Closed;
                Ok(ControlAction::Reply(response))
            }
            ControlMessage::Ack if self.phase == ConnectionPhase::Active => {
                if let Some(pending) = self.pending_policy_updates.remove(&frame.transaction_id) {
                    self.policy_epoch = pending.policy_epoch;
                    Ok(ControlAction::None)
                } else {
                    Ok(ControlAction::Reply(reject(
                        frame.transaction_id,
                        RejectCode::InvalidState,
                        "unexpected acknowledgement",
                    )))
                }
            }
            ControlMessage::Reject { .. } if self.phase == ConnectionPhase::Active => {
                if self.pending_policy_updates.remove(&frame.transaction_id).is_some() {
                    Ok(ControlAction::None)
                } else {
                    Ok(ControlAction::Reply(reject(
                        frame.transaction_id,
                        RejectCode::InvalidState,
                        "unexpected rejection",
                    )))
                }
            }
            _ => Ok(ControlAction::Reply(reject(
                frame.transaction_id,
                RejectCode::InvalidDirection,
                "message is invalid from this peer",
            ))),
        }
    }

    fn gateway_path_request(
        &mut self,
        frame: ControlFrame,
        session_id: SessionId,
        path_id: PathId,
        path_epoch: u64,
        now_ms: u64,
        detach: bool,
    ) -> Result<ControlAction, ControlStateError> {
        if let Some(code) = self.path_request_code(session_id, path_id, path_epoch) {
            return Ok(self.reject_and_remember(frame, code, "path epoch rejected", now_ms));
        }
        if detach {
            self.protocol_paths.remove(&path_id.get());
        }
        let response = ack(frame.transaction_id);
        self.remember(frame, response.clone(), now_ms);
        Ok(ControlAction::Reply(response))
    }

    fn path_request_code(
        &self,
        session_id: SessionId,
        path_id: PathId,
        path_epoch: u64,
    ) -> Option<RejectCode> {
        if !self.active_session(session_id) {
            return Some(RejectCode::InvalidSession);
        }
        match self.path_epoch(path_id) {
            None => Some(RejectCode::UnknownPath),
            Some(current) if current != path_epoch => Some(RejectCode::StaleEpoch),
            Some(_) => None,
        }
    }

    fn active_session(&self, session_id: SessionId) -> bool {
        self.phase == ConnectionPhase::Active && self.session_id == Some(session_id)
    }

    fn expire_if_needed(&mut self, now_ms: u64) -> bool {
        if self.phase == ConnectionPhase::Active
            && self.expires_at_ms.is_some_and(|expires_at_ms| expires_at_ms <= now_ms)
        {
            self.phase = ConnectionPhase::Closed;
            return true;
        }
        false
    }

    fn completed_action(&self, frame: &ControlFrame) -> Option<ControlAction> {
        let completed = self
            .completed
            .iter()
            .find(|completed| completed.request.transaction_id == frame.transaction_id)?;
        if completed.request == *frame {
            Some(ControlAction::Replay(completed.response.clone()))
        } else {
            Some(ControlAction::Reply(reject(
                frame.transaction_id,
                RejectCode::InvalidRequest,
                "transaction replay changed",
            )))
        }
    }

    fn prune_completed(&mut self, now_ms: u64) {
        self.completed.retain(|entry| entry.expires_at_ms > now_ms);
    }

    fn prune_pending_attaches(&mut self, now_ms: u64) {
        self.pending_attaches
            .retain(|_, pending| pending.expires_at_ms > now_ms);
    }

    fn prune_pending_policy_updates(&mut self, now_ms: u64) {
        self.pending_policy_updates
            .retain(|_, pending| pending.expires_at_ms > now_ms);
    }

    fn prune_pending_detaches(&mut self, now_ms: u64) {
        self.pending_detaches
            .retain(|_, pending| pending.expires_at_ms > now_ms);
    }

    fn remember(&mut self, request: ControlFrame, response: ControlFrame, now_ms: u64) {
        if self.completed.len() == self.config.completed_request_capacity {
            let _ = self.completed.pop_front();
        }
        self.completed.push_back(CompletedRequest {
            request,
            response,
            expires_at_ms: now_ms.saturating_add(self.config.completed_request_ttl_ms),
        });
    }

    fn reject_and_remember(
        &mut self,
        request: ControlFrame,
        code: RejectCode,
        reason: &'static str,
        now_ms: u64,
    ) -> ControlAction {
        let response = reject(request.transaction_id, code, reason);
        self.remember(request, response.clone(), now_ms);
        ControlAction::Reply(response)
    }
}

fn path_attach_epoch(message: &ControlMessage) -> Result<u64, ControlStateError> {
    match message {
        ControlMessage::PathAttach { path_epoch, .. } => Ok(*path_epoch),
        _ => Err(ControlStateError::InvalidAdmission),
    }
}

fn ack(transaction_id: u64) -> ControlFrame {
    ControlFrame {
        transaction_id,
        message: ControlMessage::Ack,
    }
}

fn reject(transaction_id: u64, code: RejectCode, reason: &'static str) -> ControlFrame {
    ControlFrame {
        transaction_id,
        message: ControlMessage::Reject {
            code,
            reason: reason.into(),
        },
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn is_zero(value: &[u8; 16]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::control::{AdmissionTicket, SafeModePolicy};
    use bytes::Bytes;
    use sg_core::v2::DeviceId;

    const SESSION: SessionId = SessionId::from_bytes([0x44; 16]);

    fn policy() -> SafeModePolicy {
        SafeModePolicy::new(Bytes::from_static(b"safe-mode")).unwrap()
    }

    fn config() -> StateConfig {
        StateConfig {
            completed_request_capacity: 2,
            completed_request_ttl_ms: 10,
            attachment_capacity: 2,
            pending_attach_capacity: 2,
            pending_attach_ttl_ms: 5,
            pending_policy_update_capacity: 2,
            pending_policy_update_ttl_ms: 5,
        }
    }

    fn verified_admission(expires_at_ms: u64) -> VerifiedAdmission {
        VerifiedAdmission::from_verified_claims(
            SESSION,
            expires_at_ms,
            1,
            [10, 0, 0, 2],
            24,
            [0x20; 16],
            64,
            policy(),
        )
        .unwrap()
    }

    fn gateway(expires_at_ms: u64) -> ControlConnectionState {
        ControlConnectionState::gateway_after_verified_admission(config(), verified_admission(expires_at_ms))
            .unwrap()
    }

    fn hello(transaction_id: u64) -> ControlFrame {
        ControlFrame {
            transaction_id,
            message: ControlMessage::ClientHello {
                device_id: DeviceId::from_bytes([0x55; 16]),
                requested_gateway: "iad-1".into(),
                ticket: AdmissionTicket::new("ticket".into()).unwrap(),
            },
        }
    }

    fn admit(transaction_id: u64, expires_at_ms: u64, policy_epoch: u64) -> ControlFrame {
        verified_admission(expires_at_ms).admit(transaction_id).map_policy_epoch(policy_epoch)
    }

    fn attach(transaction_id: u64, nonce: u8, epoch: u64) -> ControlFrame {
        ControlFrame {
            transaction_id,
            message: ControlMessage::PathAttach {
                session_id: SESSION,
                path_nonce: [nonce; 16],
                path_epoch: epoch,
                metadata: Bytes::from_static(b"wifi"),
            },
        }
    }

    trait FramePolicyEpoch {
        fn map_policy_epoch(self, policy_epoch: u64) -> Self;
    }

    impl FramePolicyEpoch for ControlFrame {
        fn map_policy_epoch(mut self, policy_epoch: u64) -> Self {
            if let ControlMessage::SessionAdmit { policy_epoch: epoch, .. } = &mut self.message {
                *epoch = policy_epoch;
            }
            self
        }
    }

    fn admit_gateway(state: &mut ControlConnectionState) {
        assert!(matches!(state.on_inbound(hello(1), 0).unwrap(), ControlAction::Reply(_)));
        assert_eq!(state.phase(), ConnectionPhase::Active);
    }

    fn assigned_path(state: &mut ControlConnectionState) -> PathId {
        let ControlAction::Reply(response) = state.on_inbound(attach(2, 0x66, 7), 1).unwrap() else {
            panic!("path must be assigned");
        };
        match response.message {
            ControlMessage::PathAttached { path_id, .. } => path_id,
            _ => panic!("path must be assigned"),
        }
    }

    #[test]
    fn verified_admission_only_sequences_control_and_allocates_no_protocol_path_on_hello() {
        let mut state = gateway(1_000);
        assert_eq!(state.protocol_path_count(), 0);
        let ControlAction::Reply(reply) = state.on_inbound(hello(1), 0).unwrap() else {
            panic!("hello must receive SessionAdmit");
        };
        assert!(matches!(reply.message, ControlMessage::SessionAdmit { .. }));
        assert_eq!(state.protocol_path_count(), 0);
    }

    #[test]
    fn duplicate_path_attach_survives_completed_cache_eviction_without_reallocation() {
        let mut state = gateway(1_000);
        admit_gateway(&mut state);
        let request = attach(2, 0x66, 7);
        let ControlAction::Reply(first) = state.on_inbound(request.clone(), 1).unwrap() else {
            panic!("first attach must reply");
        };
        let path_id = match first.message {
            ControlMessage::PathAttached { path_id, .. } => path_id,
            _ => panic!("attach must assign a path"),
        };
        let _ = state.on_inbound(attach(3, 0x67, 8), 2).unwrap();
        let _ = state.on_inbound(attach(4, 0x68, 9), 3).unwrap();
        assert_eq!(state.protocol_path_count(), 3.min(config().attachment_capacity));
        // The transaction cache has both evicted the first request and expired
        // by this point; the connection-lifetime nonce record still dedups it.
        let replay = state.on_inbound(request, 12).unwrap();
        assert_eq!(
            replay,
            ControlAction::Replay(ControlFrame {
                transaction_id: 2,
                message: ControlMessage::PathAttached {
                    session_id: SESSION,
                    path_id,
                    path_epoch: 7,
                },
            })
        );
        assert_eq!(state.path_epoch(path_id), Some(7));
    }

    #[test]
    fn changed_path_nonce_replay_is_correlated_reject_without_reallocation() {
        let mut state = gateway(1_000);
        admit_gateway(&mut state);
        let path_id = assigned_path(&mut state);
        let changed = attach(3, 0x66, 8);
        assert_eq!(
            state.on_inbound(changed, 2).unwrap(),
            ControlAction::Reply(reject(3, RejectCode::InvalidRequest, "path nonce replay changed"))
        );
        assert_eq!(state.protocol_path_count(), 1);
        assert_eq!(state.path_epoch(path_id), Some(7));
    }

    #[test]
    fn valid_detach_health_and_close_receive_correlated_acks() {
        let mut state = gateway(1_000);
        admit_gateway(&mut state);
        let path_id = assigned_path(&mut state);
        let health = ControlFrame {
            transaction_id: 3,
            message: ControlMessage::PathHealth {
                session_id: SESSION,
                path_id,
                path_epoch: 7,
                rtt_ms: 10,
                loss_ppm: 0,
            },
        };
        assert_eq!(state.on_inbound(health, 2).unwrap(), ControlAction::Reply(ack(3)));
        let detach = ControlFrame {
            transaction_id: 4,
            message: ControlMessage::PathDetach {
                session_id: SESSION,
                path_id,
                path_epoch: 7,
                reason: "operator".into(),
            },
        };
        assert_eq!(state.on_inbound(detach, 3).unwrap(), ControlAction::Reply(ack(4)));
        assert_eq!(state.path_epoch(path_id), None);
        let close = ControlFrame {
            transaction_id: 5,
            message: ControlMessage::Close {
                session_id: SESSION,
                reason: "done".into(),
            },
        };
        assert_eq!(state.on_inbound(close, 4).unwrap(), ControlAction::Reply(ack(5)));
        assert_eq!(state.phase(), ConnectionPhase::Closed);
    }

    #[test]
    fn client_mismatched_path_attached_preserves_pending_request() {
        let mut client = ControlConnectionState::client(config()).unwrap();
        client.on_outbound(&hello(1), 0).unwrap();
        client.on_inbound(admit(1, 1_000, 1), 1).unwrap();
        let request = attach(2, 0x66, 7);
        client.on_outbound(&request, 2).unwrap();
        let mismatched = ControlFrame {
            transaction_id: 2,
            message: ControlMessage::PathAttached {
                session_id: SESSION,
                path_id: PathId::new(1),
                path_epoch: 8,
            },
        };
        assert_eq!(
            client.on_inbound(mismatched, 3).unwrap(),
            ControlAction::Reply(reject(2, RejectCode::InvalidRequest, "path attach reply mismatch"))
        );
        assert!(client.has_pending_attach(2));
        let matched = ControlFrame {
            transaction_id: 2,
            message: ControlMessage::PathAttached {
                session_id: SESSION,
                path_id: PathId::new(1),
                path_epoch: 7,
            },
        };
        assert_eq!(client.on_inbound(matched, 4).unwrap(), ControlAction::None);
        assert!(!client.has_pending_attach(2));
    }

    #[test]
    fn client_path_binding_rejects_stale_attach_reply_and_only_accepts_newer_epoch() {
        let mut client = ControlConnectionState::client(config()).unwrap();
        client.on_outbound(&hello(1), 0).unwrap();
        client.on_inbound(admit(1, 1_000, 1), 1).unwrap();
        client.on_outbound(&attach(2, 0x66, 7), 2).unwrap();
        client
            .on_inbound(
                ControlFrame {
                    transaction_id: 2,
                    message: ControlMessage::PathAttached {
                        session_id: SESSION,
                        path_id: PathId::new(1),
                        path_epoch: 7,
                    },
                },
                3,
            )
            .unwrap();
        client.on_outbound(&attach(3, 0x67, 6), 4).unwrap();
        assert_eq!(
            client
                .on_inbound(
                    ControlFrame {
                        transaction_id: 3,
                        message: ControlMessage::PathAttached {
                            session_id: SESSION,
                            path_id: PathId::new(1),
                            path_epoch: 6,
                        },
                    },
                    5,
                )
                .unwrap(),
            ControlAction::Reply(reject(3, RejectCode::StaleEpoch, "path attached epoch rejected"))
        );
        assert_eq!(client.path_epoch(PathId::new(1)), Some(7));
        assert!(client.has_pending_attach(3));
        client.on_outbound(&attach(4, 0x68, 8), 6).unwrap();
        assert_eq!(
            client
                .on_inbound(
                    ControlFrame {
                        transaction_id: 4,
                        message: ControlMessage::PathAttached {
                            session_id: SESSION,
                            path_id: PathId::new(1),
                            path_epoch: 8,
                        },
                    },
                    7,
                )
                .unwrap(),
            ControlAction::None
        );
        assert_eq!(client.path_epoch(PathId::new(1)), Some(8));
    }

    #[test]
    fn client_detach_removes_the_binding_only_after_correlated_ack() {
        let mut client = ControlConnectionState::client(config()).unwrap();
        client.on_outbound(&hello(1), 0).unwrap();
        client.on_inbound(admit(1, 1_000, 1), 1).unwrap();
        client.on_outbound(&attach(2, 0x66, 7), 2).unwrap();
        client
            .on_inbound(
                ControlFrame {
                    transaction_id: 2,
                    message: ControlMessage::PathAttached {
                        session_id: SESSION,
                        path_id: PathId::new(1),
                        path_epoch: 7,
                    },
                },
                3,
            )
            .unwrap();
        let detach = ControlFrame {
            transaction_id: 3,
            message: ControlMessage::PathDetach {
                session_id: SESSION,
                path_id: PathId::new(1),
                path_epoch: 7,
                reason: "operator".into(),
            },
        };
        client.on_outbound(&detach, 4).unwrap();
        assert_eq!(client.path_epoch(PathId::new(1)), Some(7));
        assert_eq!(client.on_inbound(ack(3), 5).unwrap(), ControlAction::None);
        assert_eq!(client.path_epoch(PathId::new(1)), None);
    }

    #[test]
    fn policy_ack_and_reject_are_correlated_to_pending_gateway_update() {
        let mut state = gateway(1_000);
        admit_gateway(&mut state);
        let update = ControlFrame {
            transaction_id: 2,
            message: ControlMessage::PolicyUpdate {
                session_id: SESSION,
                policy_epoch: 2,
                policy: Bytes::from_static(b"policy-2"),
            },
        };
        state.on_outbound(&update, 1).unwrap();
        assert_eq!(state.policy_epoch(), 1);
        assert_eq!(state.on_inbound(ack(2), 2).unwrap(), ControlAction::None);
        assert_eq!(state.policy_epoch(), 2);
        let rejected = ControlFrame {
            transaction_id: 3,
            message: ControlMessage::PolicyUpdate {
                session_id: SESSION,
                policy_epoch: 3,
                policy: Bytes::from_static(b"policy-3"),
            },
        };
        state.on_outbound(&rejected, 3).unwrap();
        assert_eq!(
            state.on_inbound(reject(3, RejectCode::InvalidRequest, "no"), 4).unwrap(),
            ControlAction::None
        );
        assert_eq!(state.policy_epoch(), 2);
    }

    #[test]
    fn expired_policy_ack_cannot_mutate_and_frees_pending_capacity() {
        let mut state = gateway(1_000);
        admit_gateway(&mut state);
        let update = ControlFrame {
            transaction_id: 2,
            message: ControlMessage::PolicyUpdate {
                session_id: SESSION,
                policy_epoch: 2,
                policy: Bytes::from_static(b"policy-2"),
            },
        };
        state.on_outbound(&update, 1).unwrap();
        assert_eq!(
            state.on_inbound(ack(2), 6).unwrap(),
            ControlAction::Reply(reject(2, RejectCode::InvalidState, "unexpected acknowledgement"))
        );
        assert_eq!(state.policy_epoch(), 1);
        let replacement = ControlFrame {
            transaction_id: 3,
            message: ControlMessage::PolicyUpdate {
                session_id: SESSION,
                policy_epoch: 2,
                policy: Bytes::from_static(b"policy-2"),
            },
        };
        assert!(state.on_outbound(&replacement, 7).is_ok());
    }

    #[test]
    fn expired_admissions_never_become_active() {
        let mut gateway = gateway(10);
        assert_eq!(
            gateway.on_inbound(hello(1), 10).unwrap(),
            ControlAction::Reply(reject(1, RejectCode::Expired, "admission expired"))
        );
        assert_eq!(gateway.phase(), ConnectionPhase::AwaitHello);

        let mut client = ControlConnectionState::client(config()).unwrap();
        client.on_outbound(&hello(1), 0).unwrap();
        assert_eq!(
            client.on_inbound(admit(1, 10, 1), 10).unwrap(),
            ControlAction::Reply(reject(1, RejectCode::Expired, "admission expired"))
        );
        assert_eq!(client.phase(), ConnectionPhase::AwaitAdmit);
        assert_eq!(client.session_id(), None);
    }

    #[test]
    fn pending_client_attach_expires_at_injected_deadline() {
        let mut client = ControlConnectionState::client(config()).unwrap();
        client.on_outbound(&hello(1), 0).unwrap();
        client.on_inbound(admit(1, 1_000, 1), 1).unwrap();
        client.on_outbound(&attach(2, 0x66, 7), 2).unwrap();
        assert!(client.has_pending_attach(2));
        let late = ControlFrame {
            transaction_id: 2,
            message: ControlMessage::PathAttached {
                session_id: SESSION,
                path_id: PathId::new(1),
                path_epoch: 7,
            },
        };
        assert_eq!(
            client.on_inbound(late, 7).unwrap(),
            ControlAction::Reply(reject(2, RejectCode::InvalidState, "no matching path attach"))
        );
        assert!(!client.has_pending_attach(2));
    }

    #[test]
    fn stale_path_policy_and_wrong_direction_are_rejected_without_mutation() {
        let mut state = gateway(1_000);
        admit_gateway(&mut state);
        let path_id = assigned_path(&mut state);
        let stale = ControlFrame {
            transaction_id: 3,
            message: ControlMessage::PathDetach {
                session_id: SESSION,
                path_id,
                path_epoch: 6,
                reason: "stale".into(),
            },
        };
        assert_eq!(
            state.on_inbound(stale, 2).unwrap(),
            ControlAction::Reply(reject(3, RejectCode::StaleEpoch, "path epoch rejected"))
        );
        assert_eq!(state.path_epoch(path_id), Some(7));
        assert_eq!(
            state.on_inbound(admit(4, 1_000, 2), 3).unwrap(),
            ControlAction::Reply(reject(4, RejectCode::InvalidDirection, "message is invalid from this peer"))
        );
    }
}
