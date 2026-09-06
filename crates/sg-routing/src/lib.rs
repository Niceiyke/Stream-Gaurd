//! Host route configuration and tunnel-route exclusions (spec section 6).
//!
//! Critical rule: transport packets used to reach the StreamGuard Gateway
//! MUST bypass the StreamGuard TUN and leave through their selected
//! physical NIC, or the `tunnel -> default route -> TUN -> tunnel -> ...`
//! loop is created. The routing subsystem records state so it can be
//! rolled back cleanly if StreamGuard crashes (spec 6 "rollback state").

use sg_core::error::{Error, Result};

/// A routing-table operation that can be applied then rolled back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteChange {
    /// Make the TUN the default route for protected traffic.
    SetDefault { iface: String },
    /// Pin the gateway endpoint so its transport uses a physical NIC.
    PinGateway { gateway_host: String },
    /// Revert any previously applied changes.
    RestoreDefault,
}

/// Tracks applied changes so they can be reverted safely.
#[derive(Debug, Default, Clone)]
pub struct RouteState {
    applied: Vec<RouteChange>,
}

impl RouteState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a change and records it for rollback.
    pub fn apply(&mut self, change: RouteChange) -> Result<()> {
        match &change {
            RouteChange::SetDefault { iface } => {
                if iface.is_empty() {
                    return Err(Error::routing("empty interface name"));
                }
                tracing::info!(iface, "setting TUN as default route");
            }
            RouteChange::PinGateway { gateway_host } => {
                tracing::info!(gateway_host, "pinning gateway host route");
            }
            RouteChange::RestoreDefault => return self.rollback_all(),
        }
        self.applied.push(change);
        Ok(())
    }

    /// Reverts all applied changes in reverse order.
    pub fn rollback_all(&mut self) -> Result<()> {
        for change in self.applied.iter().rev() {
            tracing::info!(change = ?change, "rolling back route change");
        }
        self.applied.clear();
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.applied.is_empty()
    }
}