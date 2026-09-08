//! V2-only identifiers. These do not share V1's truncated wire contracts.

/// A full-width, opaque session identity issued by the gateway/controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

/// A full-width, opaque device identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId([u8; 16]);

/// A path identity scoped to one authenticated V2 session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathId(u16);

/// A flow identity scoped to one V2 session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId(u64);

/// A packet identity scoped to a session, direction, key epoch, and flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketId(u64);

/// Product scheduling classification shared by V2 packet and control paths.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficClass {
    Realtime = 0,
    Interactive = 1,
    Bulk = 2,
    Control = 3,
}

impl SessionId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl DeviceId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl PathId {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl FlowId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl PacketId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TrafficClass {
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Realtime),
            1 => Some(Self::Interactive),
            2 => Some(Self::Bulk),
            3 => Some(Self::Control),
            _ => None,
        }
    }

    pub const fn to_wire(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_preserve_their_full_width_values() {
        let session = SessionId::from_bytes([0xAB; 16]);
        let device = DeviceId::from_bytes([0xCD; 16]);

        assert_eq!(session.as_bytes(), &[0xAB; 16]);
        assert_eq!(device.as_bytes(), &[0xCD; 16]);
        assert_eq!(PathId::new(0xFEDC).get(), 0xFEDC);
        assert_eq!(FlowId::new(u64::MAX).get(), u64::MAX);
        assert_eq!(PacketId::new(u64::MAX - 1).get(), u64::MAX - 1);
    }

    #[test]
    fn traffic_class_only_accepts_known_wire_values() {
        assert_eq!(TrafficClass::from_wire(0), Some(TrafficClass::Realtime));
        assert_eq!(TrafficClass::from_wire(3), Some(TrafficClass::Control));
        assert_eq!(TrafficClass::from_wire(4), None);
    }
}
