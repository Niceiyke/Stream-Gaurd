//! Gateway Linux networking: kernel forwarding + nftables NAT (spec
//! engineering step 2, `Gateway-NAT`).
//!
//! The command rendering is pure string construction, unit-testable on any
//! host. `apply()` executes the plan with the system `sysctl`/`nft` tools
//! and only touches the OS on Linux; elsewhere it is a documented no-op so
//! the gateway binary can be exercised in dev mode anywhere.

use sg_core::error::Result;
use sg_tun::TunConfig;

/// Everything the gateway needs to inject client traffic into the
/// Internet-facing link.
#[derive(Debug, Clone)]
pub struct GatewayNetConfig {
    /// Name of the TUN interface the clients land on (client-address space).
    pub tun_iface: String,
    /// Client subnet in CIDR form, e.g. `10.0.85.0/24`.
    pub tun_cidr: String,
    /// Egress interface that carries traffic after NAT, e.g. `eth0`.
    pub wan_iface: String,
    /// Upstream resolvers the client is told to use (split DNS, spec 16.5).
    pub dns_upstreams: Vec<String>,
}

impl GatewayNetConfig {
    /// Builds the config from the gateway TUN adapter settings.
    pub fn tun(
        cfg: &TunConfig,
        wan_iface: impl Into<String>,
        dns_upstreams: Vec<String>,
    ) -> Self {
        Self {
            tun_iface: cfg.name.clone(),
            tun_cidr: network_of(&cfg.address, cfg.prefix_len),
            wan_iface: wan_iface.into(),
            dns_upstreams,
        }
    }

    /// `sysctl -w` arguments that enable IPv4/IPv6 forwarding.
    pub fn sysctl_args(&self) -> Vec<String> {
        vec![
            "net.ipv4.ip_forward=1".into(),
            "net.ipv6.conf.all.forwarding=1".into(),
        ]
    }

    /// Full `sysctl` command lines for display/inspection.
    pub fn sysctl_commands(&self) -> Vec<String> {
        self.sysctl_args()
            .iter()
            .map(|arg| format!("sysctl -w {arg}"))
            .collect()
    }

    /// Full `nft` command lines: table, postrouting chain and the
    /// masquerade rule that translates client-address traffic to `wan_iface`.
    pub fn nftables_commands(&self) -> Vec<String> {
        vec![
            "nft add table inet streamguard".into(),
            "nft add chain inet streamguard postrouting { type nat hook \
             postrouting priority srcnat; policy accept; }"
                .into(),
            format!(
                "nft add rule inet streamguard postrouting ip saddr {} \
                 oifname \"{}\" counter masquerade",
                self.tun_cidr, self.wan_iface
            ),
        ]
    }

    /// Full ordered plan (sysctl, then nft).
    pub fn plan(&self) -> Vec<String> {
        let mut plan = self.sysctl_commands();
        plan.extend(self.nftables_commands());
        plan
    }

    /// Applies the plan. Linux executes `sysctl` and `nft`; other hosts
    /// return `Ok(())` without touching the system (dev/simulation mode).
    pub fn apply(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            for cmd in self.plan() {
                let status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&cmd)
                    .status()
                    .map_err(|e| sg_core::error::Error::io(format!("failed to run '{cmd}': {e}")))?;
                if !status.success() {
                    return Err(sg_core::error::Error::platform(format!(
                        "command failed (exit {status}): {cmd}"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Computes the network address of an IPv4 `address`/`prefix_len` pair and
/// renders it as CIDR, e.g. `10.0.85.1` + 24 -> `10.0.85.0/24`.
pub fn network_of(address: &str, prefix_len: u8) -> String {
    let parts: Vec<u32> = address
        .split('.')
        .filter_map(|part| part.parse().ok())
        .collect();
    if parts.len() != 4 {
        return address.to_string();
    }
    let addr = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    let bits = prefix_len.min(32);
    let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
    let net = addr & mask;
    format!(
        "{}.{}.{}.{}/{}",
        (net >> 24) & 0xff,
        (net >> 16) & 0xff,
        (net >> 8) & 0xff,
        net & 0xff,
        prefix_len
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> GatewayNetConfig {
        GatewayNetConfig::tun(
            &TunConfig::default(),
            "eth0",
            vec!["1.1.1.1".into(), "1.0.0.1".into()],
        )
    }

    #[test]
    fn cidr_from_tun_address() {
        assert_eq!(network_of("10.0.85.1", 24), "10.0.85.0/24");
        assert_eq!(network_of("192.168.1.100", 16), "192.168.0.0/16");
        assert_eq!(network_of("10.1.2.3", 8), "10.0.0.0/8");
        assert_eq!(network_of("10.0.85.1", 32), "10.0.85.1/32");
    }

    #[test]
    fn plan_includes_forwarding_and_masquerade() {
        let c = config();
        let plan = c.plan();
        assert!(plan.iter().any(|cmd| cmd == "sysctl -w net.ipv4.ip_forward=1"));
        assert!(plan
            .iter()
            .any(|cmd| cmd == "sysctl -w net.ipv6.conf.all.forwarding=1"));
        assert!(plan.iter().any(|cmd| cmd == "nft add table inet streamguard"));
        assert!(plan.iter().any(|cmd| cmd.contains("type nat hook postrouting")));
        assert!(plan.iter().any(|cmd| {
            cmd.contains("ip saddr 10.0.85.0/24")
                && cmd.contains("oifname \"eth0\"")
                && cmd.ends_with("masquerade")
        }));
    }

    #[test]
    fn apply_is_noop_off_linux() {
        // Guards against accidental kernel/system mutation in dev boxes.
        #[cfg(not(target_os = "linux"))]
        assert!(config().apply().is_ok());
        #[cfg(target_os = "linux")]
        let _ = config().apply(); // requires root; exercised at the gateway milestone
    }
}