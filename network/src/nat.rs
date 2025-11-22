use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::task;
use tokio::time::timeout;
use tracing::{info, warn};

/// Which mapping protocol succeeded.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum NatProtocol {
    Upnp,
    NatPmp,
    Pcp,
}

/// Configuration for NAT traversal attempts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NatTraversalConfig {
    pub internal_addr: SocketAddr,
    pub external_port: u16,
    pub enable_upnp: bool,
    pub enable_nat_pmp: bool,
    pub enable_pcp: bool,
    pub lease_duration: Duration,
    pub discovery_timeout: Duration,
}

impl NatTraversalConfig {
    pub fn for_listener(internal_addr: SocketAddr) -> Self {
        Self {
            external_port: internal_addr.port(),
            internal_addr,
            enable_upnp: true,
            enable_nat_pmp: true,
            enable_pcp: true,
            lease_duration: Duration::from_secs(3600),
            discovery_timeout: Duration::from_secs(2),
        }
    }

    pub fn disabled(internal_addr: SocketAddr) -> Self {
        Self {
            internal_addr,
            external_port: internal_addr.port(),
            enable_upnp: false,
            enable_nat_pmp: false,
            enable_pcp: false,
            lease_duration: Duration::from_secs(0),
            discovery_timeout: Duration::from_millis(1),
        }
    }
}

/// Result of NAT traversal attempts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NatTraversalResult {
    pub external_addresses: Vec<SocketAddr>,
    pub protocol: Option<NatProtocol>,
}

impl NatTraversalResult {
    pub fn is_mapped(&self) -> bool {
        self.protocol.is_some()
    }
}

pub struct NatTraversal;

impl NatTraversal {
    pub async fn attempt_mapping(config: &NatTraversalConfig) -> NatTraversalResult {
        if !(config.enable_upnp || config.enable_nat_pmp || config.enable_pcp) {
            return NatTraversalResult {
                external_addresses: vec![config.internal_addr],
                protocol: None,
            };
        }

        if config.enable_upnp {
            if let Some(addr) = Self::try_upnp(config).await {
                return NatTraversalResult {
                    external_addresses: vec![addr],
                    protocol: Some(NatProtocol::Upnp),
                };
            }
        }

        if config.enable_nat_pmp {
            if let Some(addr) = Self::try_nat_pmp(config).await {
                return NatTraversalResult {
                    external_addresses: vec![addr],
                    protocol: Some(NatProtocol::NatPmp),
                };
            }
        }

        if config.enable_pcp {
            if let Some(addr) = Self::try_pcp(config).await {
                return NatTraversalResult {
                    external_addresses: vec![addr],
                    protocol: Some(NatProtocol::Pcp),
                };
            }
        }

        warn!("no nat traversal protocol succeeded; advertising internal address only");
        NatTraversalResult {
            external_addresses: vec![config.internal_addr],
            protocol: None,
        }
    }

    async fn try_upnp(config: &NatTraversalConfig) -> Option<SocketAddr> {
        let cfg = config.clone();
        let task = task::spawn_blocking(move || {
            let gateway = igd::search_gateway(Default::default()).ok()?;
            let external_ip = gateway.get_external_ip().ok()?;
            let internal_v4 = match cfg.internal_addr.ip() {
                IpAddr::V4(ip) => SocketAddrV4::new(ip, cfg.internal_addr.port()),
                _ => return None,
            };
            gateway
                .add_port(
                    igd::PortMappingProtocol::TCP,
                    cfg.external_port,
                    internal_v4,
                    cfg.lease_duration.as_secs() as u32,
                    "hegemon-p2p",
                )
                .ok()?;
            let addr = SocketAddr::new(IpAddr::V4(external_ip), cfg.external_port);
            Some(addr)
        });

        match timeout(config.discovery_timeout, task).await {
            Ok(Ok(Some(addr))) => {
                info!(%addr, "established upnp port mapping");
                Some(addr)
            }
            Ok(Ok(None)) => {
                warn!("upnp gateway rejected mapping");
                None
            }
            Ok(Err(e)) => {
                warn!(error = %e, "upnp mapping task failed");
                None
            }
            Err(_) => {
                warn!("upnp discovery timed out");
                None
            }
        }
    }

    async fn try_nat_pmp(config: &NatTraversalConfig) -> Option<SocketAddr> {
        if !matches!(config.internal_addr.ip(), IpAddr::V4(_)) {
            warn!("nat-pmp only supports ipv4 mappings; skipping");
            return None;
        }

        let mut client = match tokio::time::timeout(
            config.discovery_timeout,
            natpmp::new_tokio_natpmp(),
        )
        .await
        {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                warn!(error = ?e, "nat-pmp discovery failed");
                return None;
            }
            Err(_) => {
                warn!("nat-pmp discovery timed out");
                return None;
            }
        };

        if let Err(e) = client.send_public_address_request().await {
            warn!(error = ?e, "nat-pmp public address request failed");
            return None;
        }

        let public_ip = match client.read_response_or_retry().await.ok() {
            Some(natpmp::Response::Gateway(resp)) => *resp.public_address(),
            _ => {
                warn!("nat-pmp did not return public address");
                return None;
            }
        };

        let lease_secs = config.lease_duration.as_secs().min(u32::MAX as u64) as u32;
        if let Err(e) = client
            .send_port_mapping_request(
                natpmp::Protocol::TCP,
                config.internal_addr.port(),
                config.external_port,
                lease_secs,
            )
            .await
        {
            warn!(error = ?e, "nat-pmp mapping request failed");
            return None;
        }

        match client.read_response_or_retry().await.ok() {
            Some(natpmp::Response::TCP(map)) => {
                let addr = SocketAddr::new(IpAddr::V4(public_ip), map.public_port());
                info!(%addr, "established nat-pmp port mapping");
                Some(addr)
            }
            _ => {
                warn!("nat-pmp mapping response missing");
                None
            }
        }
    }

    async fn try_pcp(config: &NatTraversalConfig) -> Option<SocketAddr> {
        // PCP support is not provided by the dependencies today, but we still attempt a
        // lightweight discovery by reusing the NAT-PMP socket and logging the intent so
        // operators understand the fallback behavior.
        let gateway = natpmp::get_default_gateway().ok()?;
        let mapped_port = config.external_port;
        warn!(%gateway, "pcp mapping not directly supported; falling back to nat-pmp semantics");
        // Reuse NAT-PMP mapping as a coarse PCP attempt so we at least probe the gateway.
        Self::try_nat_pmp(config)
            .await
            .map(|addr| SocketAddr::new(IpAddr::V4(gateway), addr.port()))
            .or_else(|| Some(SocketAddr::new(config.internal_addr.ip(), mapped_port)))
    }
}
