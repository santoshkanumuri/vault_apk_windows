//! Local advertisements are connection hints. LAN sync authenticates every peer separately.
use mdns_sd::{Receiver, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{collections::BTreeMap, net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream}};

const SERVICE: &str = "_nuvori-sync._tcp.local.";

pub(crate) fn local_addresses() -> Vec<IpAddr> {
    let mut addresses: Vec<_> = if_addrs::get_if_addrs().unwrap_or_default().into_iter()
        .map(|interface| interface.ip()).filter(|ip| private_address(*ip)).collect();
    addresses.sort();
    addresses.dedup();
    addresses.truncate(16);
    addresses
}

pub(crate) fn private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() && !ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

pub(crate) struct LanDiscovery {
    daemon: ServiceDaemon,
    events: Receiver<ServiceEvent>,
    peers: BTreeMap<String, Vec<SocketAddr>>,
    instance: String,
    advertised: Option<(String, String, TcpListener)>,
}

impl LanDiscovery {
    pub fn new() -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|e| e.to_string())?;
        let events = daemon.browse(SERVICE).map_err(|e| e.to_string())?;
        Ok(Self { daemon, events, peers: BTreeMap::new(),
            instance: format!("nuvori-{}", uuid::Uuid::new_v4()), advertised: None })
    }

    pub fn endpoints(&mut self) -> Vec<SocketAddr> {
        while let Ok(event) = self.events.try_recv() {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    if info.get_fullname().starts_with(&self.instance) || info.get_port() < 1024 { continue; }
                    if !self.peers.contains_key(info.get_fullname()) && self.peers.len() >= 64 { continue; }
                    let mut addresses: Vec<_> = info.get_addresses_v4().into_iter()
                        .filter(|ip| ip.is_private()).map(|ip| SocketAddr::new(IpAddr::V4(ip), info.get_port())).collect();
                    addresses.sort();
                    self.peers.insert(info.get_fullname().to_owned(), addresses);
                }
                ServiceEvent::ServiceRemoved(_, name) => { self.peers.remove(&name); }
                _ => {}
            }
        }
        self.peers.values().flatten().copied().collect()
    }

    pub fn advertise(&mut self, vault: Option<&str>) -> Result<(), String> {
        if self.advertised.as_ref().map(|(id, _, _)| id.as_str()) == vault { return Ok(()); }
        if let Some((_, name, _)) = self.advertised.take() {
            let _ = self.daemon.unregister(&name);
        }
        let Some(vault) = vault else { return Ok(()); };
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, crate::lan_sync::sync_port(vault)))
            .or_else(|_| TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let service = ServiceInfo::new(SERVICE, &self.instance, &format!("{}.local.", self.instance),
            "", listener.local_addr().map_err(|e| e.to_string())?.port(), None)
            .map_err(|e| e.to_string())?.enable_addr_auto();
        let fullname = service.get_fullname().to_owned();
        self.daemon.register(service).map_err(|e| e.to_string())?;
        self.advertised = Some((vault.to_owned(), fullname, listener));
        Ok(())
    }

    pub fn accept(&self) -> Option<TcpStream> {
        let listener = &self.advertised.as_ref()?.2;
        let (stream, address) = listener.accept().ok()?;
        if !private_address(address.ip()) { return None; }
        stream.set_nonblocking(false).ok()?;
        Some(stream)
    }
}

impl Drop for LanDiscovery {
    fn drop(&mut self) { let _ = self.daemon.shutdown(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn advertisements_never_authorize_public_or_loopback_connections() {
        for ip in ["192.168.1.2", "10.0.0.2", "172.16.0.2", "fd00::2"] {
            assert!(private_address(ip.parse().unwrap()));
        }
        for ip in ["127.0.0.1", "169.254.1.2", "8.8.8.8", "::1", "fe80::2"] {
            assert!(!private_address(ip.parse().unwrap()));
        }
    }
    #[test]
    #[ignore = "requires a private local network with multicast enabled"]
    fn discovers_windows_listener_and_removes_it_when_sync_is_disabled() {
        assert!(!local_addresses().is_empty());
        let mut advertiser = LanDiscovery::new().unwrap();
        let mut observer = LanDiscovery::new().unwrap();
        advertiser.advertise(Some("discovery-regression")).unwrap();
        let name = advertiser.advertised.as_ref().unwrap().1.clone();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let address = loop {
            observer.endpoints();
            if let Some(address) = observer.peers.get(&name).and_then(|addresses| addresses.first()) { break *address; }
            assert!(std::time::Instant::now() < deadline, "mDNS did not resolve the Windows listener");
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        let _client = TcpStream::connect_timeout(&address, std::time::Duration::from_secs(2)).unwrap();
        assert!(advertiser.accept().is_some());
        advertiser.advertise(None).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            observer.endpoints();
            if !observer.peers.contains_key(&name) { break; }
            assert!(std::time::Instant::now() < deadline, "disabled sync left a stale advertisement");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

}
