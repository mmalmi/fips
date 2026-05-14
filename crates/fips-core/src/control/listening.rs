//! Listening-socket enumeration for fipstop.
//!
//! Walks `/proc/net/tcp6` and `/proc/net/udp6`, pairs entries with owning
//! processes by scanning `/proc/<pid>/fd`, and filters to sockets reachable
//! from fips0: IPv6 wildcard binds or binds to the node's fips0 address.

#[cfg(target_os = "linux")]
use std::net::IpAddr;
use std::net::Ipv6Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListeningSocket {
    pub proto: Proto,
    pub local_addr: Ipv6Addr,
    pub port: u16,
    pub pid: Option<u32>,
    pub process: Option<String>,
    /// True when bound to `::` rather than the fips0 address.
    pub wildcard_bind: bool,
}

#[cfg(target_os = "linux")]
pub fn enumerate(fips0_addr: Ipv6Addr) -> Vec<ListeningSocket> {
    use procfs::net::TcpState;

    let inode_to_pid = build_inode_to_pid_map();
    let mut out = Vec::new();

    if let Ok(entries) = procfs::net::tcp6() {
        for entry in entries {
            if entry.state != TcpState::Listen {
                continue;
            }
            if let Some(sock) = build_entry(
                Proto::Tcp,
                entry.local_address.ip(),
                entry.local_address.port(),
                entry.inode,
                &inode_to_pid,
                fips0_addr,
            ) {
                out.push(sock);
            }
        }
    }

    if let Ok(entries) = procfs::net::udp6() {
        for entry in entries {
            // Connected UDP sockets carry a non-wildcard remote and are not
            // passive listeners.
            if !entry.remote_address.ip().is_unspecified() {
                continue;
            }
            if let Some(sock) = build_entry(
                Proto::Udp,
                entry.local_address.ip(),
                entry.local_address.port(),
                entry.inode,
                &inode_to_pid,
                fips0_addr,
            ) {
                out.push(sock);
            }
        }
    }

    out.sort_by(|a, b| {
        a.proto
            .as_str()
            .cmp(b.proto.as_str())
            .then(a.port.cmp(&b.port))
            .then(a.pid.cmp(&b.pid))
    });
    out
}

#[cfg(not(target_os = "linux"))]
pub fn enumerate(_fips0_addr: Ipv6Addr) -> Vec<ListeningSocket> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn build_entry(
    proto: Proto,
    local: IpAddr,
    port: u16,
    inode: u64,
    inode_to_pid: &std::collections::HashMap<u64, (u32, String)>,
    fips0_addr: Ipv6Addr,
) -> Option<ListeningSocket> {
    let local_addr = match local {
        IpAddr::V6(addr) => addr,
        IpAddr::V4(_) => return None,
    };

    let wildcard_bind = local_addr.is_unspecified();
    if !wildcard_bind && local_addr != fips0_addr {
        return None;
    }

    let (pid, process) = match inode_to_pid.get(&inode) {
        Some((pid, process)) => (Some(*pid), Some(process.clone())),
        None => (None, None),
    };

    Some(ListeningSocket {
        proto,
        local_addr,
        port,
        pid,
        process,
        wildcard_bind,
    })
}

#[cfg(target_os = "linux")]
fn build_inode_to_pid_map() -> std::collections::HashMap<u64, (u32, String)> {
    use procfs::process::FDTarget;

    let mut map = std::collections::HashMap::new();
    let Ok(processes) = procfs::process::all_processes() else {
        return map;
    };

    for process in processes.flatten() {
        let Ok(stat) = process.stat() else {
            continue;
        };
        let Ok(fds) = process.fd() else {
            continue;
        };

        for fd in fds.flatten() {
            if let FDTarget::Socket(inode) = fd.target {
                map.insert(inode, (stat.pid as u32, stat.comm.clone()));
            }
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_as_str() {
        assert_eq!(Proto::Tcp.as_str(), "tcp");
        assert_eq!(Proto::Udp.as_str(), "udp");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enumerate_runs_without_panicking() {
        let _ = enumerate(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_entry_filters_non_fips0_binds() {
        let inode_map = std::collections::HashMap::new();
        let fips0 = Ipv6Addr::new(0xfd97, 0, 0, 0, 0, 0, 0, 1);

        let wildcard = build_entry(
            Proto::Tcp,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            22,
            0,
            &inode_map,
            fips0,
        )
        .expect("wildcard bind is reachable");
        assert!(wildcard.wildcard_bind);

        let specific = build_entry(Proto::Tcp, IpAddr::V6(fips0), 22, 0, &inode_map, fips0)
            .expect("fips0 bind is reachable");
        assert!(!specific.wildcard_bind);

        let loopback = build_entry(
            Proto::Tcp,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            22,
            0,
            &inode_map,
            fips0,
        );
        assert!(loopback.is_none());

        let other = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let other = build_entry(Proto::Tcp, IpAddr::V6(other), 22, 0, &inode_map, fips0);
        assert!(other.is_none());

        let ipv4 = build_entry(
            Proto::Tcp,
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            22,
            0,
            &inode_map,
            fips0,
        );
        assert!(ipv4.is_none());
    }
}
