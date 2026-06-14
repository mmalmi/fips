//! Darwin UDP socket tuning.
//!
//! macOS does not expose UDP GSO/TSO to userspace tunnels, so high-rate
//! Wi-Fi sends are often limited by per-datagram kernel scheduling. The
//! service type is the one low-cost Darwin hint that can change how the
//! socket is queued by the host networking stack and Wi-Fi WMM.

#![cfg(target_os = "macos")]

use std::io;
use std::os::fd::RawFd;
use std::sync::OnceLock;

use tracing::{debug, warn};

const SO_NET_SERVICE_TYPE: libc::c_int = 0x1116;

const NET_SERVICE_TYPE_BE: libc::c_int = 0;
const NET_SERVICE_TYPE_BK: libc::c_int = 1;
const NET_SERVICE_TYPE_SIG: libc::c_int = 2;
const NET_SERVICE_TYPE_VI: libc::c_int = 3;
const NET_SERVICE_TYPE_VO: libc::c_int = 4;
const NET_SERVICE_TYPE_RV: libc::c_int = 5;
const NET_SERVICE_TYPE_AV: libc::c_int = 6;
const NET_SERVICE_TYPE_OAM: libc::c_int = 7;
const NET_SERVICE_TYPE_RD: libc::c_int = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NetServiceType {
    name: &'static str,
    value: libc::c_int,
}

const VPN_SERVICE_TYPE: NetServiceType = NetServiceType {
    name: "oam",
    value: NET_SERVICE_TYPE_OAM,
};
const DEFAULT_SERVICE_TYPE: Option<NetServiceType> = Some(NetServiceType {
    name: "rd",
    value: NET_SERVICE_TYPE_RD,
});

#[derive(Debug)]
struct Tuning {
    service_type: Option<NetServiceType>,
}

static TUNING: OnceLock<Tuning> = OnceLock::new();

pub(crate) fn apply_udp_socket_tuning(fd: RawFd, context: &'static str) {
    if let Some(service_type) = tuning().service_type {
        match set_sockopt_int(
            fd,
            libc::SOL_SOCKET,
            SO_NET_SERVICE_TYPE,
            service_type.value,
        ) {
            Ok(()) => {
                debug!(
                    context,
                    service_type = service_type.name,
                    value = service_type.value,
                    "set Darwin UDP SO_NET_SERVICE_TYPE"
                );
            }
            Err(err) => {
                warn!(
                    context,
                    service_type = service_type.name,
                    value = service_type.value,
                    %err,
                    "failed to set Darwin UDP SO_NET_SERVICE_TYPE"
                );
            }
        }
    }
}

fn tuning() -> &'static Tuning {
    TUNING.get_or_init(|| {
        let service_type = match std::env::var("FIPS_MACOS_NET_SERVICE_TYPE") {
            Ok(raw) => match parse_net_service_type(&raw) {
                Ok(service_type) => service_type,
                Err(()) => {
                    let default = default_service_type()
                        .map(|service_type| service_type.name)
                        .unwrap_or("off");
                    warn!(
                        value = %raw,
                        default,
                        "invalid FIPS_MACOS_NET_SERVICE_TYPE, using default"
                    );
                    default_service_type()
                }
            },
            // Apple documents OAM as fitting VPN tunnels, but current
            // MacBook-to-mini LAN tests show RD cuts tunnel ping queueing
            // without the VI/RV retransmit penalty. Keep this overridable for
            // NIC-specific throughput A/Bs.
            Err(_) => default_service_type(),
        };

        Tuning { service_type }
    })
}

fn default_service_type() -> Option<NetServiceType> {
    DEFAULT_SERVICE_TYPE
}

fn parse_net_service_type(raw: &str) -> Result<Option<NetServiceType>, ()> {
    let normalized = raw.trim().to_ascii_lowercase().replace(['-', '_'], "");
    let service_type = match normalized.as_str() {
        "" | "off" | "none" | "disabled" | "disable" | "unset" | "default" => None,
        "vpn" | "oam" => Some(VPN_SERVICE_TYPE),
        "be" | "besteffort" => Some(NetServiceType {
            name: "be",
            value: NET_SERVICE_TYPE_BE,
        }),
        "bk" | "background" => Some(NetServiceType {
            name: "bk",
            value: NET_SERVICE_TYPE_BK,
        }),
        "sig" | "signaling" => Some(NetServiceType {
            name: "sig",
            value: NET_SERVICE_TYPE_SIG,
        }),
        "vi" | "interactivevideo" | "video" => Some(NetServiceType {
            name: "vi",
            value: NET_SERVICE_TYPE_VI,
        }),
        "vo" | "interactivevoice" | "voice" => Some(NetServiceType {
            name: "vo",
            value: NET_SERVICE_TYPE_VO,
        }),
        "rv" | "responsivemultimedia" | "responsivemultimediavideo" => Some(NetServiceType {
            name: "rv",
            value: NET_SERVICE_TYPE_RV,
        }),
        "av" | "multimedia" | "audiovideo" => Some(NetServiceType {
            name: "av",
            value: NET_SERVICE_TYPE_AV,
        }),
        "rd" | "responsivedata" => Some(NetServiceType {
            name: "rd",
            value: NET_SERVICE_TYPE_RD,
        }),
        _ => return Err(()),
    };
    Ok(service_type)
}

fn set_sockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_service_type_aliases() {
        assert_eq!(parse_net_service_type("off").unwrap(), None);
        assert_eq!(parse_net_service_type("default").unwrap(), None);
        assert_eq!(
            parse_net_service_type("vpn").unwrap(),
            Some(VPN_SERVICE_TYPE)
        );
        assert_eq!(
            parse_net_service_type("interactive_video").unwrap(),
            Some(NetServiceType {
                name: "vi",
                value: NET_SERVICE_TYPE_VI
            })
        );
        assert_eq!(
            parse_net_service_type("responsive-data").unwrap(),
            Some(NetServiceType {
                name: "rd",
                value: NET_SERVICE_TYPE_RD
            })
        );
        assert!(parse_net_service_type("wat").is_err());
    }

    #[test]
    fn default_service_type_is_responsive_data() {
        assert_eq!(
            default_service_type(),
            Some(NetServiceType {
                name: "rd",
                value: NET_SERVICE_TYPE_RD
            })
        );
    }
}
