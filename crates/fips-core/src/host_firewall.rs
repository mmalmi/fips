//! Host firewall helpers for FIPS mesh TUN interfaces.
//!
//! This module intentionally owns only narrowly scoped rules for one mesh
//! interface. The policy is default-deny for FIPS-addressed inbound traffic and
//! outbound traffic, with stateful outbound TCP allowed and optional inbound TCP
//! service ports.

use std::fmt::Write as _;
use std::process::Output;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::{Command, Stdio};

use thiserror::Error;

/// The IPv6 prefix used by FIPS mesh addresses.
pub const FIPS_MESH_IPV6_PREFIX: &str = "fd00::/8";

const DEFAULT_LINUX_TABLE_NAME: &str = "fips_host";
const DEFAULT_MACOS_ANCHOR_NAME: &str = "com.apple/fips/host";

/// Platform firewall configuration for a FIPS host-facing TUN interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFirewallConfig {
    interface: String,
    inbound_tcp_ports: Vec<u16>,
    linux_table_name: String,
    macos_anchor_name: String,
}

impl HostFirewallConfig {
    /// Build a firewall config for `interface`.
    #[must_use]
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            inbound_tcp_ports: Vec::new(),
            linux_table_name: DEFAULT_LINUX_TABLE_NAME.to_string(),
            macos_anchor_name: DEFAULT_MACOS_ANCHOR_NAME.to_string(),
        }
    }

    /// Allow inbound TCP connections to the supplied destination ports.
    #[must_use]
    pub fn with_inbound_tcp_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.inbound_tcp_ports = normalized_tcp_ports(ports);
        self
    }

    /// Override the managed Linux nftables table name.
    #[must_use]
    pub fn with_linux_table_name(mut self, table_name: impl Into<String>) -> Self {
        self.linux_table_name = table_name.into();
        self
    }

    /// Override the managed macOS PF anchor name.
    #[must_use]
    pub fn with_macos_anchor_name(mut self, anchor_name: impl Into<String>) -> Self {
        self.macos_anchor_name = anchor_name.into();
        self
    }

    /// TUN interface matched by the rules.
    #[must_use]
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Normalized inbound TCP destination ports.
    #[must_use]
    pub fn inbound_tcp_ports(&self) -> &[u16] {
        &self.inbound_tcp_ports
    }

    /// Managed Linux nftables table name.
    #[must_use]
    pub fn linux_table_name(&self) -> &str {
        &self.linux_table_name
    }

    /// Managed macOS PF anchor name.
    #[must_use]
    pub fn macos_anchor_name(&self) -> &str {
        &self.macos_anchor_name
    }

    fn validate(&self) -> Result<(), HostFirewallError> {
        validate_interface_name(&self.interface)?;
        validate_nft_table_name(&self.linux_table_name)?;
        validate_pf_anchor_name(&self.macos_anchor_name)?;
        Ok(())
    }
}

/// RAII guard for installed host firewall rules.
///
/// Dropping the guard removes only the managed table/anchor. It does not flush
/// the host's main firewall ruleset.
#[derive(Debug)]
pub struct HostFirewallGuard {
    backend: HostFirewallBackend,
}

#[derive(Debug)]
enum HostFirewallBackend {
    #[cfg(target_os = "linux")]
    Linux { table_name: String },
    #[cfg(target_os = "macos")]
    Macos {
        anchor_name: String,
        enable_token: Option<String>,
    },
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Unsupported,
}

impl HostFirewallGuard {
    /// True when this target has an implemented host firewall backend.
    #[must_use]
    pub const fn platform_supported() -> bool {
        cfg!(any(target_os = "linux", target_os = "macos"))
    }

    /// True when this target has an implemented backend and the required
    /// platform command is present.
    #[must_use]
    pub fn platform_available() -> bool {
        #[cfg(target_os = "linux")]
        return command_exists("nft");
        #[cfg(target_os = "macos")]
        return command_exists("pfctl");
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return false;
    }

    /// Install host firewall rules for the configured mesh interface.
    ///
    /// Returns an error on unsupported platforms or when the platform firewall
    /// command is unavailable. Callers should treat that as a hard failure
    /// before exposing the host tunnel.
    pub fn install(config: &HostFirewallConfig) -> Result<Self, HostFirewallError> {
        config.validate()?;

        #[cfg(target_os = "linux")]
        {
            install_linux_firewall(config)
        }
        #[cfg(target_os = "macos")]
        {
            install_macos_firewall(config)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = config;
            Err(HostFirewallError::UnsupportedPlatform)
        }
    }

    /// Remove managed firewall artifacts without requiring a live guard.
    ///
    /// Useful after crash/restart paths where the previous process may have
    /// died before its guard could drop.
    pub fn cleanup_disabled_artifacts(config: &HostFirewallConfig) {
        #[cfg(target_os = "linux")]
        remove_nft_table(config.linux_table_name());
        #[cfg(target_os = "macos")]
        flush_pf_anchor(config.macos_anchor_name());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = config;
    }
}

impl Drop for HostFirewallGuard {
    fn drop(&mut self) {
        match &self.backend {
            #[cfg(target_os = "linux")]
            HostFirewallBackend::Linux { table_name } => remove_nft_table(table_name),
            #[cfg(target_os = "macos")]
            HostFirewallBackend::Macos {
                anchor_name,
                enable_token,
            } => {
                flush_pf_anchor(anchor_name);
                if let Some(token) = enable_token {
                    release_pf_enable_token(token);
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            HostFirewallBackend::Unsupported => {}
        }
    }
}

/// Errors returned while installing platform firewall rules.
#[derive(Debug, Error)]
pub enum HostFirewallError {
    /// Host firewall support is not implemented for the current platform.
    #[error("host firewall is not supported on this platform")]
    UnsupportedPlatform,

    /// A required platform command was not found in PATH.
    #[error("required firewall command `{0}` was not found")]
    MissingCommand(&'static str),

    /// A user-supplied or kernel-supplied name was unsafe for rule rendering.
    #[error("invalid {field}: {value}")]
    InvalidName {
        /// Field name.
        field: &'static str,
        /// Invalid value.
        value: String,
    },

    /// Failed to spawn or communicate with a platform firewall command.
    #[error("failed to run `{command}`: {source}")]
    CommandIo {
        /// Command name.
        command: &'static str,
        /// I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A platform firewall command exited unsuccessfully.
    #[error("`{command}` exited with {status}: {stderr}")]
    CommandFailed {
        /// Command name.
        command: &'static str,
        /// Process exit status.
        status: std::process::ExitStatus,
        /// Captured stderr.
        stderr: String,
    },
}

fn normalized_tcp_ports(ports: impl IntoIterator<Item = u16>) -> Vec<u16> {
    let mut ports = ports.into_iter().collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn validate_interface_name(name: &str) -> Result<(), HostFirewallError> {
    validate_name(
        "interface",
        name,
        |ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'),
        false,
    )
}

fn validate_nft_table_name(name: &str) -> Result<(), HostFirewallError> {
    if name.is_empty()
        || !name
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
    {
        return Err(HostFirewallError::InvalidName {
            field: "nft table name",
            value: name.to_string(),
        });
    }
    validate_name(
        "nft table name",
        name,
        |ch| ch.is_ascii_alphanumeric() || ch == '_',
        false,
    )
}

fn validate_pf_anchor_name(name: &str) -> Result<(), HostFirewallError> {
    validate_name(
        "pf anchor name",
        name,
        |ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/'),
        true,
    )
}

fn validate_name(
    field: &'static str,
    value: &str,
    valid_char: impl Fn(char) -> bool,
    allow_slash: bool,
) -> Result<(), HostFirewallError> {
    let slash_ok = allow_slash && !value.starts_with('/') && !value.ends_with('/');
    let slash_valid = !value.contains('/') || slash_ok;
    if value.is_empty() || !slash_valid || !value.chars().all(valid_char) {
        return Err(HostFirewallError::InvalidName {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
#[must_use]
pub fn render_nft_host_firewall_rules(
    table_name: &str,
    iface: &str,
    inbound_tcp_ports: &[u16],
) -> String {
    let ports = normalized_tcp_ports(inbound_tcp_ports.iter().copied());
    let inbound_tcp_rule = match ports.as_slice() {
        [] => String::new(),
        [port] => format!("    tcp dport {port} accept\n"),
        ports => {
            let joined = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("    tcp dport {{ {joined} }} accept\n")
        }
    };

    format!(
        "table inet {table_name} {{\n\
           chain input {{\n\
             type filter hook input priority 0; policy accept;\n\
             iifname != \"{iface}\" return\n\
             meta nfproto != ipv6 return\n\
             ip6 saddr != {FIPS_MESH_IPV6_PREFIX} return\n\
             ct state established,related accept\n\
         {inbound_tcp_rule}\
             counter drop\n\
           }}\n\
           chain output {{\n\
             type filter hook output priority 0; policy accept;\n\
             oifname != \"{iface}\" return\n\
             meta nfproto != ipv6 return\n\
             ip6 daddr != {FIPS_MESH_IPV6_PREFIX} return\n\
             ct state established,related accept\n\
             meta l4proto tcp accept\n\
             counter drop\n\
           }}\n\
         }}\n"
    )
}

#[cfg(any(test, target_os = "macos"))]
#[must_use]
pub fn render_macos_pf_host_firewall_rules(iface: &str, inbound_tcp_ports: &[u16]) -> String {
    let ports = normalized_tcp_ports(inbound_tcp_ports.iter().copied());
    let mut rules = String::from("# Managed by fips-core for FIPS host routing.\n");

    match ports.as_slice() {
        [] => {}
        [port] => {
            let _ = writeln!(
                rules,
                "pass in quick on {iface} inet6 proto tcp from {FIPS_MESH_IPV6_PREFIX} to any port {port} flags S/SA keep state"
            );
        }
        ports => {
            let joined = ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                rules,
                "pass in quick on {iface} inet6 proto tcp from {FIPS_MESH_IPV6_PREFIX} to any port {{ {joined} }} flags S/SA keep state"
            );
        }
    }

    let _ = write!(
        rules,
        "pass out quick on {iface} inet6 proto tcp from any to {FIPS_MESH_IPV6_PREFIX} flags S/SA keep state\n\
         block drop in quick on {iface} inet6 from {FIPS_MESH_IPV6_PREFIX} to any\n\
         block drop out quick on {iface} inet6 from any to {FIPS_MESH_IPV6_PREFIX}\n"
    );
    rules
}

#[cfg(target_os = "linux")]
fn install_linux_firewall(
    config: &HostFirewallConfig,
) -> Result<HostFirewallGuard, HostFirewallError> {
    if !command_exists("nft") {
        return Err(HostFirewallError::MissingCommand("nft"));
    }

    let rules = render_nft_host_firewall_rules(
        config.linux_table_name(),
        config.interface(),
        config.inbound_tcp_ports(),
    );
    remove_nft_table(config.linux_table_name());
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| HostFirewallError::CommandIo {
            command: "nft",
            source,
        })?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| HostFirewallError::CommandIo {
                command: "nft",
                source: std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "nft stdin unavailable",
                ),
            })?;
        use std::io::Write as _;
        stdin
            .write_all(rules.as_bytes())
            .map_err(|source| HostFirewallError::CommandIo {
                command: "nft",
                source,
            })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|source| HostFirewallError::CommandIo {
            command: "nft",
            source,
        })?;
    ensure_success("nft", output)?;

    Ok(HostFirewallGuard {
        backend: HostFirewallBackend::Linux {
            table_name: config.linux_table_name().to_string(),
        },
    })
}

#[cfg(target_os = "linux")]
fn remove_nft_table(table_name: &str) {
    if !command_exists("nft") {
        return;
    }
    let _ = Command::new("nft")
        .arg("delete")
        .arg("table")
        .arg("inet")
        .arg(table_name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(target_os = "macos")]
fn install_macos_firewall(
    config: &HostFirewallConfig,
) -> Result<HostFirewallGuard, HostFirewallError> {
    if !command_exists("pfctl") {
        return Err(HostFirewallError::MissingCommand("pfctl"));
    }

    let rules = render_macos_pf_host_firewall_rules(config.interface(), config.inbound_tcp_ports());
    let _ = run_pfctl(&["-a", config.macos_anchor_name(), "-F", "rules"], None)?;
    run_pfctl(&["-a", config.macos_anchor_name(), "-f", "-"], Some(&rules))?;
    let enable_output = run_pfctl(&["-E"], None)?;
    let enable_token = parse_pf_enable_token(&String::from_utf8_lossy(&enable_output.stdout));

    Ok(HostFirewallGuard {
        backend: HostFirewallBackend::Macos {
            anchor_name: config.macos_anchor_name().to_string(),
            enable_token,
        },
    })
}

#[cfg(target_os = "macos")]
fn flush_pf_anchor(anchor_name: &str) {
    if !command_exists("pfctl") {
        return;
    }
    let _ = run_pfctl(&["-a", anchor_name, "-F", "rules"], None);
}

#[cfg(target_os = "macos")]
fn release_pf_enable_token(token: &str) {
    if !command_exists("pfctl") {
        return;
    }
    let _ = run_pfctl(&["-X", token], None);
}

#[cfg(target_os = "macos")]
fn run_pfctl(args: &[&str], stdin: Option<&str>) -> Result<Output, HostFirewallError> {
    let mut command = Command::new("pfctl");
    command.args(args).stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|source| HostFirewallError::CommandIo {
            command: "pfctl",
            source,
        })?;
    if let Some(input) = stdin {
        let child_stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| HostFirewallError::CommandIo {
                command: "pfctl",
                source: std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "pfctl stdin unavailable",
                ),
            })?;
        use std::io::Write as _;
        child_stdin
            .write_all(input.as_bytes())
            .map_err(|source| HostFirewallError::CommandIo {
                command: "pfctl",
                source,
            })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|source| HostFirewallError::CommandIo {
            command: "pfctl",
            source,
        })?;
    ensure_success("pfctl", output)
}

#[cfg(target_os = "macos")]
fn parse_pf_enable_token(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        if label.trim().eq_ignore_ascii_case("token") {
            let token = value.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
        None
    })
}

fn ensure_success(command: &'static str, output: Output) -> Result<Output, HostFirewallError> {
    if output.status.success() {
        Ok(output)
    } else {
        Err(HostFirewallError::CommandFailed {
            command,
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn command_exists(command: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {command} >/dev/null 2>&1"))
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_normalizes_inbound_tcp_ports() {
        let config = HostFirewallConfig::new("fips0").with_inbound_tcp_ports([443, 22, 22]);

        assert_eq!(config.inbound_tcp_ports(), &[22, 443]);
    }

    #[test]
    fn rejects_unsafe_names() {
        assert!(HostFirewallConfig::new("utun0").validate().is_ok());
        assert!(HostFirewallConfig::new("utun0; reboot").validate().is_err());
        assert!(
            HostFirewallConfig::new("utun0")
                .with_linux_table_name("1bad")
                .validate()
                .is_err()
        );
        assert!(
            HostFirewallConfig::new("utun0")
                .with_macos_anchor_name("/bad")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn nft_rules_default_to_outbound_tcp_only() {
        let rules = render_nft_host_firewall_rules("fips_host", "nvpn0", &[]);

        assert!(rules.contains("table inet fips_host"));
        assert!(rules.contains("iifname != \"nvpn0\" return"));
        assert!(rules.contains("oifname != \"nvpn0\" return"));
        assert!(rules.contains("ip6 saddr != fd00::/8 return"));
        assert!(rules.contains("ip6 daddr != fd00::/8 return"));
        assert!(rules.contains("meta l4proto tcp accept"));
        assert!(!rules.contains("tcp dport"));
    }

    #[test]
    fn nft_rules_allow_configured_inbound_tcp_ports() {
        let rules = render_nft_host_firewall_rules("fips_host", "nvpn0", &[443, 22, 22]);

        assert!(rules.contains("tcp dport { 22, 443 } accept"));
    }

    #[test]
    fn macos_pf_rules_default_to_outbound_tcp_only() {
        let rules = render_macos_pf_host_firewall_rules("utun8", &[]);

        assert!(rules.contains("pass out quick on utun8 inet6 proto tcp"));
        assert!(rules.contains("block drop in quick on utun8 inet6 from fd00::/8 to any"));
        assert!(rules.contains("block drop out quick on utun8 inet6 from any to fd00::/8"));
        assert!(!rules.contains("pass in quick"));
        assert!(!rules.contains("proto udp"));
    }

    #[test]
    fn macos_pf_rules_allow_configured_inbound_tcp_ports() {
        let rules = render_macos_pf_host_firewall_rules("utun8", &[443, 22, 22]);

        assert!(rules.contains(
            "pass in quick on utun8 inet6 proto tcp from fd00::/8 to any port { 22, 443 }"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_pf_enable_token() {
        assert_eq!(
            parse_pf_enable_token("Token : 1234567890\n"),
            Some("1234567890".to_string())
        );
    }
}
