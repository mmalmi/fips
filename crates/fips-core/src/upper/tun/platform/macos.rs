use super::TunError;
use std::net::Ipv6Addr;
use tokio::process::Command;

/// Check if IPv6 is disabled system-wide.
pub fn is_ipv6_disabled() -> bool {
    // macOS: check via sysctl; if the key doesn't exist, IPv6 is enabled
    std::process::Command::new("sysctl")
        .args(["-n", "net.inet6.ip6.disabled"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "1")
        .unwrap_or(false)
}

/// Check if a network interface already exists.
pub async fn interface_exists(name: &str) -> bool {
    Command::new("ifconfig")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Shut down a network interface by name.
///
/// On macOS, utun devices are automatically destroyed when the file
/// descriptor is closed. Bringing the interface down causes any
/// blocking reads to return an error, which unblocks the reader thread.
pub async fn delete_interface(name: &str) -> Result<(), TunError> {
    run_cmd("ifconfig", &[name, "down"]).await
}

/// Configure a network interface with an IPv6 address using ifconfig/route.
pub async fn configure_interface(name: &str, addr: Ipv6Addr, mtu: u16) -> Result<(), TunError> {
    // Add IPv6 address with /128 prefix
    run_cmd(
        "ifconfig",
        &[name, "inet6", &addr.to_string(), "prefixlen", "128"],
    )
    .await?;

    // Set MTU
    run_cmd("ifconfig", &[name, "mtu", &mtu.to_string()]).await?;

    // Bring interface up
    run_cmd("ifconfig", &[name, "up"]).await?;

    // Add route for fd00::/8 (FIPS address space) via this interface
    run_cmd(
        "route",
        &[
            "add",
            "-inet6",
            "-prefixlen",
            "8",
            "fd00::",
            "-interface",
            name,
        ],
    )
    .await?;

    Ok(())
}

/// Run a command and return an error if it fails.
async fn run_cmd(program: &str, args: &[&str]) -> Result<(), TunError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| TunError::Configure(format!("{} failed: {}", program, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TunError::Configure(format!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}
