use super::TunError;
use futures::TryStreamExt;
use rtnetlink::{Handle, LinkUnspec, RouteMessageBuilder, new_connection};
use std::net::Ipv6Addr;
use tracing::debug;

/// Check if IPv6 is disabled system-wide.
pub fn is_ipv6_disabled() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// Check if a network interface already exists.
pub async fn interface_exists(name: &str) -> bool {
    let Ok((connection, handle, _)) = new_connection() else {
        return false;
    };
    tokio::spawn(connection);

    get_interface_index(&handle, name).await.is_ok()
}

/// Delete a network interface by name.
pub async fn delete_interface(name: &str) -> Result<(), TunError> {
    let (connection, handle, _) = new_connection()
        .map_err(|e| TunError::Configure(format!("netlink connection failed: {}", e)))?;
    tokio::spawn(connection);

    let index = get_interface_index(&handle, name).await?;
    handle.link().del(index).execute().await?;
    Ok(())
}

/// Configure a network interface with an IPv6 address via netlink.
pub async fn configure_interface(name: &str, addr: Ipv6Addr, mtu: u16) -> Result<(), TunError> {
    let (connection, handle, _) = new_connection()
        .map_err(|e| TunError::Configure(format!("netlink connection failed: {}", e)))?;
    tokio::spawn(connection);

    // Get interface index
    let index = get_interface_index(&handle, name).await?;

    // Add IPv6 address with /128 prefix (point-to-point)
    handle
        .address()
        .add(index, std::net::IpAddr::V6(addr), 128)
        .execute()
        .await?;

    // Set MTU
    handle
        .link()
        .change(LinkUnspec::new_with_index(index).mtu(mtu as u32).build())
        .execute()
        .await?;

    // Bring interface up
    handle
        .link()
        .change(LinkUnspec::new_with_index(index).up().build())
        .execute()
        .await?;

    // Add route for fd00::/8 (FIPS address space) via this interface
    let fd_prefix: Ipv6Addr = "fd00::".parse().unwrap();
    let route = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(fd_prefix, 8)
        .output_interface(index)
        .build();
    handle
        .route()
        .add(route)
        .execute()
        .await
        .map_err(|e| TunError::Configure(format!("failed to add fd00::/8 route: {}", e)))?;

    // Add ip6 rule to ensure fd00::/8 uses the main table, preventing other
    // routing software (e.g. Tailscale) from intercepting FIPS traffic via
    // catch-all rules in auxiliary routing tables.
    let mut rule_req = handle
        .rule()
        .add()
        .v6()
        .destination_prefix(fd_prefix, 8)
        .table_id(254)
        .priority(5265);
    rule_req.message_mut().header.action = 1.into(); // FR_ACT_TO_TBL
    if let Err(e) = rule_req.execute().await {
        debug!("ip6 rule for fd00::/8 not added (may already exist): {e}");
    }

    Ok(())
}

/// Get the interface index by name.
async fn get_interface_index(handle: &Handle, name: &str) -> Result<u32, TunError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();

    if let Some(link) = links.try_next().await? {
        Ok(link.header.index)
    } else {
        Err(TunError::InterfaceNotFound(name.to_string()))
    }
}
