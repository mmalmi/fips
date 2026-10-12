use crab_nat::{
    natpmp, pcp, InternetProtocol, PortMapping, PortMappingOptions, SocketProtector, TimeoutConfig,
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU16,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

fn options() -> PortMappingOptions {
    PortMappingOptions {
        timeout_config: Some(TimeoutConfig {
            initial_timeout: Duration::from_millis(100),
            max_retries: 0,
            max_retry_timeout: None,
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn real_gateway_protects_creation_fallback_renewal_release_and_peer_mapping() {
    timeout(Duration::from_secs(10), async {
        let gateway: IpAddr = Ipv4Addr::LOCALHOST.into();
        let server = UdpSocket::bind((gateway, crab_nat::GATEWAY_PORT)).await.unwrap();
        let packets = Arc::new(AtomicUsize::new(0));
        let fallback = Arc::new(AtomicBool::new(true));
        let task = tokio::spawn({
            let packets = packets.clone(); let fallback = fallback.clone();
            async move {
                let mut data = [0u8; 1500];
                loop {
                    let (n, source) = server.recv_from(&mut data).await.unwrap();
                    packets.fetch_add(1, Ordering::SeqCst);
                    let request = &data[..n];
                    let reply = if request[0] == 2 && fallback.load(Ordering::SeqCst) {
                        vec![0, 0x80 | request[1], 0, 1]
                    } else if request[0] == 2 {
                        let mut reply = request.to_vec();
                        reply[1] |= 0x80;
                        reply[8..24].fill(0);
                        reply[42..44].copy_from_slice(&45000u16.to_be_bytes());
                        reply[44..60].copy_from_slice(&Ipv4Addr::new(203,0,113,5).to_ipv6_mapped().octets());
                        reply
                    } else if request[1] == 0 {
                        vec![0, 128, 0, 0, 0, 0, 0, 1, 203, 0, 113, 5]
                    } else {
                        let mut reply = vec![0, 128 | request[1], 0, 0, 0, 0, 0, 1];
                        reply.extend_from_slice(&request[4..6]);
                        let lifetime = &request[8..12];
                        reply.extend_from_slice(&if lifetime == [0,0,0,0] { 0u16 } else { 45000u16 }.to_be_bytes());
                        reply.extend_from_slice(lifetime);
                        reply
                    };
                    server.send_to(&reply, source).await.unwrap();
                }
            }
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let deny = Arc::new(AtomicBool::new(true));
        let protector: SocketProtector = Arc::new({
            let calls=calls.clone(); let deny=deny.clone();
            move |socket| {
                assert!(socket.peer_addr().is_err(), "socket connected before protection");
                assert_ne!(socket.local_addr()?.port(), 0);
                calls.fetch_add(1, Ordering::SeqCst);
                if deny.load(Ordering::SeqCst) { Err(io::Error::new(io::ErrorKind::PermissionDenied, "test policy")) } else { Ok(()) }
            }
        });
        let result=natpmp::external_address_with_socket_protector(gateway, options().timeout_config, protector.clone()).await;
        assert!(matches!(result, Err(natpmp::Failure::Socket(ref e)) if e.kind()==io::ErrorKind::PermissionDenied), "denied socket reached the gateway: {result:?}");
        assert_eq!(packets.load(Ordering::SeqCst), 0);
        deny.store(false, Ordering::SeqCst);
        let port=NonZeroU16::new(8080).unwrap();
        let mut mapping=PortMapping::new_with_socket_protector(gateway,gateway,InternetProtocol::Tcp,port,options(),protector.clone()).await.unwrap();
        assert!(matches!(mapping.mapping_type(), crab_nat::PortMappingType::NatPmp));
        assert_eq!(mapping.external_port().get(),45000);
        mapping.renew().await.unwrap();
        let address=natpmp::external_address_with_socket_protector(gateway,options().timeout_config,protector.clone()).await.unwrap();
        assert_eq!(address, Ipv4Addr::new(203,0,113,5));
        let before=packets.load(Ordering::SeqCst);
        deny.store(true, Ordering::SeqCst);
        assert!(mapping.renew().await.is_err());
        let (_, mapping)=mapping.try_drop().await.unwrap_err();
        assert_eq!(packets.load(Ordering::SeqCst), before);
        deny.store(false, Ordering::SeqCst);
        mapping.try_drop().await.unwrap();
        fallback.store(false, Ordering::SeqCst);
        let mut mapping=PortMapping::new_with_socket_protector(gateway,gateway,InternetProtocol::Udp,port,options(),protector.clone()).await.unwrap();
        assert!(matches!(mapping.mapping_type(), crab_nat::PortMappingType::Pcp { .. }));
        mapping.renew().await.unwrap(); mapping.try_drop().await.unwrap();
        let mut peer=pcp::peer_mapping_with_socket_protector(pcp::BaseMapRequest::new(gateway,gateway,InternetProtocol::Udp,port),None,None,SocketAddr::from(([203,0,113,6],9999)),options(),protector.clone()).await.unwrap();
        peer.renew().await.unwrap(); peer.try_drop().await.unwrap();
        let mut all=pcp::port_mapping_all_ports_with_socket_protector(gateway,gateway,None,None,None,Some(60),options().timeout_config,protector).await.unwrap();
        all.renew().await.unwrap(); all.try_drop().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), packets.load(Ordering::SeqCst)+3, "every protected attempt must pass the callback");
        // Legacy callers still exercise the same protocol implementation with native sockets.
        assert_eq!(natpmp::external_address(gateway, options().timeout_config).await.unwrap(), address);
        task.abort(); let _=task.await;
    }).await.unwrap();
}
