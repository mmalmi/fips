use mdns_sd::{DaemonStatus, IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct RunningDaemon(ServiceDaemon);

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        if let Ok(stopped) = self.0.shutdown() {
            let _ = stopped.recv_timeout(Duration::from_secs(2));
        }
    }
}

#[test]
fn protection_denial_prevents_daemon_start() {
    for deny_ipv6 in [false, true] {
        let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let result = ServiceDaemon::new_with_socket_protector(
            port,
            Arc::new(move |socket| {
                let address = socket.local_addr()?;
                assert_eq!(address.port(), 0, "protection must precede bind");
                if address.is_ipv6() == deny_ipv6 {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "host protection denied",
                    ))
                } else {
                    Ok(())
                }
            }),
        );
        match result {
            Ok(daemon) => {
                drop(RunningDaemon(daemon));
                panic!("daemon started despite a denied socket");
            }
            Err(error) => assert!(error.to_string().contains("host protection denied")),
        }
        // IPv6 denial happens after IPv4 bind. The failed constructor must
        // close that already-created family socket before returning.
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).expect("failed startup released sockets");
    }
}

fn protected_daemon(port: u16) -> (RunningDaemon, Arc<Mutex<Vec<UdpSocket>>>) {
    let sockets = Arc::new(Mutex::new(Vec::new()));
    let retained = sockets.clone();
    let daemon = RunningDaemon(
        ServiceDaemon::new_with_socket_protector(
            port,
            Arc::new(move |socket| {
                assert_eq!(
                    socket.local_addr()?.port(),
                    0,
                    "protection must precede bind"
                );
                retained.lock().unwrap().push(socket.try_clone()?);
                Ok(())
            }),
        )
        .unwrap(),
    );
    assert_eq!(
        daemon
            .0
            .status()
            .unwrap()
            .recv_timeout(Duration::from_secs(2))
            .unwrap(),
        DaemonStatus::Running
    );
    let guarded = sockets.lock().unwrap();
    assert!(guarded
        .iter()
        .any(|socket| socket.local_addr().unwrap().is_ipv4()));
    assert!(guarded
        .iter()
        .any(|socket| socket.local_addr().unwrap().is_ipv6()));
    assert!(guarded
        .iter()
        .all(|socket| socket.local_addr().unwrap().port() > 0));
    drop(guarded);
    (daemon, sockets)
}

#[test]
fn interface_changes_retain_the_protected_native_sockets() {
    let (daemon, sockets) = protected_daemon(0);
    let before: Vec<_> = sockets
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.local_addr().unwrap())
        .collect();
    daemon.0.disable_interface(IfKind::All).unwrap();
    daemon.0.enable_interface(IfKind::LoopbackV4).unwrap();
    assert_eq!(
        daemon
            .0
            .status()
            .unwrap()
            .recv_timeout(Duration::from_secs(2))
            .unwrap(),
        DaemonStatus::Running
    );
    let after: Vec<_> = sockets
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.local_addr().unwrap())
        .collect();
    assert_eq!(before, after);
}

#[test]
fn protected_daemons_discover_services_after_an_interface_cycle() {
    let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let (publisher, _) = protected_daemon(port);
    let (browser, _) = protected_daemon(port);
    for daemon in [&publisher.0, &browser.0] {
        daemon.disable_interface(IfKind::All).unwrap();
        daemon.enable_interface(IfKind::LoopbackV4).unwrap();
        assert_eq!(
            daemon
                .status()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            DaemonStatus::Running
        );
    }
    let service_type = "_nvpn-policy._udp.local.";
    let service = ServiceInfo::new(
        service_type,
        "protected-native-socket",
        "protected-native-socket.local.",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        12345,
        None,
    )
    .unwrap();
    let fullname = service.get_fullname().to_string();
    let events = browser.0.browse(service_type).unwrap();
    publisher.0.register(service).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(ServiceEvent::ServiceResolved(info)) =
            events.recv_timeout(Duration::from_millis(100))
        {
            if info.get_fullname() == fullname {
                assert_eq!(info.get_port(), 12345);
                return;
            }
        }
    }
    panic!("service discovery did not cross protected native sockets");
}
