mod tests {
    use super::*;

    #[test]
    fn test_acl_show_command_name() {
        assert_eq!(AclCommands::Show.command_name(), "show_acl");
    }

    #[test]
    fn test_show_discovery_trust_command_name() {
        assert_eq!(
            ShowCommands::DiscoveryTrust.command_name(),
            "show_discovery_trust"
        );
    }

    #[test]
    fn test_cli_parses_acl_show() {
        let cli = Cli::try_parse_from(["fipsctl", "acl", "show"]).unwrap();

        assert!(matches!(
            cli.command,
            Commands::Acl {
                what: AclCommands::Show
            }
        ));
    }

    #[test]
    fn test_cli_parses_show_discovery_trust() {
        let cli = Cli::try_parse_from(["fipsctl", "show", "discovery-trust"]).unwrap();

        assert!(matches!(
            cli.command,
            Commands::Show {
                what: ShowCommands::DiscoveryTrust
            }
        ));
    }

    #[test]
    fn test_cli_parses_ratings_export() {
        let cli = Cli::try_parse_from([
            "fipsctl",
            "ratings",
            "export",
            "--scope",
            "fips.peer",
            "--format",
            "events",
            "-o",
            "ratings.json",
        ])
        .unwrap();

        match cli.command {
            Commands::Ratings {
                what: RatingsCommands::Export { format, output, .. },
            } => {
                assert_eq!(format, RatingExportFormat::Events);
                assert_eq!(output, Some(PathBuf::from("ratings.json")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn test_cli_parses_ratings_publish() {
        let cli = Cli::try_parse_from([
            "fipsctl",
            "ratings",
            "publish",
            "--scope",
            "fips.peer",
            "--relay",
            "wss://relay.example",
            "--json",
        ])
        .unwrap();

        match cli.command {
            Commands::Ratings {
                what:
                    RatingsCommands::Publish {
                        scope,
                        relays,
                        interval_secs,
                        json,
                    },
            } => {
                assert_eq!(scope, "fips.peer");
                assert_eq!(relays, vec!["wss://relay.example".to_string()]);
                assert_eq!(interval_secs, None);
                assert!(json);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn test_cli_parses_ratings_publish_interval() {
        let cli = Cli::try_parse_from([
            "fipsctl",
            "ratings",
            "publish",
            "--relay",
            "wss://relay.example",
            "--interval-secs",
            "300",
        ])
        .unwrap();

        match cli.command {
            Commands::Ratings {
                what:
                    RatingsCommands::Publish {
                        interval_secs,
                        relays,
                        ..
                    },
            } => {
                assert_eq!(relays, vec!["wss://relay.example".to_string()]);
                assert_eq!(interval_secs, Some(300));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn test_cli_rejects_zero_ratings_publish_interval() {
        assert!(
            Cli::try_parse_from([
                "fipsctl",
                "ratings",
                "publish",
                "--relay",
                "wss://relay.example",
                "--interval-secs",
                "0",
            ])
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn control_exchange_preserves_wire_contract() {
        use std::io::{Read as _, Write as _};

        let (mut client, mut server) = ControlStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let worker =
            std::thread::spawn(move || exchange_request(&mut client, "{\"command\":\"x\"}\n"));

        let mut request = String::new();
        server.read_to_string(&mut request).unwrap();
        assert_eq!(request, "{\"command\":\"x\"}\n");
        server
            .write_all(b"{\"status\":\"ok\",\"data\":1}\n{\"status\":\"error\"}\n")
            .unwrap();
        drop(server);

        let response = worker.join().unwrap().unwrap();
        assert_eq!(response, serde_json::json!({"status": "ok", "data": 1}));
    }

    #[test]
    fn interprets_control_response_errors_consistently() {
        let explicit = serde_json::json!({"status": "error", "message": "boom"});
        let missing = serde_json::json!({"status": "error"});
        assert_eq!(response_error(&explicit), Some("boom"));
        assert_eq!(response_error(&missing), Some("unknown error"));
        assert_eq!(response_error(&serde_json::json!({"status": "ok"})), None);
        assert_eq!(
            control_response_data(&explicit, "cmd").unwrap_err(),
            "cmd failed: boom"
        );
    }

    #[test]
    fn detects_bare_ula_literal() {
        assert!(is_fips_mesh_address("fd9d:abcd::1"));
        assert!(is_fips_mesh_address("fd00::"));
        assert!(is_fips_mesh_address(
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        ));
    }

    #[test]
    fn detects_bracketed_ula_with_port() {
        assert!(is_fips_mesh_address("[fd9d:abcd::1]:2121"));
        assert!(is_fips_mesh_address("[fd00::1]:8443"));
    }

    #[test]
    fn detects_bare_ula_with_port() {
        assert!(is_fips_mesh_address("fd9d:abcd::1:2121"));
    }

    #[test]
    fn rejects_non_ula_ipv6() {
        // fc00::/7 other half (fcXX:) is also ULA but not fd00::/8 — we only
        // block the fd-prefixed half that FIPS actually uses.
        assert!(!is_fips_mesh_address("fc00::1"));
        assert!(!is_fips_mesh_address("::1"));
        assert!(!is_fips_mesh_address("2001:db8::1"));
        assert!(!is_fips_mesh_address("[2001:db8::1]:2121"));
    }

    #[test]
    fn ignores_ipv4_and_hostnames() {
        assert!(!is_fips_mesh_address("192.0.2.1:2121"));
        assert!(!is_fips_mesh_address("peer.example.com:2121"));
        assert!(!is_fips_mesh_address("coinos.pro:2121"));
    }

    #[test]
    fn validates_only_target_transports() {
        assert!(validate_connect_address("fd9d::1:2121", "udp").is_err());
        assert!(validate_connect_address("fd9d::1:2121", "tcp").is_err());
        assert!(validate_connect_address("fd9d::1:2121", "ethernet").is_err());
        // Other transports are not inspected — they may legitimately accept
        // non-IP endpoints (tor onion, etc.).
        assert!(validate_connect_address("fd9d::1:2121", "tor").is_ok());
    }

    #[test]
    fn allows_valid_endpoints() {
        assert!(validate_connect_address("192.0.2.1:2121", "udp").is_ok());
        assert!(validate_connect_address("peer.example.com:2121", "tcp").is_ok());
        assert!(validate_connect_address("[2001:db8::1]:2121", "udp").is_ok());
    }
}
