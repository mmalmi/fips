use super::*;

use crate::Identity;

fn test_npub() -> String {
    Identity::generate().npub()
}

fn test_peer(npub: &str) -> PeerIdentity {
    PeerIdentity::from_npub(npub).unwrap()
}

fn test_node_addr() -> NodeAddr {
    *test_peer(&test_npub()).node_addr()
}

fn write_file(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
}

fn acl_with_shape(has_allow: bool, has_deny: bool, allow_all: bool, deny_all: bool) -> PeerAcl {
    let mut acl = PeerAcl::default();
    if has_allow {
        acl.allow.insert(test_node_addr());
    }
    if has_deny {
        acl.deny.insert(test_node_addr());
    }
    acl.allow_all = allow_all;
    acl.deny_all = deny_all;
    acl
}

#[test]
fn test_acl_decision_allowed_and_display() {
    assert!(PeerAclDecision::AllowList.allowed());
    assert!(!PeerAclDecision::DenyList.allowed());
    assert!(PeerAclDecision::DefaultAllow.allowed());

    assert_eq!(PeerAclDecision::AllowList.to_string(), "allowlist match");
    assert_eq!(PeerAclDecision::DenyList.to_string(), "denylist match");
    assert_eq!(PeerAclDecision::DefaultAllow.to_string(), "default allow");
}

#[test]
fn test_acl_context_display() {
    assert_eq!(
        PeerAclContext::OutboundConnect.to_string(),
        "outbound_connect"
    );
    assert_eq!(
        PeerAclContext::InboundHandshake.to_string(),
        "inbound_handshake"
    );
    assert_eq!(
        PeerAclContext::OutboundHandshake.to_string(),
        "outbound_handshake"
    );
}

#[test]
fn test_acl_missing_files_default_open() {
    let acl = PeerAcl::load_files(
        Path::new("/nonexistent/allow"),
        Path::new("/nonexistent/deny"),
    );
    let peer = PeerIdentity::from_npub(&test_npub()).unwrap();

    assert_eq!(acl.check(&peer), PeerAclDecision::DefaultAllow);
    assert!(acl.is_empty());
}

#[test]
fn test_acl_allow_match_wins() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let npub = test_npub();

    std::fs::write(&allow, format!("{npub}\n")).unwrap();
    std::fs::write(&deny, format!("ALL\n{npub}\n")).unwrap();

    let acl = PeerAcl::load_files(&allow, &deny);
    let peer = PeerIdentity::from_npub(&npub).unwrap();

    assert_eq!(acl.check(&peer), PeerAclDecision::AllowList);
}

#[test]
fn test_acl_allow_all_overrides_deny_all_and_specific_entries() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let npub = test_npub();

    write_file(&allow, "aLl # wildcard\n");
    write_file(&deny, &format!("ALL\n{npub}\n"));

    let acl = PeerAcl::load_files(&allow, &deny);
    let peer = test_peer(&npub);

    assert_eq!(acl.check(&peer), PeerAclDecision::AllowList);
    assert_eq!(acl.effective_mode(), "allow_all");
    assert_eq!(acl.default_decision(), "allow");
    assert!(acl.allow_file_entries().is_empty());
    assert_eq!(acl.deny_file_entries(), vec![npub.clone()]);
    assert!(acl.allow_entries().is_empty());
    assert_eq!(acl.deny_entries(), vec![npub]);
}

#[test]
fn test_acl_allowlist_miss_falls_through_to_default_allow() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let allowed = test_npub();
    let denied = test_npub();

    std::fs::write(&allow, format!("{allowed}\n")).unwrap();

    let acl = PeerAcl::load_files(&allow, &deny);

    assert_eq!(
        acl.check(&PeerIdentity::from_npub(&allowed).unwrap()),
        PeerAclDecision::AllowList
    );
    assert_eq!(
        acl.check(&PeerIdentity::from_npub(&denied).unwrap()),
        PeerAclDecision::DefaultAllow
    );
}

#[test]
fn test_acl_deny_only() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let denied = test_npub();
    let other = test_npub();

    std::fs::write(&deny, format!("{denied}\n")).unwrap();

    let acl = PeerAcl::load_files(&allow, &deny);

    assert_eq!(
        acl.check(&PeerIdentity::from_npub(&denied).unwrap()),
        PeerAclDecision::DenyList
    );
    assert_eq!(
        acl.check(&PeerIdentity::from_npub(&other).unwrap()),
        PeerAclDecision::DefaultAllow
    );
}

#[test]
fn test_acl_deny_all() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");

    std::fs::write(&deny, "ALL\n").unwrap();

    let acl = PeerAcl::load_files(&allow, &deny);
    let peer = PeerIdentity::from_npub(&test_npub()).unwrap();

    assert_eq!(acl.check(&peer), PeerAclDecision::DenyList);
}

#[test]
fn test_acl_deny_applies_after_allowlist_miss() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let allowed = test_npub();
    let denied = test_npub();

    std::fs::write(&allow, format!("{allowed}\n")).unwrap();
    std::fs::write(&deny, format!("{denied}\n")).unwrap();

    let acl = PeerAcl::load_files(&allow, &deny);

    assert_eq!(
        acl.check(&PeerIdentity::from_npub(&denied).unwrap()),
        PeerAclDecision::DenyList
    );
}

#[test]
fn test_acl_effective_mode_and_default_decision_matrix() {
    let default_open = acl_with_shape(false, false, false, false);
    assert_eq!(default_open.effective_mode(), "default_open");
    assert_eq!(default_open.default_decision(), "allow");

    let allowlist = acl_with_shape(true, false, false, false);
    assert_eq!(allowlist.effective_mode(), "allowlist");
    assert_eq!(allowlist.default_decision(), "allow");

    let denylist = acl_with_shape(false, true, false, false);
    assert_eq!(denylist.effective_mode(), "denylist");
    assert_eq!(denylist.default_decision(), "allow");

    let allow_then_deny = acl_with_shape(true, true, false, false);
    assert_eq!(allow_then_deny.effective_mode(), "allow_then_deny");
    assert_eq!(allow_then_deny.default_decision(), "allow");

    let deny_all = acl_with_shape(false, false, false, true);
    assert_eq!(deny_all.effective_mode(), "deny_all");
    assert_eq!(deny_all.default_decision(), "deny");

    let allow_then_deny_all = acl_with_shape(true, false, false, true);
    assert_eq!(allow_then_deny_all.effective_mode(), "allow_then_deny_all");
    assert_eq!(allow_then_deny_all.default_decision(), "deny");

    let allow_all = acl_with_shape(false, false, true, false);
    assert_eq!(allow_all.effective_mode(), "allow_all");
    assert_eq!(allow_all.default_decision(), "allow");
}

#[test]
fn test_acl_inline_comments_and_bad_lines() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let npub = test_npub();

    std::fs::write(
        &allow,
        format!("# comment\n{npub} # inline comment\ninvalid entry here\n"),
    )
    .unwrap();

    let acl = PeerAcl::load_files(&allow, &deny);

    assert_eq!(
        acl.check(&PeerIdentity::from_npub(&npub).unwrap()),
        PeerAclDecision::AllowList
    );
}

#[test]
fn test_acl_unknown_alias_and_invalid_entries_do_not_activate_enforcement() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");

    write_file(
        &allow,
        "# comment only\nunknown-alias\nnot-a-valid-npub\ninvalid entry here\n",
    );

    let acl = PeerAcl::load_files(&allow, &deny);

    assert!(acl.is_empty());
    assert!(acl.allow_file_entries().is_empty());
    assert!(acl.allow_entries().is_empty());
}

#[test]
fn test_acl_read_error_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    std::fs::create_dir(&allow).unwrap();

    let acl = PeerAcl::load_files(&allow, &deny);

    assert!(acl.is_empty());
    assert_eq!(
        acl.check(&test_peer(&test_npub())),
        PeerAclDecision::DefaultAllow
    );
}

#[test]
fn test_acl_alias_lookup_is_case_insensitive() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let npub = test_npub();
    let mut hosts = HostMap::new();

    hosts.insert("node-a", &npub).unwrap();
    write_file(&allow, "NODE-A\n");

    let acl = PeerAcl::load_files_with_hosts(&allow, &deny, &hosts);

    assert_eq!(acl.allow_file_entries(), vec!["NODE-A".to_string()]);
    assert_eq!(acl.allow_entries(), vec![npub.clone()]);
    assert_eq!(acl.check(&test_peer(&npub)), PeerAclDecision::AllowList);
}

#[test]
fn test_acl_alias_and_npub_for_same_peer_deduplicate_effective_entries() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let npub = test_npub();
    let mut hosts = HostMap::new();

    hosts.insert("node-a", &npub).unwrap();
    write_file(&allow, &format!("node-a\n{npub}\nnode-a\n"));

    let acl = PeerAcl::load_files_with_hosts(&allow, &deny, &hosts);

    assert_eq!(
        acl.allow_file_entries(),
        vec!["node-a".to_string(), npub.clone()]
    );
    assert_eq!(acl.allow_entries(), vec![npub.clone()]);
    assert_eq!(acl.check(&test_peer(&npub)), PeerAclDecision::AllowList);
}

#[test]
fn test_acl_reloader_detects_change() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let denied = test_npub();

    let mut reloader = PeerAclReloader::with_paths(allow.clone(), deny.clone());
    assert!(!reloader.check_reload());

    std::thread::sleep(std::time::Duration::from_millis(5));
    std::fs::write(&deny, format!("{denied}\n")).unwrap();

    assert!(reloader.check_reload());
    assert_eq!(
        reloader
            .acl()
            .check(&PeerIdentity::from_npub(&denied).unwrap()),
        PeerAclDecision::DenyList
    );
}

#[test]
fn test_acl_reloader_detects_allow_file_removal() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let allowed = test_npub();

    write_file(&allow, &format!("{allowed}\n"));
    let mut reloader = PeerAclReloader::with_paths(allow.clone(), deny);
    assert_eq!(
        reloader.acl().check(&test_peer(&allowed)),
        PeerAclDecision::AllowList
    );

    std::thread::sleep(std::time::Duration::from_millis(5));
    std::fs::remove_file(&allow).unwrap();

    assert!(reloader.check_reload());
    assert!(reloader.acl().is_empty());
    assert_eq!(
        reloader.acl().check(&test_peer(&allowed)),
        PeerAclDecision::DefaultAllow
    );
}

#[test]
fn test_acl_status_reports_effective_state_and_entries() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let allowed = test_npub();
    let denied = test_npub();

    std::fs::write(&allow, format!("{allowed}\n")).unwrap();
    std::fs::write(&deny, format!("{denied}\n")).unwrap();

    let reloader = PeerAclReloader::with_paths(allow.clone(), deny.clone());
    let status = reloader.status();

    assert_eq!(status.allow_file, allow.display().to_string());
    assert_eq!(status.deny_file, deny.display().to_string());
    assert!(status.enforcement_active);
    assert_eq!(status.effective_mode, "allow_then_deny");
    assert_eq!(status.default_decision, "allow");
    assert_eq!(status.allow_file_entries, vec![allowed.clone()]);
    assert_eq!(status.deny_file_entries, vec![denied.clone()]);
    assert_eq!(status.allow_entries, vec![allowed]);
    assert_eq!(status.deny_entries, vec![denied]);
}

#[test]
fn test_acl_status_reports_default_open_state() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");

    let reloader = PeerAclReloader::with_paths(allow, deny);
    let status = reloader.status();

    assert!(!status.enforcement_active);
    assert_eq!(status.effective_mode, "default_open");
    assert_eq!(status.default_decision, "allow");
    assert!(!status.allow_all);
    assert!(!status.deny_all);
    assert!(status.allow_file_entries.is_empty());
    assert!(status.deny_file_entries.is_empty());
    assert!(status.allow_entries.is_empty());
    assert!(status.deny_entries.is_empty());
}

#[test]
fn test_acl_status_reports_allow_all_state() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    write_file(&allow, "ALL\n");

    let reloader = PeerAclReloader::with_paths(allow, deny);
    let status = reloader.status();

    assert!(status.enforcement_active);
    assert_eq!(status.effective_mode, "allow_all");
    assert_eq!(status.default_decision, "allow");
    assert!(status.allow_all);
    assert!(!status.deny_all);
    assert!(status.allow_file_entries.is_empty());
    assert!(status.allow_entries.is_empty());
}

#[test]
fn test_acl_status_reports_deny_all_default_decision() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");

    std::fs::write(&deny, "ALL\n").unwrap();

    let reloader = PeerAclReloader::with_paths(allow, deny);
    let status = reloader.status();

    assert_eq!(status.effective_mode, "deny_all");
    assert_eq!(status.default_decision, "deny");
}

#[test]
fn test_acl_alias_resolves_from_host_map() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let npub = test_npub();
    let mut hosts = HostMap::new();

    hosts.insert("node-a", &npub).unwrap();
    std::fs::write(&allow, "node-a\n").unwrap();

    let acl = PeerAcl::load_files_with_hosts(&allow, &deny, &hosts);
    let peer = PeerIdentity::from_npub(&npub).unwrap();

    assert_eq!(acl.allow_file_entries(), vec!["node-a".to_string()]);
    assert_eq!(acl.allow_entries(), vec![npub]);
    assert_eq!(acl.check(&peer), PeerAclDecision::AllowList);
}

#[test]
fn test_acl_reloader_detects_hosts_change_for_alias_entry() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let hosts = dir.path().join("hosts");
    let npub = test_npub();

    std::fs::write(&allow, "node-a\n").unwrap();

    let mut reloader =
        PeerAclReloader::with_alias_sources(allow.clone(), deny, HostMap::new(), hosts.clone());
    assert!(reloader.acl().is_empty());

    std::thread::sleep(std::time::Duration::from_millis(5));
    std::fs::write(&hosts, format!("node-a {npub}\n")).unwrap();

    assert!(reloader.check_reload());
    assert_eq!(
        reloader.acl().allow_file_entries(),
        vec!["node-a".to_string()]
    );
    assert_eq!(reloader.acl().allow_entries(), vec![npub.clone()]);
    assert_eq!(
        reloader
            .acl()
            .check(&PeerIdentity::from_npub(&npub).unwrap()),
        PeerAclDecision::AllowList
    );
}

#[test]
fn test_acl_reloader_detects_hosts_removal_for_alias_entry() {
    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let hosts = dir.path().join("hosts");
    let npub = test_npub();

    write_file(&allow, "node-a\n");
    write_file(&hosts, &format!("node-a {npub}\n"));

    let mut reloader =
        PeerAclReloader::with_alias_sources(allow, deny, HostMap::new(), hosts.clone());
    assert_eq!(
        reloader.acl().check(&test_peer(&npub)),
        PeerAclDecision::AllowList
    );

    std::thread::sleep(std::time::Duration::from_millis(5));
    std::fs::remove_file(&hosts).unwrap();

    assert!(reloader.check_reload());
    assert!(reloader.acl().is_empty());
    assert_eq!(
        reloader.acl().check(&test_peer(&npub)),
        PeerAclDecision::DefaultAllow
    );
}
