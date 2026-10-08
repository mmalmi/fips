#[test]
fn idle_mmp_ticks_preserve_log_deadline_and_fallback_name() {
    let owner = fsp_owner(980);
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8).with_fsp_mmp(
            crate::config::SessionMmpConfig {
                mode: crate::mmp::MmpMode::Minimal,
                log_interval_secs: 10,
                ..Default::default()
            },
            true,
        ),
    );
    let now = std::time::Instant::now();
    let first = mover.collect_fsp_mmp_reports(now);
    assert_eq!(first.metric_logs.len(), 1);
    assert_eq!(
        first.metric_logs[0].fallback_session_name,
        owner.node_addr().to_string()
    );
    for offset in 1..10 {
        let idle = mover.collect_fsp_mmp_reports(now + std::time::Duration::from_secs(offset));
        assert!(idle.metric_logs.is_empty());
        assert!(idle.reports.is_empty());
    }
    let due = mover.collect_fsp_mmp_reports(now + std::time::Duration::from_secs(10));
    assert_eq!(due.metric_logs.len(), 1);
    assert_eq!(
        due.metric_logs[0].fallback_session_name,
        first.metric_logs[0].fallback_session_name
    );
    assert!(due.reports.is_empty());
}
