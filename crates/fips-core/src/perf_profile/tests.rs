#[cfg(target_os = "linux")]
use super::udp_send_batch_tail_bucket_flags;
use super::{
    EVENTS, Event, HIST_BUCKETS, N_EVENTS, N_STAGES, Stage, TraceStamp, bucket_upper_ns,
    bulk_queue_depth_absolute_flags, bulk_queue_depth_threshold_flags, event_from_index,
    fmt_rate_per_sec, percentile_ns, record_event_count_sample, record_wait_threshold,
    stage_from_index,
};
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

#[test]
fn trace_stamp_is_compact_for_hot_queue_records() {
    assert_eq!(std::mem::size_of::<Option<TraceStamp>>(), 8);
    assert!(std::mem::size_of::<Option<TraceStamp>>() < std::mem::size_of::<Option<Instant>>());
}

#[test]
fn reporter_rate_format_preserves_sub_one_hz_samples() {
    assert_eq!(fmt_rate_per_sec(10, 5), "2");
    assert_eq!(fmt_rate_per_sec(1, 5), "0.2");
    assert_eq!(fmt_rate_per_sec(1, 60), "0.017");
    assert_eq!(fmt_rate_per_sec(1_234_567, 10), "123456.7");
}

#[test]
fn percentile_uses_observed_histogram_count_when_stage_count_leads() {
    let mut hist = [0u64; HIST_BUCKETS];
    hist[10] = 1;

    assert_eq!(percentile_ns(&hist, 2, 99), bucket_upper_ns(10));
    assert_eq!(percentile_ns(&[0u64; HIST_BUCKETS], 1, 99), 0);
}

#[test]
fn event_table_exposes_liveness_and_send_path_events() {
    assert_eq!(N_EVENTS, 262);
    assert!(
        (Event::DecryptWorkerFspOpenQueueDepthGe4096 as usize) < N_EVENTS,
        "last event must fit in the EVENTS table"
    );
    assert_eq!(
        event_from_index(Event::DecryptFallbackBacklogHigh as usize).name(),
        "decrypt_fallback_backlog_high"
    );
    assert_eq!(
        event_from_index(Event::DecryptAuthenticatedBacklogHigh as usize).name(),
        "decrypt_authenticated_backlog_high"
    );
    assert_eq!(
        event_from_index(Event::EndpointEventBulkBacklogHigh as usize).name(),
        "endpoint_event_bulk_backlog_high"
    );
    assert_eq!(
        event_from_index(Event::EndpointEventDequeueEvents as usize).name(),
        "endpoint_event_dequeue_events"
    );
    assert_eq!(
        event_from_index(Event::EndpointEventDequeueMessages as usize).name(),
        "endpoint_event_dequeue_messages"
    );
    assert_eq!(
        event_from_index(Event::EndpointEventDequeuePriorityMessages as usize).name(),
        "endpoint_event_dequeue_priority_messages"
    );
    assert_eq!(
        event_from_index(Event::EndpointEventDequeueBulkMessages as usize).name(),
        "endpoint_event_dequeue_bulk_messages"
    );
    assert_eq!(
        event_from_index(Event::EndpointEventDequeueMultiMessageEvents as usize).name(),
        "endpoint_event_dequeue_multi_message_events"
    );
    assert_eq!(
        event_from_index(Event::EndpointEventDequeueMixedLaneEvents as usize).name(),
        "endpoint_event_dequeue_mixed_lane_events"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkQueueDepthGe25 as usize).name(),
        "decrypt_worker_bulk_queue_depth_ge25"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkQueueDepthGe50 as usize).name(),
        "decrypt_worker_bulk_queue_depth_ge50"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkQueueDepthGe75 as usize).name(),
        "decrypt_worker_bulk_queue_depth_ge75"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkQueueDepthGe90 as usize).name(),
        "decrypt_worker_bulk_queue_depth_ge90"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkQueueDepthGe64 as usize).name(),
        "decrypt_worker_bulk_queue_depth_ge64"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkQueueDepthGe256 as usize).name(),
        "decrypt_worker_bulk_queue_depth_ge256"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkQueueDepthGe1024 as usize).name(),
        "decrypt_worker_bulk_queue_depth_ge1024"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkQueueDepthGe4096 as usize).name(),
        "decrypt_worker_bulk_queue_depth_ge4096"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerFmpBulkQueueDepthGe64 as usize).name(),
        "decrypt_worker_fmp_bulk_queue_depth_ge64"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerFmpBulkQueueDepthGe4096 as usize).name(),
        "decrypt_worker_fmp_bulk_queue_depth_ge4096"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerFspOwnerQueueDepthGe64 as usize).name(),
        "decrypt_worker_fsp_owner_queue_depth_ge64"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerFspOwnerQueueDepthGe4096 as usize).name(),
        "decrypt_worker_fsp_owner_queue_depth_ge4096"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerFspOpenQueueDepthGe64 as usize).name(),
        "decrypt_worker_fsp_open_queue_depth_ge64"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerFspOpenQueueDepthGe4096 as usize).name(),
        "decrypt_worker_fsp_open_queue_depth_ge4096"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOpenWorkerLocalIneligibleNoShared as usize).name(),
        "decrypt_fsp_open_worker_local_ineligible_no_shared"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOpenWorkerLocalIneligibleKbitMismatch as usize).name(),
        "decrypt_fsp_open_worker_local_ineligible_kbit_mismatch"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOpenWorkerLocalIneligibleWindowFull as usize).name(),
        "decrypt_fsp_open_worker_local_ineligible_window_full"
    );
    assert_eq!(
        event_from_index(Event::RxLoopSlowMaintenanceTimeout as usize).name(),
        "rx_loop_slow_maintenance_timeout"
    );
    assert_eq!(
        event_from_index(Event::RxLoopSlowMaintenanceSkipped as usize).name(),
        "rx_loop_slow_maintenance_skipped"
    );
    assert_eq!(
        event_from_index(Event::DecryptFallbackPressureDrain as usize).name(),
        "decrypt_fallback_pressure_drain"
    );
    assert_eq!(
        event_from_index(Event::DecryptFallbackPriorityGated as usize).name(),
        "decrypt_fallback_priority_gated"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPriorityQueueFullFallback as usize).name(),
        "decrypt_fsp_priority_queue_full_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspBulkQueueFullFallback as usize).name(),
        "decrypt_fsp_bulk_queue_full_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspWorkerReplayDropped as usize).name(),
        "decrypt_fsp_worker_replay_dropped"
    );
    assert_eq!(
        event_from_index(Event::DecryptAuthenticatedSessionPriorityDropped as usize).name(),
        "decrypt_authenticated_session_priority_dropped"
    );
    assert_eq!(
        event_from_index(Event::DecryptAuthenticatedSessionBulkDropped as usize).name(),
        "decrypt_authenticated_session_bulk_dropped"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchFlush as usize).name(),
        "fmp_worker_batch_flush"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchPackets as usize).name(),
        "fmp_worker_batch_packets"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchFull as usize).name(),
        "fmp_worker_batch_full"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchSingle as usize).name(),
        "fmp_worker_batch_single"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchPriorityPackets as usize).name(),
        "fmp_worker_batch_priority_packets"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerBatchBulkPackets as usize).name(),
        "fmp_worker_batch_bulk_packets"
    );
    assert_eq!(
        event_from_index(Event::UdpSendGsoBatch as usize).name(),
        "udp_send_gso_batch"
    );
    assert_eq!(
        event_from_index(Event::UdpSendGsoPackets as usize).name(),
        "udp_send_gso_packets"
    );
    assert_eq!(
        event_from_index(Event::UdpSendSendmmsgBatch as usize).name(),
        "udp_send_sendmmsg_batch"
    );
    assert_eq!(
        event_from_index(Event::UdpSendSendmmsgPackets as usize).name(),
        "udp_send_sendmmsg_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchFlush as usize).name(),
        "decrypt_worker_batch_flush"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchPackets as usize).name(),
        "decrypt_worker_batch_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchFull as usize).name(),
        "decrypt_worker_batch_full"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchSingle as usize).name(),
        "decrypt_worker_batch_single"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchPriorityPackets as usize).name(),
        "decrypt_worker_batch_priority_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchBulkPackets as usize).name(),
        "decrypt_worker_batch_bulk_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchWorker0 as usize).name(),
        "decrypt_worker_batch_worker0"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBatchWorkerOther as usize).name(),
        "decrypt_worker_batch_worker_other"
    );
    assert_eq!(
        event_from_index(Event::UdpSendGsoBatchGe32 as usize).name(),
        "udp_send_gso_batch_ge32"
    );
    assert_eq!(
        event_from_index(Event::UdpSendGsoBatchGe48 as usize).name(),
        "udp_send_gso_batch_ge48"
    );
    assert_eq!(
        event_from_index(Event::UdpSendGsoBatchEq64 as usize).name(),
        "udp_send_gso_batch_eq64"
    );
    assert_eq!(
        event_from_index(Event::UdpSendSendmmsgBatchGe32 as usize).name(),
        "udp_send_sendmmsg_batch_ge32"
    );
    assert_eq!(
        event_from_index(Event::UdpSendSendmmsgBatchGe48 as usize).name(),
        "udp_send_sendmmsg_batch_ge48"
    );
    assert_eq!(
        event_from_index(Event::UdpSendSendmmsgBatchEq64 as usize).name(),
        "udp_send_sendmmsg_batch_eq64"
    );
    assert_eq!(
        event_from_index(Event::FmpSendGroup as usize).name(),
        "fmp_send_group"
    );
    assert_eq!(
        event_from_index(Event::FmpSendGroupPackets as usize).name(),
        "fmp_send_group_packets"
    );
    assert_eq!(
        event_from_index(Event::FmpSendGroupSingle as usize).name(),
        "fmp_send_group_single"
    );
    assert_eq!(
        event_from_index(Event::EncryptWorkerPriorityQueueFull as usize).name(),
        "encrypt_worker_priority_queue_full"
    );
    assert_eq!(
        event_from_index(Event::EncryptWorkerBulkQueueFull as usize).name(),
        "encrypt_worker_bulk_queue_full"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchBatch as usize).name(),
        "fmp_worker_dispatch_batch"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchPackets as usize).name(),
        "fmp_worker_dispatch_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkInputWaitGe250us as usize).name(),
        "decrypt_worker_bulk_input_wait_ge250us"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkInputWaitGe500us as usize).name(),
        "decrypt_worker_bulk_input_wait_ge500us"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkInputWaitGe1ms as usize).name(),
        "decrypt_worker_bulk_input_wait_ge1ms"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOwnerSame as usize).name(),
        "decrypt_fsp_owner_same"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOwnerMismatch as usize).name(),
        "decrypt_fsp_owner_mismatch"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathLocal as usize).name(),
        "decrypt_fsp_path_local"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathHandoff as usize).name(),
        "decrypt_fsp_path_handoff"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathHelper as usize).name(),
        "decrypt_fsp_path_helper"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathFallback as usize).name(),
        "decrypt_fsp_path_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathWorkerOpen as usize).name(),
        "decrypt_fsp_path_worker_open"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathWorkerOpenStriped as usize).name(),
        "decrypt_fsp_path_worker_open_striped"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathLocalPriority as usize).name(),
        "decrypt_fsp_path_local_priority"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathLocalBulk as usize).name(),
        "decrypt_fsp_path_local_bulk"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathHandoffPriority as usize).name(),
        "decrypt_fsp_path_handoff_priority"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathHandoffBulk as usize).name(),
        "decrypt_fsp_path_handoff_bulk"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathHelperBulk as usize).name(),
        "decrypt_fsp_path_helper_bulk"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspPathWorkerOpenBulk as usize).name(),
        "decrypt_fsp_path_worker_open_bulk"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerControlDropped as usize).name(),
        "decrypt_worker_control_dropped"
    );
    assert_eq!(
        event_from_index(Event::ReservedRetiredEvent76 as usize).name(),
        "reserved_retired_event_76"
    );
    assert_eq!(
        event_from_index(Event::ReservedRetiredEvent77 as usize).name(),
        "reserved_retired_event_77"
    );
    assert_eq!(
        event_from_index(Event::DecryptFmpPreownerWindowFallback as usize).name(),
        "decrypt_fmp_preowner_window_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFmpPreownerInlineFallback as usize).name(),
        "decrypt_fmp_preowner_inline_fallback"
    );
    assert_eq!(
        event_from_index(Event::ReservedRetiredEvent143 as usize).name(),
        "reserved_retired_event_143"
    );
    assert_eq!(
        event_from_index(Event::DecryptFmpPreownerCompletionBacklogFallback as usize).name(),
        "decrypt_fmp_preowner_completion_backlog_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOpenWorkerCompletionBacklogFallback as usize).name(),
        "decrypt_fsp_open_worker_completion_backlog_fallback"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchFlowKeyed as usize).name(),
        "fmp_worker_dispatch_flow_keyed"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchTargetOnly as usize).name(),
        "fmp_worker_dispatch_target_only"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchWorker0 as usize).name(),
        "fmp_worker_dispatch_worker0"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchWorker7 as usize).name(),
        "fmp_worker_dispatch_worker7"
    );
    assert_eq!(
        event_from_index(Event::FmpWorkerDispatchWorkerOther as usize).name(),
        "fmp_worker_dispatch_worker_other"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReady as usize).name(),
        "fmp_aead_completion_ready"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionAccepted as usize).name(),
        "fmp_aead_completion_accepted"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionAeadFailed as usize).name(),
        "fmp_aead_completion_aead_failed"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReplayDropped as usize).name(),
        "fmp_aead_completion_replay_dropped"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReplayDroppedPrechecked as usize).name(),
        "fmp_aead_completion_replay_dropped_prechecked"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReplayDroppedDeferred as usize).name(),
        "fmp_aead_completion_replay_dropped_deferred"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReplayDroppedDuplicate as usize).name(),
        "fmp_aead_completion_replay_dropped_duplicate"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReplayDroppedTooOld as usize).name(),
        "fmp_aead_completion_replay_dropped_too_old"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReplayDroppedTooOldLagGe2xWindow as usize).name(),
        "fmp_aead_completion_replay_dropped_too_old_lag_ge_2x_window"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReplayDroppedTooOldLagGe4xWindow as usize).name(),
        "fmp_aead_completion_replay_dropped_too_old_lag_ge_4x_window"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReplayDroppedTooOldLagGe16xWindow as usize).name(),
        "fmp_aead_completion_replay_dropped_too_old_lag_ge_16x_window"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReplayDroppedTooOldLagGe64xWindow as usize).name(),
        "fmp_aead_completion_replay_dropped_too_old_lag_ge_64x_window"
    );
    assert_eq!(
        event_from_index(Event::FmpAeadCompletionReadyMulti as usize).name(),
        "fmp_aead_completion_ready_multi"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReady as usize).name(),
        "fsp_aead_completion_ready"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAccepted as usize).name(),
        "fsp_aead_completion_accepted"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAeadFailed as usize).name(),
        "fsp_aead_completion_aead_failed"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAeadFailedLocal as usize).name(),
        "fsp_aead_completion_aead_failed_local"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAeadFailedHelper as usize).name(),
        "fsp_aead_completion_aead_failed_helper"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAeadFailedHelperReturned as usize).name(),
        "fsp_aead_completion_aead_failed_helper_returned"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAeadFailedWorkerOpen as usize).name(),
        "fsp_aead_completion_aead_failed_worker_open"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAeadFailedWorkerOpenReturned as usize).name(),
        "fsp_aead_completion_aead_failed_worker_open_returned"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionEpochMismatch as usize).name(),
        "fsp_aead_completion_epoch_mismatch"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAeadFailedLocalOpen as usize).name(),
        "fsp_aead_completion_aead_failed_local_open"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionAeadFailedAcceptKbitMismatch as usize).name(),
        "fsp_aead_completion_aead_failed_accept_kbit_mismatch"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionStaleEpochWorkerOpen as usize).name(),
        "fsp_aead_completion_stale_epoch_worker_open"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDropped as usize).name(),
        "fsp_aead_completion_replay_dropped"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDroppedHelper as usize).name(),
        "fsp_aead_completion_replay_dropped_helper"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDroppedHelperReturned as usize).name(),
        "fsp_aead_completion_replay_dropped_helper_returned"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDroppedWorkerOpen as usize).name(),
        "fsp_aead_completion_replay_dropped_worker_open"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDroppedWorkerOpenReturned as usize).name(),
        "fsp_aead_completion_replay_dropped_worker_open_returned"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDroppedDuplicate as usize).name(),
        "fsp_aead_completion_replay_dropped_duplicate"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDroppedTooOld as usize).name(),
        "fsp_aead_completion_replay_dropped_too_old"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDroppedTooOldLagGe2xWindow as usize).name(),
        "fsp_aead_completion_replay_dropped_too_old_lag_ge_2x_window"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDroppedTooOldLagGe4xWindow as usize).name(),
        "fsp_aead_completion_replay_dropped_too_old_lag_ge_4x_window"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDroppedTooOldLagGe16xWindow as usize).name(),
        "fsp_aead_completion_replay_dropped_too_old_lag_ge_16x_window"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReplayDroppedTooOldLagGe64xWindow as usize).name(),
        "fsp_aead_completion_replay_dropped_too_old_lag_ge_64x_window"
    );
    assert_eq!(
        event_from_index(Event::ConnectedUdpDirectDecryptBulkShed as usize).name(),
        "connected_udp_direct_decrypt_bulk_shed"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOpenWorkerReturnedDropped as usize).name(),
        "decrypt_fsp_open_worker_returned_dropped"
    );
    assert_eq!(
        event_from_index(Event::ConnectedUdpKernelDropped as usize).name(),
        "connected_udp_kernel_dropped"
    );
    assert_eq!(
        event_from_index(Event::ConnectedUdpPeerKernelDropped as usize).name(),
        "connected_udp_peer_kernel_dropped"
    );
    assert_eq!(
        event_from_index(Event::UdpKernelDropped as usize).name(),
        "udp_kernel_dropped"
    );
    assert_eq!(
        event_from_index(Event::UdpSocketKernelDropped as usize).name(),
        "udp_socket_kernel_dropped"
    );
    assert_eq!(
        event_from_index(Event::UdpNamespaceRcvbufErrors as usize).name(),
        "udp_namespace_rcvbuf_errors"
    );
    assert_eq!(
        event_from_index(Event::ConnectedUdpDrainBulkDropped as usize).name(),
        "connected_udp_drain_bulk_dropped"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspWorkerReplayDroppedDuplicate as usize).name(),
        "decrypt_fsp_worker_replay_dropped_duplicate"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspWorkerReplayDroppedTooOld as usize).name(),
        "decrypt_fsp_worker_replay_dropped_too_old"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspWorkerReplayDroppedTooOldLagGe2xWindow as usize).name(),
        "decrypt_fsp_worker_replay_dropped_too_old_lag_ge_2x_window"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspWorkerReplayDroppedTooOldLagGe4xWindow as usize).name(),
        "decrypt_fsp_worker_replay_dropped_too_old_lag_ge_4x_window"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspWorkerReplayDroppedTooOldLagGe16xWindow as usize).name(),
        "decrypt_fsp_worker_replay_dropped_too_old_lag_ge_16x_window"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspWorkerReplayDroppedTooOldLagGe64xWindow as usize).name(),
        "decrypt_fsp_worker_replay_dropped_too_old_lag_ge_64x_window"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReadyMulti as usize).name(),
        "fsp_aead_completion_ready_multi"
    );
    assert_eq!(
        event_from_index(Event::EndpointBulkFastPathPrepareFailed as usize).name(),
        "endpoint_bulk_fast_path_prepare_failed"
    );
    assert_eq!(
        event_from_index(Event::EndpointBulkFastPathStageFull as usize).name(),
        "endpoint_bulk_fast_path_stage_full"
    );
    assert_eq!(
        event_from_index(Event::EndpointBulkFastPathFeedbackFull as usize).name(),
        "endpoint_bulk_fast_path_feedback_full"
    );
    assert_eq!(
        event_from_index(Event::EndpointBulkFastPathAttempt as usize).name(),
        "endpoint_bulk_fast_path_attempt"
    );
    assert_eq!(
        event_from_index(Event::EndpointBulkFastPathDispatched as usize).name(),
        "endpoint_bulk_fast_path_dispatched"
    );
    assert_eq!(
        event_from_index(Event::EndpointBulkFastPathLeaseMiss as usize).name(),
        "endpoint_bulk_fast_path_lease_miss"
    );
    assert_eq!(
        event_from_index(Event::EndpointBulkFastPathIneligible as usize).name(),
        "endpoint_bulk_fast_path_ineligible"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchChunk as usize).name(),
        "linux_wg_batch_chunk"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchChunkPackets as usize).name(),
        "linux_wg_batch_chunk_packets"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchChunkFull as usize).name(),
        "linux_wg_batch_chunk_full"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchSenderWaitGe250us as usize).name(),
        "linux_wg_batch_sender_wait_ge250us"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchSenderWaitGe1ms as usize).name(),
        "linux_wg_batch_sender_wait_ge1ms"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchSenderWaitGe4ms as usize).name(),
        "linux_wg_batch_sender_wait_ge4ms"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchAdmissionBatch as usize).name(),
        "linux_wg_batch_admission_batch"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchAdmissionPackets as usize).name(),
        "linux_wg_batch_admission_packets"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchAdmissionTooSmallPackets as usize).name(),
        "linux_wg_batch_admission_too_small_packets"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchAdmissionUnavailablePackets as usize).name(),
        "linux_wg_batch_admission_unavailable_packets"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchAdmissionNoTargetPackets as usize).name(),
        "linux_wg_batch_admission_no_target_packets"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchAdmissionFallbackPackets as usize).name(),
        "linux_wg_batch_admission_fallback_packets"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchFlowQueueFullPackets as usize).name(),
        "linux_wg_batch_flow_queue_full_packets"
    );
    assert_eq!(
        event_from_index(Event::LinuxWgBatchWorkerQueueFullPackets as usize).name(),
        "linux_wg_batch_worker_queue_full_packets"
    );
    assert_eq!(
        event_from_index(Event::FmpSendGroupSplitTarget as usize).name(),
        "fmp_send_group_split_target"
    );
    assert_eq!(
        event_from_index(Event::FmpSendGroupSplitLane as usize).name(),
        "fmp_send_group_split_lane"
    );
    assert_eq!(
        event_from_index(Event::FmpSendGroupSplitBackpressure as usize).name(),
        "fmp_send_group_split_backpressure"
    );
    assert_eq!(
        event_from_index(Event::FmpSendGroupSplitPacketCap as usize).name(),
        "fmp_send_group_split_packet_cap"
    );
    assert_eq!(
        event_from_index(Event::EndpointCommittedBulkDispatchBatch as usize).name(),
        "endpoint_committed_bulk_dispatch_batch"
    );
    assert_eq!(
        event_from_index(Event::EndpointCommittedBulkDispatchPackets as usize).name(),
        "endpoint_committed_bulk_dispatch_packets"
    );
    assert_eq!(
        event_from_index(Event::EndpointCommittedBulkDispatchMergedBatch as usize).name(),
        "endpoint_committed_bulk_dispatch_merged_batch"
    );
    assert_eq!(
        event_from_index(Event::EndpointCommittedBulkDispatchMergedPackets as usize).name(),
        "endpoint_committed_bulk_dispatch_merged_packets"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionStaleSession as usize).name(),
        "fsp_aead_completion_stale_session"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionStaleOrder as usize).name(),
        "fsp_aead_completion_stale_order"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionStaleTicket as usize).name(),
        "fsp_aead_completion_stale_ticket"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionDuplicateTicket as usize).name(),
        "fsp_aead_completion_duplicate_ticket"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionWindowExceeded as usize).name(),
        "fsp_aead_completion_window_exceeded"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOpenWorkerWindowFallback as usize).name(),
        "decrypt_fsp_open_worker_window_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerSelectPriority as usize).name(),
        "decrypt_worker_select_priority"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerSelectControl as usize).name(),
        "decrypt_worker_select_control"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerSelectFmpCompletion as usize).name(),
        "decrypt_worker_select_fmp_completion"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerSelectFspCompletionPackets as usize).name(),
        "decrypt_worker_select_fsp_completion_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerSelectFspCompletionBatch as usize).name(),
        "decrypt_worker_select_fsp_completion_batch"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerSelectBulkPackets as usize).name(),
        "decrypt_worker_select_bulk_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerDrainPriority as usize).name(),
        "decrypt_worker_drain_priority"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerDrainControl as usize).name(),
        "decrypt_worker_drain_control"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerDrainAeadCompletionPackets as usize).name(),
        "decrypt_worker_drain_aead_completion_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerDrainAeadCompletionBatch as usize).name(),
        "decrypt_worker_drain_aead_completion_batch"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerDrainBulkPackets as usize).name(),
        "decrypt_worker_drain_bulk_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkInterleaveAeadCompletionPackets as usize).name(),
        "decrypt_worker_bulk_interleave_aead_completion_packets"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkInterleaveAeadCompletionBatch as usize).name(),
        "decrypt_worker_bulk_interleave_aead_completion_batch"
    );
    assert_eq!(
        event_from_index(Event::DecryptWorkerBulkInterleaveBudgetExhausted as usize).name(),
        "decrypt_worker_bulk_interleave_budget_exhausted"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspHelperCompletionBacklogFallback as usize).name(),
        "decrypt_fsp_helper_completion_backlog_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspHelperQueueFullFallback as usize).name(),
        "decrypt_fsp_helper_queue_full_fallback"
    );
    assert_eq!(
        event_from_index(Event::ReservedRetiredEvent143 as usize).name(),
        "reserved_retired_event_143"
    );
    assert_eq!(
        event_from_index(Event::DecryptFmpPreownerCompletionBacklogFallback as usize).name(),
        "decrypt_fmp_preowner_completion_backlog_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOpenWorkerCompletionBacklogFallback as usize).name(),
        "decrypt_fsp_open_worker_completion_backlog_fallback"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOpenWorkerReturnedDropped as usize).name(),
        "decrypt_fsp_open_worker_returned_dropped"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReturnedHelper as usize).name(),
        "fsp_aead_completion_returned_helper"
    );
    assert_eq!(
        event_from_index(Event::FspAeadCompletionReturnedWorkerOpen as usize).name(),
        "fsp_aead_completion_returned_worker_open"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspOwnerHandoffDropped as usize).name(),
        "decrypt_fsp_owner_handoff_dropped"
    );
    assert_eq!(
        event_from_index(Event::DecryptFspMalformedDropped as usize).name(),
        "decrypt_fsp_malformed_dropped"
    );
    assert_eq!(
        event_from_index(Event::PacketBatchPoolFresh as usize).name(),
        "packet_batch_pool_fresh"
    );
    assert_eq!(
        event_from_index(Event::PacketBatchPoolReuse as usize).name(),
        "packet_batch_pool_reuse"
    );
    assert_eq!(
        event_from_index(Event::PacketBatchPoolReturn as usize).name(),
        "packet_batch_pool_return"
    );
    assert_eq!(
        event_from_index(Event::PacketBatchPoolDiscard as usize).name(),
        "packet_batch_pool_discard"
    );
    assert_eq!(
        event_from_index(Event::PacketBufferPoolFresh as usize).name(),
        "packet_buffer_pool_fresh"
    );
    assert_eq!(
        event_from_index(Event::PacketBufferPoolReuse as usize).name(),
        "packet_buffer_pool_reuse"
    );
    assert_eq!(
        event_from_index(Event::PacketBufferPoolReturn as usize).name(),
        "packet_buffer_pool_return"
    );
    assert_eq!(
        event_from_index(Event::PacketBufferPoolDiscard as usize).name(),
        "packet_buffer_pool_discard"
    );
    assert_eq!(
        event_from_index(Event::LinuxBulkUdpPaceWait as usize).name(),
        "linux_bulk_udp_pace_wait"
    );
}

#[test]
fn bulk_queue_depth_thresholds_are_cumulative() {
    assert_eq!(
        bulk_queue_depth_threshold_flags(0, 100),
        (false, false, false, false)
    );
    assert_eq!(
        bulk_queue_depth_threshold_flags(25, 100),
        (true, false, false, false)
    );
    assert_eq!(
        bulk_queue_depth_threshold_flags(50, 100),
        (true, true, false, false)
    );
    assert_eq!(
        bulk_queue_depth_threshold_flags(75, 100),
        (true, true, true, false)
    );
    assert_eq!(
        bulk_queue_depth_threshold_flags(90, 100),
        (true, true, true, true)
    );
    assert_eq!(
        bulk_queue_depth_threshold_flags(150, 100),
        (true, true, true, true)
    );
    assert_eq!(
        bulk_queue_depth_threshold_flags(10, 0),
        (false, false, false, false)
    );
}

#[test]
fn bulk_queue_depth_absolute_thresholds_are_cumulative() {
    assert_eq!(
        bulk_queue_depth_absolute_flags(0),
        (false, false, false, false)
    );
    assert_eq!(
        bulk_queue_depth_absolute_flags(64),
        (true, false, false, false)
    );
    assert_eq!(
        bulk_queue_depth_absolute_flags(256),
        (true, true, false, false)
    );
    assert_eq!(
        bulk_queue_depth_absolute_flags(1024),
        (true, true, true, false)
    );
    assert_eq!(
        bulk_queue_depth_absolute_flags(4096),
        (true, true, true, true)
    );
    assert_eq!(
        bulk_queue_depth_absolute_flags(8192),
        (true, true, true, true)
    );
}

#[test]
fn event_counter_mode_keeps_failures_without_batch_shape_counters() {
    assert!(Event::TransportBulkDropped.recorded_by_event_counter_mode());
    assert!(Event::TransportChannelBacklogHigh.recorded_by_event_counter_mode());
    assert!(Event::RxLoopSlowMaintenanceSkipped.recorded_by_event_counter_mode());
    assert!(Event::FspAeadCompletionAeadFailed.recorded_by_event_counter_mode());
    assert!(Event::FspAeadCompletionEpochMismatch.recorded_by_event_counter_mode());
    assert!(Event::FspAeadCompletionStaleEpochWorkerOpen.recorded_by_event_counter_mode());
    assert!(Event::UdpKernelDropped.recorded_by_event_counter_mode());

    assert!(!Event::FmpWorkerBatchPackets.recorded_by_event_counter_mode());
    assert!(!Event::UdpSendGsoPackets.recorded_by_event_counter_mode());
    assert!(!Event::DecryptWorkerBatchPackets.recorded_by_event_counter_mode());
    assert!(!Event::PacketBatchPoolReuse.recorded_by_event_counter_mode());
    assert!(!Event::LinuxWgBatchAdmissionPackets.recorded_by_event_counter_mode());
    assert!(!Event::DecryptWorkerBulkQueueDepthGe90.recorded_by_event_counter_mode());
    assert!(!Event::DecryptWorkerBulkQueueDepthGe64.recorded_by_event_counter_mode());
    assert!(!Event::DecryptWorkerBulkQueueDepthGe4096.recorded_by_event_counter_mode());
    assert!(!Event::DecryptWorkerFmpBulkQueueDepthGe64.recorded_by_event_counter_mode());
    assert!(!Event::DecryptWorkerFspOwnerQueueDepthGe64.recorded_by_event_counter_mode());
    assert!(!Event::DecryptWorkerFspOpenQueueDepthGe64.recorded_by_event_counter_mode());
    assert!(!Event::DecryptFspOpenWorkerLocalIneligibleNoShared.recorded_by_event_counter_mode());
    assert!(
        !Event::DecryptFspOpenWorkerLocalIneligibleKbitMismatch.recorded_by_event_counter_mode()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn udp_send_batch_buckets_classify_large_bursts() {
    assert_eq!(udp_send_batch_tail_bucket_flags(0), (false, false, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(31), (false, false, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(32), (true, false, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(47), (true, false, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(48), (true, true, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(63), (true, true, false));
    assert_eq!(udp_send_batch_tail_bucket_flags(64), (true, true, true));
}

#[test]
fn stage_table_exposes_endpoint_command_lane_waits() {
    assert_eq!(N_STAGES, 74);
    assert_eq!(
        stage_from_index(Stage::EndpointCommandWait as usize).name(),
        "endpoint_command_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointPriorityCommandWait as usize).name(),
        "endpoint_priority_command_wait"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointBulkCommandWait as usize).name(),
        "endpoint_bulk_command_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptAuthenticatedSessionWait as usize).name(),
        "decrypt_authenticated_session_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptAuthenticatedSessionPriorityWait as usize).name(),
        "decrypt_authenticated_session_priority_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptAuthenticatedSessionBulkWait as usize).name(),
        "decrypt_authenticated_session_bulk_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptAuthenticatedFmpReceiveWait as usize).name(),
        "decrypt_authenticated_fmp_receive_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerQueueWait as usize).name(),
        "decrypt_fsp_worker_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerPriorityQueueWait as usize).name(),
        "decrypt_fsp_worker_priority_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerBulkQueueWait as usize).name(),
        "decrypt_fsp_worker_bulk_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerPriorityQueueWait as usize).name(),
        "fmp_worker_priority_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerBulkQueueWait as usize).name(),
        "fmp_worker_bulk_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerService as usize).name(),
        "decrypt_fsp_worker_service"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerBulkInputHeadWait as usize).name(),
        "decrypt_fsp_worker_bulk_input_head_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptFspWorkerBulkInputTailWait as usize).name(),
        "decrypt_fsp_worker_bulk_input_tail_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FspAeadHelperQueueWait as usize).name(),
        "fsp_aead_helper_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FspAeadHelperCompletionWait as usize).name(),
        "fsp_aead_helper_completion_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerFspSeal as usize).name(),
        "fmp_worker_fsp_seal"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerFmpSeal as usize).name(),
        "fmp_worker_fmp_seal"
    );
    assert_eq!(
        stage_from_index(Stage::FmpWorkerDispatch as usize).name(),
        "fmp_worker_dispatch"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptWorkerBulkInputHeadWait as usize).name(),
        "decrypt_worker_bulk_input_head_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptWorkerBulkInputTailWait as usize).name(),
        "decrypt_worker_bulk_input_tail_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptWorkerBulkItemService as usize).name(),
        "decrypt_worker_bulk_item_service"
    );
    assert_eq!(
        stage_from_index(Stage::ReservedRetiredStage53 as usize).name(),
        "reserved_retired_stage_53"
    );
    assert_eq!(
        stage_from_index(Stage::ReservedRetiredStage54 as usize).name(),
        "reserved_retired_stage_54"
    );
    assert_eq!(
        stage_from_index(Stage::ReservedRetiredStage55 as usize).name(),
        "reserved_retired_stage_55"
    );
    assert_eq!(
        stage_from_index(Stage::ReservedRetiredStage56 as usize).name(),
        "reserved_retired_stage_56"
    );
    assert_eq!(
        stage_from_index(Stage::ReservedRetiredStage57 as usize).name(),
        "reserved_retired_stage_57"
    );
    assert_eq!(
        stage_from_index(Stage::ReservedRetiredStage58 as usize).name(),
        "reserved_retired_stage_58"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptWorkerOutputFlush as usize).name(),
        "decrypt_worker_output_flush"
    );
    assert_eq!(
        stage_from_index(Stage::FspAeadCompletionService as usize).name(),
        "fsp_aead_completion_service"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointSendPrepare as usize).name(),
        "endpoint_send_prepare"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointSendPlan as usize).name(),
        "endpoint_send_plan"
    );
    assert_eq!(
        stage_from_index(Stage::EndpointSendCommit as usize).name(),
        "endpoint_send_commit"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptAuthenticatedFmpReceiveWait as usize).name(),
        "decrypt_authenticated_fmp_receive_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FspAeadWorkerOpenQueueWait as usize).name(),
        "fsp_aead_worker_open_queue_wait"
    );
    assert_eq!(
        stage_from_index(Stage::FspAeadWorkerOpenCompletionWait as usize).name(),
        "fsp_aead_worker_open_completion_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptDirectSessionCommitWait as usize).name(),
        "decrypt_direct_session_commit_wait"
    );
    assert_eq!(
        stage_from_index(Stage::DecryptDirectSessionDataWait as usize).name(),
        "decrypt_direct_session_data_wait"
    );
    assert_eq!(
        stage_from_index(Stage::ConnectedUdpDrainRecv as usize).name(),
        "connected_udp_drain_recv"
    );
    assert_eq!(
        stage_from_index(Stage::ConnectedUdpFastPathDispatch as usize).name(),
        "connected_udp_fast_path_dispatch"
    );
    assert_eq!(
        stage_from_index(Stage::ConnectedUdpDrainRingWait as usize).name(),
        "connected_udp_drain_ring_wait"
    );
    assert_eq!(
        stage_from_index(Stage::ConnectedUdpDrainPriorityRingWait as usize).name(),
        "connected_udp_drain_priority_ring_wait"
    );
    assert_eq!(
        stage_from_index(Stage::ConnectedUdpDrainBulkRingWait as usize).name(),
        "connected_udp_drain_bulk_ring_wait"
    );
}

#[test]
fn rx_loop_liveness_and_fallback_pressure_events_increment_counters() {
    let timeout_before = EVENTS[Event::RxLoopSlowMaintenanceTimeout as usize].load(Relaxed);
    let skipped_before = EVENTS[Event::RxLoopSlowMaintenanceSkipped as usize].load(Relaxed);
    let pressure_before = EVENTS[Event::DecryptFallbackPressureDrain as usize].load(Relaxed);
    let gated_before = EVENTS[Event::DecryptFallbackPriorityGated as usize].load(Relaxed);
    let auth_priority_before =
        EVENTS[Event::DecryptAuthenticatedSessionPriorityDropped as usize].load(Relaxed);
    let auth_bulk_before =
        EVENTS[Event::DecryptAuthenticatedSessionBulkDropped as usize].load(Relaxed);
    let encrypt_queue_full_before = EVENTS[Event::EncryptWorkerQueueFull as usize].load(Relaxed);
    let encrypt_priority_full_before =
        EVENTS[Event::EncryptWorkerPriorityQueueFull as usize].load(Relaxed);
    let encrypt_bulk_full_before = EVENTS[Event::EncryptWorkerBulkQueueFull as usize].load(Relaxed);
    let batch_flush_before = EVENTS[Event::FmpWorkerBatchFlush as usize].load(Relaxed);
    let batch_packets_before = EVENTS[Event::FmpWorkerBatchPackets as usize].load(Relaxed);
    let batch_full_before = EVENTS[Event::FmpWorkerBatchFull as usize].load(Relaxed);
    let batch_single_before = EVENTS[Event::FmpWorkerBatchSingle as usize].load(Relaxed);
    let batch_priority_before = EVENTS[Event::FmpWorkerBatchPriorityPackets as usize].load(Relaxed);
    let batch_bulk_before = EVENTS[Event::FmpWorkerBatchBulkPackets as usize].load(Relaxed);
    let gso_batch_before = EVENTS[Event::UdpSendGsoBatch as usize].load(Relaxed);
    let gso_packets_before = EVENTS[Event::UdpSendGsoPackets as usize].load(Relaxed);
    let sendmmsg_batch_before = EVENTS[Event::UdpSendSendmmsgBatch as usize].load(Relaxed);
    let sendmmsg_packets_before = EVENTS[Event::UdpSendSendmmsgPackets as usize].load(Relaxed);
    let decrypt_batch_flush_before = EVENTS[Event::DecryptWorkerBatchFlush as usize].load(Relaxed);
    let decrypt_batch_packets_before =
        EVENTS[Event::DecryptWorkerBatchPackets as usize].load(Relaxed);
    let decrypt_batch_full_before = EVENTS[Event::DecryptWorkerBatchFull as usize].load(Relaxed);
    let decrypt_batch_single_before =
        EVENTS[Event::DecryptWorkerBatchSingle as usize].load(Relaxed);
    let decrypt_batch_priority_before =
        EVENTS[Event::DecryptWorkerBatchPriorityPackets as usize].load(Relaxed);
    let decrypt_batch_bulk_before =
        EVENTS[Event::DecryptWorkerBatchBulkPackets as usize].load(Relaxed);
    let dispatch_batch_before = EVENTS[Event::FmpWorkerDispatchBatch as usize].load(Relaxed);
    let dispatch_packets_before = EVENTS[Event::FmpWorkerDispatchPackets as usize].load(Relaxed);
    let decrypt_input_wait_ge250_before =
        EVENTS[Event::DecryptWorkerBulkInputWaitGe250us as usize].load(Relaxed);
    let decrypt_input_wait_ge500_before =
        EVENTS[Event::DecryptWorkerBulkInputWaitGe500us as usize].load(Relaxed);
    let decrypt_input_wait_ge1ms_before =
        EVENTS[Event::DecryptWorkerBulkInputWaitGe1ms as usize].load(Relaxed);
    let fsp_owner_same_before = EVENTS[Event::DecryptFspOwnerSame as usize].load(Relaxed);
    let fsp_owner_mismatch_before = EVENTS[Event::DecryptFspOwnerMismatch as usize].load(Relaxed);
    let fsp_path_local_before = EVENTS[Event::DecryptFspPathLocal as usize].load(Relaxed);
    let fsp_path_handoff_before = EVENTS[Event::DecryptFspPathHandoff as usize].load(Relaxed);
    let fsp_path_helper_before = EVENTS[Event::DecryptFspPathHelper as usize].load(Relaxed);
    let fsp_path_fallback_before = EVENTS[Event::DecryptFspPathFallback as usize].load(Relaxed);
    let fsp_owner_handoff_dropped_before =
        EVENTS[Event::DecryptFspOwnerHandoffDropped as usize].load(Relaxed);
    let fsp_path_worker_open_before =
        EVENTS[Event::DecryptFspPathWorkerOpen as usize].load(Relaxed);
    let fmp_preowner_window_fallback_before =
        EVENTS[Event::DecryptFmpPreownerWindowFallback as usize].load(Relaxed);
    let fmp_preowner_inline_fallback_before =
        EVENTS[Event::DecryptFmpPreownerInlineFallback as usize].load(Relaxed);
    let fmp_preowner_completion_backlog_fallback_before =
        EVENTS[Event::DecryptFmpPreownerCompletionBacklogFallback as usize].load(Relaxed);
    let fsp_open_worker_completion_backlog_fallback_before =
        EVENTS[Event::DecryptFspOpenWorkerCompletionBacklogFallback as usize].load(Relaxed);
    let fsp_open_worker_returned_dropped_before =
        EVENTS[Event::DecryptFspOpenWorkerReturnedDropped as usize].load(Relaxed);
    let fsp_path_worker_open_striped_before =
        EVENTS[Event::DecryptFspPathWorkerOpenStriped as usize].load(Relaxed);
    let dispatch_flow_keyed_before =
        EVENTS[Event::FmpWorkerDispatchFlowKeyed as usize].load(Relaxed);
    let dispatch_target_only_before =
        EVENTS[Event::FmpWorkerDispatchTargetOnly as usize].load(Relaxed);
    let dispatch_worker0_before = EVENTS[Event::FmpWorkerDispatchWorker0 as usize].load(Relaxed);
    let dispatch_worker7_before = EVENTS[Event::FmpWorkerDispatchWorker7 as usize].load(Relaxed);
    let dispatch_worker_other_before =
        EVENTS[Event::FmpWorkerDispatchWorkerOther as usize].load(Relaxed);
    let endpoint_bulk_prepare_failed_before =
        EVENTS[Event::EndpointBulkFastPathPrepareFailed as usize].load(Relaxed);
    let endpoint_bulk_stage_full_before =
        EVENTS[Event::EndpointBulkFastPathStageFull as usize].load(Relaxed);
    let endpoint_bulk_feedback_full_before =
        EVENTS[Event::EndpointBulkFastPathFeedbackFull as usize].load(Relaxed);
    record_event_count_sample(Event::RxLoopSlowMaintenanceTimeout, 3);
    record_event_count_sample(Event::RxLoopSlowMaintenanceSkipped, 5);
    record_event_count_sample(Event::DecryptFallbackPressureDrain, 7);
    record_event_count_sample(Event::DecryptFallbackPriorityGated, 11);
    record_event_count_sample(Event::DecryptAuthenticatedSessionPriorityDropped, 13);
    record_event_count_sample(Event::DecryptAuthenticatedSessionBulkDropped, 17);
    record_event_count_sample(Event::EncryptWorkerQueueFull, 3);
    record_event_count_sample(Event::EncryptWorkerPriorityQueueFull, 1);
    record_event_count_sample(Event::EncryptWorkerBulkQueueFull, 2);
    record_event_count_sample(Event::FmpWorkerBatchFlush, 19);
    record_event_count_sample(Event::FmpWorkerBatchPackets, 23);
    record_event_count_sample(Event::FmpWorkerBatchFull, 29);
    record_event_count_sample(Event::FmpWorkerBatchSingle, 31);
    record_event_count_sample(Event::FmpWorkerBatchPriorityPackets, 37);
    record_event_count_sample(Event::FmpWorkerBatchBulkPackets, 41);
    record_event_count_sample(Event::UdpSendGsoBatch, 43);
    record_event_count_sample(Event::UdpSendGsoPackets, 47);
    record_event_count_sample(Event::UdpSendSendmmsgBatch, 53);
    record_event_count_sample(Event::UdpSendSendmmsgPackets, 59);
    record_event_count_sample(Event::DecryptWorkerBatchFlush, 2);
    record_event_count_sample(Event::DecryptWorkerBatchPackets, 65);
    record_event_count_sample(Event::DecryptWorkerBatchFull, 1);
    record_event_count_sample(Event::DecryptWorkerBatchSingle, 1);
    record_event_count_sample(Event::DecryptWorkerBatchPriorityPackets, 3);
    record_event_count_sample(Event::DecryptWorkerBatchBulkPackets, 62);
    record_event_count_sample(Event::FmpWorkerDispatchBatch, 5);
    record_event_count_sample(Event::FmpWorkerDispatchPackets, 320);
    record_event_count_sample(Event::DecryptWorkerBulkInputWaitGe250us, 3);
    record_event_count_sample(Event::DecryptWorkerBulkInputWaitGe500us, 2);
    record_event_count_sample(Event::DecryptWorkerBulkInputWaitGe1ms, 1);
    record_event_count_sample(Event::DecryptFspOwnerSame, 71);
    record_event_count_sample(Event::DecryptFspOwnerMismatch, 73);
    record_event_count_sample(Event::DecryptFspPathLocal, 79);
    record_event_count_sample(Event::DecryptFspPathHandoff, 83);
    record_event_count_sample(Event::DecryptFspPathHelper, 89);
    record_event_count_sample(Event::DecryptFspPathFallback, 97);
    record_event_count_sample(Event::DecryptFspOwnerHandoffDropped, 98);
    record_event_count_sample(Event::DecryptFspPathWorkerOpen, 99);
    record_event_count_sample(Event::DecryptFmpPreownerWindowFallback, 107);
    record_event_count_sample(Event::DecryptFmpPreownerInlineFallback, 109);
    record_event_count_sample(Event::DecryptFmpPreownerCompletionBacklogFallback, 112);
    record_event_count_sample(Event::DecryptFspOpenWorkerCompletionBacklogFallback, 116);
    record_event_count_sample(Event::DecryptFspOpenWorkerReturnedDropped, 117);
    record_event_count_sample(Event::DecryptFspPathWorkerOpenStriped, 118);
    record_event_count_sample(Event::FmpWorkerDispatchFlowKeyed, 113);
    record_event_count_sample(Event::FmpWorkerDispatchTargetOnly, 127);
    record_event_count_sample(Event::FmpWorkerDispatchWorker0, 131);
    record_event_count_sample(Event::FmpWorkerDispatchWorker7, 137);
    record_event_count_sample(Event::FmpWorkerDispatchWorkerOther, 139);
    record_event_count_sample(Event::EndpointBulkFastPathPrepareFailed, 149);
    record_event_count_sample(Event::EndpointBulkFastPathStageFull, 151);
    record_event_count_sample(Event::EndpointBulkFastPathFeedbackFull, 157);
    assert_eq!(
        EVENTS[Event::RxLoopSlowMaintenanceTimeout as usize].load(Relaxed) - timeout_before,
        3
    );
    assert_eq!(
        EVENTS[Event::RxLoopSlowMaintenanceSkipped as usize].load(Relaxed) - skipped_before,
        5
    );
    assert_eq!(
        EVENTS[Event::DecryptFallbackPressureDrain as usize].load(Relaxed) - pressure_before,
        7
    );
    assert_eq!(
        EVENTS[Event::DecryptFallbackPriorityGated as usize].load(Relaxed) - gated_before,
        11
    );
    assert_eq!(
        EVENTS[Event::DecryptAuthenticatedSessionPriorityDropped as usize].load(Relaxed)
            - auth_priority_before,
        13
    );
    assert_eq!(
        EVENTS[Event::DecryptAuthenticatedSessionBulkDropped as usize].load(Relaxed)
            - auth_bulk_before,
        17
    );
    assert_eq!(
        EVENTS[Event::EncryptWorkerQueueFull as usize].load(Relaxed) - encrypt_queue_full_before,
        3
    );
    assert_eq!(
        EVENTS[Event::EncryptWorkerPriorityQueueFull as usize].load(Relaxed)
            - encrypt_priority_full_before,
        1
    );
    assert_eq!(
        EVENTS[Event::EncryptWorkerBulkQueueFull as usize].load(Relaxed) - encrypt_bulk_full_before,
        2
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchFlush as usize].load(Relaxed) - batch_flush_before,
        19
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchPackets as usize].load(Relaxed) - batch_packets_before,
        23
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchFull as usize].load(Relaxed) - batch_full_before,
        29
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchSingle as usize].load(Relaxed) - batch_single_before,
        31
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchPriorityPackets as usize].load(Relaxed) - batch_priority_before,
        37
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerBatchBulkPackets as usize].load(Relaxed) - batch_bulk_before,
        41
    );
    assert_eq!(
        EVENTS[Event::UdpSendGsoBatch as usize].load(Relaxed) - gso_batch_before,
        43
    );
    assert_eq!(
        EVENTS[Event::UdpSendGsoPackets as usize].load(Relaxed) - gso_packets_before,
        47
    );
    assert_eq!(
        EVENTS[Event::UdpSendSendmmsgBatch as usize].load(Relaxed) - sendmmsg_batch_before,
        53
    );
    assert_eq!(
        EVENTS[Event::UdpSendSendmmsgPackets as usize].load(Relaxed) - sendmmsg_packets_before,
        59
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchFlush as usize].load(Relaxed) - decrypt_batch_flush_before,
        2
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchPackets as usize].load(Relaxed)
            - decrypt_batch_packets_before,
        65
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchFull as usize].load(Relaxed) - decrypt_batch_full_before,
        1
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchSingle as usize].load(Relaxed)
            - decrypt_batch_single_before,
        1
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchPriorityPackets as usize].load(Relaxed)
            - decrypt_batch_priority_before,
        3
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBatchBulkPackets as usize].load(Relaxed)
            - decrypt_batch_bulk_before,
        62
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchBatch as usize].load(Relaxed) - dispatch_batch_before,
        5
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchPackets as usize].load(Relaxed) - dispatch_packets_before,
        320
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBulkInputWaitGe250us as usize].load(Relaxed)
            - decrypt_input_wait_ge250_before,
        3
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBulkInputWaitGe500us as usize].load(Relaxed)
            - decrypt_input_wait_ge500_before,
        2
    );
    assert_eq!(
        EVENTS[Event::DecryptWorkerBulkInputWaitGe1ms as usize].load(Relaxed)
            - decrypt_input_wait_ge1ms_before,
        1
    );
    assert_eq!(
        EVENTS[Event::DecryptFspOwnerSame as usize].load(Relaxed) - fsp_owner_same_before,
        71
    );
    assert_eq!(
        EVENTS[Event::DecryptFspOwnerMismatch as usize].load(Relaxed) - fsp_owner_mismatch_before,
        73
    );
    assert_eq!(
        EVENTS[Event::DecryptFspPathLocal as usize].load(Relaxed) - fsp_path_local_before,
        79
    );
    assert_eq!(
        EVENTS[Event::DecryptFspPathHandoff as usize].load(Relaxed) - fsp_path_handoff_before,
        83
    );
    assert_eq!(
        EVENTS[Event::DecryptFspPathHelper as usize].load(Relaxed) - fsp_path_helper_before,
        89
    );
    assert_eq!(
        EVENTS[Event::DecryptFspPathFallback as usize].load(Relaxed) - fsp_path_fallback_before,
        97
    );
    assert_eq!(
        EVENTS[Event::DecryptFspOwnerHandoffDropped as usize].load(Relaxed)
            - fsp_owner_handoff_dropped_before,
        98
    );
    assert_eq!(
        EVENTS[Event::DecryptFspPathWorkerOpen as usize].load(Relaxed)
            - fsp_path_worker_open_before,
        99
    );
    assert_eq!(
        EVENTS[Event::DecryptFmpPreownerWindowFallback as usize].load(Relaxed)
            - fmp_preowner_window_fallback_before,
        107
    );
    assert_eq!(
        EVENTS[Event::DecryptFmpPreownerInlineFallback as usize].load(Relaxed)
            - fmp_preowner_inline_fallback_before,
        109
    );
    assert_eq!(
        EVENTS[Event::DecryptFmpPreownerCompletionBacklogFallback as usize].load(Relaxed)
            - fmp_preowner_completion_backlog_fallback_before,
        112
    );
    assert_eq!(
        EVENTS[Event::DecryptFspOpenWorkerCompletionBacklogFallback as usize].load(Relaxed)
            - fsp_open_worker_completion_backlog_fallback_before,
        116
    );
    assert_eq!(
        EVENTS[Event::DecryptFspOpenWorkerReturnedDropped as usize].load(Relaxed)
            - fsp_open_worker_returned_dropped_before,
        117
    );
    assert_eq!(
        EVENTS[Event::DecryptFspPathWorkerOpenStriped as usize].load(Relaxed)
            - fsp_path_worker_open_striped_before,
        118
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchFlowKeyed as usize].load(Relaxed)
            - dispatch_flow_keyed_before,
        113
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchTargetOnly as usize].load(Relaxed)
            - dispatch_target_only_before,
        127
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchWorker0 as usize].load(Relaxed) - dispatch_worker0_before,
        131
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchWorker7 as usize].load(Relaxed) - dispatch_worker7_before,
        137
    );
    assert_eq!(
        EVENTS[Event::FmpWorkerDispatchWorkerOther as usize].load(Relaxed)
            - dispatch_worker_other_before,
        139
    );
    assert_eq!(
        EVENTS[Event::EndpointBulkFastPathPrepareFailed as usize].load(Relaxed)
            - endpoint_bulk_prepare_failed_before,
        149
    );
    assert_eq!(
        EVENTS[Event::EndpointBulkFastPathStageFull as usize].load(Relaxed)
            - endpoint_bulk_stage_full_before,
        151
    );
    assert_eq!(
        EVENTS[Event::EndpointBulkFastPathFeedbackFull as usize].load(Relaxed)
            - endpoint_bulk_feedback_full_before,
        157
    );
}

#[test]
fn wait_threshold_events_only_count_samples_at_or_above_threshold() {
    let event = Event::ConnectedUdpActivationFailed;
    let before = EVENTS[event as usize].load(Relaxed);

    record_wait_threshold(event, 499_999, 3, 500_000);
    record_wait_threshold(event, 500_000, 5, 500_000);
    record_wait_threshold(event, 750_000, 7, 500_000);

    assert_eq!(EVENTS[event as usize].load(Relaxed) - before, 12);
}
