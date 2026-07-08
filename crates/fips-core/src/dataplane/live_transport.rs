pub(crate) const DATAPLANE_TRANSPORT_SEND_BATCH_PACKETS: usize = 64;

#[derive(Debug)]
enum DataplaneTransportPayloadRecord {
    Whole(PacketOutput),
    DirectFspSegments(DataplaneDirectFspTransportSegments),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataplaneTransportPayloadItem {
    Whole {
        record_index: usize,
    },
    DirectFspSegment {
        record_index: usize,
        segment_index: usize,
    },
}

#[derive(Debug)]
struct DataplaneTransportPayloadBatch {
    records: Vec<DataplaneTransportPayloadRecord>,
    items: Vec<DataplaneTransportPayloadItem>,
}

impl DataplaneTransportPayloadBatch {
    fn with_capacity(record_capacity: usize) -> Self {
        Self {
            records: Vec::with_capacity(record_capacity),
            items: Vec::with_capacity(record_capacity),
        }
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn clear(&mut self) {
        self.records.clear();
        self.items.clear();
    }

    fn push_whole(&mut self, output: PacketOutput) {
        let record_index = self.records.len();
        self.records
            .push(DataplaneTransportPayloadRecord::Whole(output));
        self.items
            .push(DataplaneTransportPayloadItem::Whole { record_index });
    }

    fn push_direct_fsp_segments(&mut self, segments: DataplaneDirectFspTransportSegments) {
        let record_index = self.records.len();
        let segment_count = segments.len();
        self.records
            .push(DataplaneTransportPayloadRecord::DirectFspSegments(segments));
        self.items.reserve(segment_count);
        for segment_index in 0..segment_count {
            self.items.push(DataplaneTransportPayloadItem::DirectFspSegment {
                record_index,
                segment_index,
            });
        }
    }

    fn finish_send(
        &self,
        sent_items: usize,
        drops: &mut Vec<DataplaneOutputDrop>,
        sent_receipts: &mut Option<&mut Vec<DataplaneTransportSentReceipt>>,
        sent: &mut usize,
    ) {
        let mut item_cursor = 0usize;
        for record in &self.records {
            let item_count = record.item_count();
            let record_sent = item_cursor.saturating_add(item_count) <= sent_items;
            let output = record.output();
            if record_sent {
                *sent += 1;
                if let Some(sent_receipts) = sent_receipts.as_deref_mut() {
                    sent_receipts.push(DataplaneTransportSentReceipt::from_output(output));
                }
            } else {
                drops.push(DataplaneOutputDrop::from_output(
                    output,
                    DataplaneOutputError::TransportFailed,
                ));
            }
            item_cursor = item_cursor.saturating_add(item_count);
        }
    }
}

impl DataplaneTransportPayloadRecord {
    fn output(&self) -> &PacketOutput {
        match self {
            Self::Whole(output) => output,
            Self::DirectFspSegments(segments) => &segments.output,
        }
    }

    fn item_count(&self) -> usize {
        match self {
            Self::Whole(_) => 1,
            Self::DirectFspSegments(segments) => segments.len(),
        }
    }
}

impl crate::transport::udp::UdpPayloadBatch for DataplaneTransportPayloadBatch {
    fn len(&self) -> usize {
        self.items.len()
    }

    fn payload_len(&self, index: usize) -> usize {
        match self.items[index] {
            DataplaneTransportPayloadItem::Whole { record_index } => match &self.records[record_index] {
                DataplaneTransportPayloadRecord::Whole(output) => output.payload_len(),
                DataplaneTransportPayloadRecord::DirectFspSegments(_) => unreachable!(),
            },
            DataplaneTransportPayloadItem::DirectFspSegment {
                record_index,
                segment_index,
            } => match &self.records[record_index] {
                DataplaneTransportPayloadRecord::DirectFspSegments(segments) => {
                    segments.payload_len(segment_index)
                }
                DataplaneTransportPayloadRecord::Whole(_) => unreachable!(),
            },
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn contiguous_payload(&self, index: usize) -> Option<&[u8]> {
        match self.items[index] {
            DataplaneTransportPayloadItem::Whole { record_index } => match &self.records[record_index] {
                DataplaneTransportPayloadRecord::Whole(output) => Some(output.payload()),
                DataplaneTransportPayloadRecord::DirectFspSegments(_) => unreachable!(),
            },
            DataplaneTransportPayloadItem::DirectFspSegment { .. } => None,
        }
    }

    fn payload_slices<'a>(
        &'a self,
        index: usize,
        out: &mut [Option<&'a [u8]>; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES],
    ) -> usize {
        out.fill(None);
        match self.items[index] {
            DataplaneTransportPayloadItem::Whole { record_index } => match &self.records[record_index] {
                DataplaneTransportPayloadRecord::Whole(output) => {
                    out[0] = Some(output.payload());
                    1
                }
                DataplaneTransportPayloadRecord::DirectFspSegments(_) => unreachable!(),
            },
            DataplaneTransportPayloadItem::DirectFspSegment {
                record_index,
                segment_index,
            } => match &self.records[record_index] {
                DataplaneTransportPayloadRecord::DirectFspSegments(segments) => {
                    segments.payload_slices(segment_index, out)
                }
                DataplaneTransportPayloadRecord::Whole(_) => unreachable!(),
            },
        }
    }
}

fn record_dataplane_udp_send_failed(count: usize) {
    if count > 0 {
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneTransportSendFailed,
            count as u64,
        );
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DataplaneTransportPlanGroup {
    lane: Lane,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    outputs: Vec<PacketOutput>,
}

impl DataplaneTransportPlanGroup {
    fn new(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Self {
        let lane = output.lane();
        Self {
            lane,
            transport_id,
            remote_addr,
            outputs: vec![output],
        }
    }

    fn matches(&self, lane: Lane, transport_id: TransportId, remote_addr: &TransportAddr) -> bool {
        self.lane == lane && self.transport_id == transport_id && &self.remote_addr == remote_addr
    }

    fn push(&mut self, output: PacketOutput) {
        debug_assert_eq!(self.lane, output.lane());
        self.outputs.push(output);
    }

}

#[derive(Debug, Default)]
struct DataplaneTransportSendGroups {
    groups: Vec<DataplaneTransportPlanGroup>,
}

impl DataplaneTransportSendGroups {
    fn new() -> Self {
        Self::default()
    }

    fn clear(&mut self) {
        self.groups.clear();
    }

    fn planned_packets(&self) -> usize {
        self.groups.iter().map(|group| group.outputs.len()).sum()
    }

    fn take_groups_preserving_capacity(&mut self) -> Vec<DataplaneTransportPlanGroup> {
        let capacity = self.groups.capacity();
        std::mem::replace(&mut self.groups, Vec::with_capacity(capacity))
    }

    fn push_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) {
        let lane = output.lane();
        if let Some(group) = self.groups.last_mut()
            && group.matches(lane, transport_id, &remote_addr)
        {
            group.push(output);
            return;
        }
        self.groups
            .push(DataplaneTransportPlanGroup::new(transport_id, remote_addr, output));
    }
}

async fn send_dataplane_transport_groups(
    transports: &HashMap<TransportId, TransportHandle>,
    groups: Vec<DataplaneTransportPlanGroup>,
    drops: &mut Vec<DataplaneOutputDrop>,
    max_batch_packets: usize,
    mut sent_receipts: Option<&mut Vec<DataplaneTransportSentReceipt>>,
) -> usize
{
    if groups.is_empty() {
        return 0;
    }

    let mut sent = 0usize;
    for group in groups {
        let Some(transport) = transports.get(&group.transport_id) else {
            drop_transport_plan_group(group, drops, DataplaneOutputError::NoRoute);
            continue;
        };

        let TransportHandle::Udp(udp) = transport else {
            send_non_udp_transport_plan_group(
                transport,
                group,
                drops,
                &mut sent_receipts,
                &mut sent,
            )
            .await;
            continue;
        };

        send_udp_transport_plan_group(
            udp,
            group,
            drops,
            max_batch_packets,
            &mut sent_receipts,
            &mut sent,
        )
        .await;
    }
    sent
}

async fn send_non_udp_transport_plan_group(
    transport: &TransportHandle,
    group: DataplaneTransportPlanGroup,
    drops: &mut Vec<DataplaneOutputDrop>,
    sent_receipts: &mut Option<&mut Vec<DataplaneTransportSentReceipt>>,
    sent: &mut usize,
) {
    let DataplaneTransportPlanGroup {
        remote_addr,
        outputs,
        ..
    } = group;
    for output in outputs {
        match transport.send(&remote_addr, output.payload()).await {
            Ok(_) => {
                *sent += 1;
                if let Some(sent_receipts) = sent_receipts.as_deref_mut() {
                    sent_receipts.push(DataplaneTransportSentReceipt::from_output(&output));
                }
            }
            Err(error) => drops.push(DataplaneOutputDrop::from_output(
                &output,
                dataplane_output_error_for_transport(&error),
            )),
        }
    }
}

async fn send_udp_transport_plan_group(
    udp: &crate::transport::udp::UdpTransport,
    group: DataplaneTransportPlanGroup,
    drops: &mut Vec<DataplaneOutputDrop>,
    max_batch_packets: usize,
    sent_receipts: &mut Option<&mut Vec<DataplaneTransportSentReceipt>>,
    sent: &mut usize,
) {
    let snapshot = match udp.send_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            drop_transport_plan_group(
                group,
                drops,
                dataplane_output_error_for_transport(&error),
            );
            return;
        }
    };
    let socket_addr = match udp.resolve_for_off_task(&group.remote_addr).await {
        Ok(socket_addr) => socket_addr,
        Err(error) => {
            drop_transport_plan_group(
                group,
                drops,
                dataplane_output_error_for_transport(&error),
            );
            return;
        }
    };

    let max_batch_packets = max_batch_packets.clamp(1, DATAPLANE_TRANSPORT_SEND_BATCH_PACKETS);
    let total_outputs = group.outputs.len();
    let mut packets = DataplaneUdpTransportSendBatch::new(
        &snapshot,
        socket_addr,
        total_outputs.min(max_batch_packets),
        max_batch_packets,
    );
    for output in group.outputs {
        packets
            .push_record(output, drops, sent_receipts, sent)
            .await;
    }
    packets.flush(drops, sent_receipts, sent).await;
}

struct DataplaneUdpTransportSendBatch<'a> {
    snapshot: &'a crate::transport::udp::UdpSendSnapshot,
    socket_addr: std::net::SocketAddr,
    packets: DataplaneTransportPayloadBatch,
    max_batch_packets: usize,
}

impl<'a> DataplaneUdpTransportSendBatch<'a> {
    fn new(
        snapshot: &'a crate::transport::udp::UdpSendSnapshot,
        socket_addr: std::net::SocketAddr,
        record_capacity: usize,
        max_batch_packets: usize,
    ) -> Self {
        Self {
            snapshot,
            socket_addr,
            packets: DataplaneTransportPayloadBatch::with_capacity(record_capacity),
            max_batch_packets,
        }
    }

    async fn push_record(
        &mut self,
        output: PacketOutput,
        drops: &mut Vec<DataplaneOutputDrop>,
        sent_receipts: &mut Option<&mut Vec<DataplaneTransportSentReceipt>>,
        sent: &mut usize,
    ) {
        match dataplane_direct_fsp_transport_output(output) {
            DataplaneDirectFspTransportOutput::Whole(output) => {
                if let Err(reason) =
                    validate_dataplane_udp_payload(self.snapshot, self.socket_addr, output.payload_len())
                {
                    drops.push(DataplaneOutputDrop::from_output(&output, reason));
                    return;
                }
                self.packets.push_whole(output);
            }
            DataplaneDirectFspTransportOutput::Segments(segments) => {
                for index in 0..segments.len() {
                    if let Err(reason) = validate_dataplane_udp_payload(
                        self.snapshot,
                        self.socket_addr,
                        segments.payload_len(index),
                    ) {
                        drops.push(DataplaneOutputDrop::from_output(&segments.output, reason));
                        return;
                    }
                }
                self.packets.push_direct_fsp_segments(segments);
            }
            DataplaneDirectFspTransportOutput::MtuExceeded(output) => {
                let mtu = output.path_mtu();
                drops.push(DataplaneOutputDrop::from_output(
                    &output,
                    DataplaneOutputError::MtuExceeded { mtu },
                ));
                return;
            }
        };

        if self.packets.len() >= self.max_batch_packets {
            self.flush(drops, sent_receipts, sent).await;
        }
    }

    async fn flush(
        &mut self,
        drops: &mut Vec<DataplaneOutputDrop>,
        sent_receipts: &mut Option<&mut Vec<DataplaneTransportSentReceipt>>,
        sent: &mut usize,
    ) {
        if self.packets.is_empty() {
            return;
        }
        let _timer = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::DataplaneTransportSendBatch,
        );
        let failed = self
            .snapshot
            .send_payload_batch_to(&self.packets, self.socket_addr)
            .await;
        record_dataplane_udp_send_failed(failed);
        let sent_items = self.packets.len().saturating_sub(failed);
        self.packets
            .finish_send(sent_items, drops, sent_receipts, sent);
        self.packets.clear();
    }
}

fn validate_dataplane_udp_payload(
    snapshot: &crate::transport::udp::UdpSendSnapshot,
    socket_addr: std::net::SocketAddr,
    data_len: usize,
) -> Result<(), DataplaneOutputError> {
    snapshot
        .validate_packet(data_len, socket_addr)
        .map_err(|error| dataplane_output_error_for_transport(&error))
}

fn drop_transport_plan_group(
    group: DataplaneTransportPlanGroup,
    drops: &mut Vec<DataplaneOutputDrop>,
    reason: DataplaneOutputError,
) {
    for output in group.outputs {
        drops.push(DataplaneOutputDrop::from_output(&output, reason));
    }
}

fn dataplane_output_error_for_transport(error: &TransportError) -> DataplaneOutputError {
    match error {
        TransportError::MtuExceeded { mtu, .. } => DataplaneOutputError::MtuExceeded { mtu: *mtu },
        error if error.is_local_route_unavailable() => DataplaneOutputError::NoRoute,
        TransportError::NotStarted | TransportError::NotSupported(_) => {
            DataplaneOutputError::Unavailable
        }
        _ => DataplaneOutputError::TransportFailed,
    }
}
