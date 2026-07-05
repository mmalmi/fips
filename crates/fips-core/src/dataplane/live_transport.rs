const TRANSPORT_SEND_BATCH_PACKETS: usize = 32;
#[cfg(test)]
const TRANSPORT_SEND_WORKER_COALESCE_PACKETS: usize = TRANSPORT_SEND_BATCH_PACKETS;
#[cfg(test)]
const TRANSPORT_SEND_WORKER_PRIORITY_RESERVE_PACKETS: usize = TRANSPORT_SEND_BATCH_PACKETS;

#[derive(Debug)]
pub(crate) struct DataplaneTransportSendWorkerPool {
    max_batch_packets: usize,
}

impl DataplaneTransportSendWorkerPool {
    pub(crate) fn new(max_batch_packets: usize) -> Self {
        Self {
            max_batch_packets: max_batch_packets
                .max(1)
                .min(TRANSPORT_SEND_BATCH_PACKETS),
        }
    }

    pub(crate) fn default_live() -> Self {
        Self::new(TRANSPORT_SEND_BATCH_PACKETS)
    }

    #[cfg(test)]
    fn max_job_records_for_lane(&self, _lane: Lane) -> usize {
        self.max_batch_packets()
    }

    fn max_batch_packets(&self) -> usize {
        self.max_batch_packets.max(1)
    }
}

impl Default for DataplaneTransportSendWorkerPool {
    fn default() -> Self {
        Self::default_live()
    }
}

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

fn push_dataplane_udp_whole_datagram(
    snapshot: &crate::transport::udp::UdpSendSnapshot,
    remote_addr: std::net::SocketAddr,
    output: PacketOutput,
    packets: &mut DataplaneTransportPayloadBatch,
) -> bool {
    if snapshot
        .validate_packet(output.payload_len(), remote_addr)
        .is_err()
    {
        record_dataplane_udp_send_failed(1);
        return false;
    }
    packets.push_whole(output);
    true
}

fn push_dataplane_udp_direct_fsp_segments(
    snapshot: &crate::transport::udp::UdpSendSnapshot,
    remote_addr: std::net::SocketAddr,
    segments: DataplaneDirectFspTransportSegments,
    packets: &mut DataplaneTransportPayloadBatch,
) -> bool {
    for index in 0..segments.len() {
        if snapshot
            .validate_packet(segments.payload_len(index), remote_addr)
            .is_err()
        {
            record_dataplane_udp_send_failed(1);
            return false;
        }
    }
    packets.push_direct_fsp_segments(segments);
    true
}

fn record_dataplane_udp_send_failed(count: usize) {
    if count > 0 {
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneTransportSendWorkerSendFailed,
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

    fn len(&self) -> usize {
        self.outputs.len()
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
        self.groups.iter().map(DataplaneTransportPlanGroup::len).sum()
    }

    fn take_groups_preserving_capacity(&mut self) -> Vec<DataplaneTransportPlanGroup> {
        let capacity = self.groups.capacity();
        std::mem::replace(&mut self.groups, Vec::with_capacity(capacity))
    }

    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), DataplaneOutputError> {
        let lane = output.lane();
        if let Some(group) = self.groups.last_mut()
            && group.matches(lane, transport_id, &remote_addr)
        {
            group.push(output);
            return Ok(());
        }
        self.groups
            .push(DataplaneTransportPlanGroup::new(transport_id, remote_addr, output));
        Ok(())
    }
}

pub(crate) trait DataplaneTransportResolver {
    fn resolve_dataplane_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle>;
}

impl DataplaneTransportResolver for HashMap<TransportId, TransportHandle> {
    fn resolve_dataplane_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle> {
        self.get(&transport_id)
    }
}

impl<T: DataplaneTransportResolver + ?Sized> DataplaneTransportResolver for &T {
    fn resolve_dataplane_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle> {
        (**self).resolve_dataplane_transport(transport_id)
    }
}

async fn send_dataplane_transport_groups_with_worker<R>(
    transports: &R,
    groups: Vec<DataplaneTransportPlanGroup>,
    drops: &mut Vec<DataplaneOutputDrop>,
    worker: &mut DataplaneTransportSendWorkerPool,
    mut sent_receipts: Option<&mut Vec<DataplaneTransportSentReceipt>>,
) -> usize
where
    R: DataplaneTransportResolver + ?Sized,
{
    if groups.is_empty() {
        return 0;
    }

    let mut sent = 0usize;
    for group in groups {
        let Some(transport) = transports.resolve_dataplane_transport(group.transport_id)
        else {
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
            worker,
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
    for output in group.outputs {
        send_non_udp_transport_output(
            transport,
            &group.remote_addr,
            output,
            drops,
            sent_receipts,
            sent,
        )
        .await;
    }
}

async fn send_non_udp_transport_output(
    transport: &TransportHandle,
    remote_addr: &TransportAddr,
    output: PacketOutput,
    drops: &mut Vec<DataplaneOutputDrop>,
    sent_receipts: &mut Option<&mut Vec<DataplaneTransportSentReceipt>>,
    sent: &mut usize,
) {
    match transport.send(remote_addr, output.payload()).await {
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

async fn send_udp_transport_plan_group(
    udp: &crate::transport::udp::UdpTransport,
    group: DataplaneTransportPlanGroup,
    drops: &mut Vec<DataplaneOutputDrop>,
    worker: &mut DataplaneTransportSendWorkerPool,
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

    let max_batch_packets = worker.max_batch_packets();
    let total_outputs = group.outputs.len();
    let mut packets =
        DataplaneTransportPayloadBatch::with_capacity(total_outputs.min(max_batch_packets));
    for output in group.outputs {
        push_dataplane_udp_record(
            &snapshot,
            socket_addr,
            output,
            &mut packets,
            max_batch_packets,
            drops,
            sent_receipts,
            sent,
        )
        .await;
    }
    flush_dataplane_udp_send_batch(&snapshot, socket_addr, &mut packets).await;
}

#[allow(clippy::too_many_arguments)]
async fn push_dataplane_udp_record(
    snapshot: &crate::transport::udp::UdpSendSnapshot,
    socket_addr: std::net::SocketAddr,
    output: PacketOutput,
    packets: &mut DataplaneTransportPayloadBatch,
    max_batch_packets: usize,
    drops: &mut Vec<DataplaneOutputDrop>,
    sent_receipts: &mut Option<&mut Vec<DataplaneTransportSentReceipt>>,
    sent: &mut usize,
) {
    if let Err(reason) = validate_dataplane_udp_record(snapshot, socket_addr, &output) {
        drops.push(DataplaneOutputDrop::from_output(&output, reason));
        return;
    }

    let receipt = sent_receipts
        .as_ref()
        .map(|_| DataplaneTransportSentReceipt::from_output(&output));
    let accepted = match dataplane_direct_fsp_transport_output(output) {
        Ok(DataplaneDirectFspTransportOutput::Whole(output)) => {
            push_dataplane_udp_whole_datagram(snapshot, socket_addr, output, packets)
        }
        Ok(DataplaneDirectFspTransportOutput::Segments(segments)) => {
            push_dataplane_udp_direct_fsp_segments(snapshot, socket_addr, segments, packets)
        }
        Err(output) => {
            drops.push(DataplaneOutputDrop::from_output(
                &output,
                DataplaneOutputError::MtuExceeded,
            ));
            false
        }
    };
    if !accepted {
        return;
    }

    *sent += 1;
    if let (Some(sent_receipts), Some(receipt)) = (sent_receipts.as_deref_mut(), receipt) {
        sent_receipts.push(receipt);
    }
    if packets.len() >= max_batch_packets {
        flush_dataplane_udp_send_batch(snapshot, socket_addr, packets).await;
    }
}

fn validate_dataplane_udp_record(
    snapshot: &crate::transport::udp::UdpSendSnapshot,
    socket_addr: std::net::SocketAddr,
    output: &PacketOutput,
) -> Result<(), DataplaneOutputError> {
    let data_len = match dataplane_direct_fsp_transport_max_datagram_len(output) {
        Ok(Some(data_len)) => data_len,
        Ok(None) => output.payload_len(),
        Err(()) => return Err(DataplaneOutputError::MtuExceeded),
    };
    snapshot
        .validate_packet(data_len, socket_addr)
        .map_err(|error| dataplane_output_error_for_transport(&error))
}

async fn flush_dataplane_udp_send_batch(
    snapshot: &crate::transport::udp::UdpSendSnapshot,
    socket_addr: std::net::SocketAddr,
    packets: &mut DataplaneTransportPayloadBatch,
) {
    if packets.is_empty() {
        return;
    }
    let _timer = crate::perf_profile::Timer::start(
        crate::perf_profile::Stage::DataplaneTransportSendWorker,
    );
    let failed = snapshot.send_payload_batch_to(packets, socket_addr).await;
    record_dataplane_udp_send_failed(failed);
    packets.clear();
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
        TransportError::MtuExceeded { .. } => DataplaneOutputError::MtuExceeded,
        error if error.is_local_route_unavailable() => DataplaneOutputError::NoRoute,
        TransportError::NotStarted | TransportError::NotSupported(_) => {
            DataplaneOutputError::Unavailable
        }
        _ => DataplaneOutputError::TransportFailed,
    }
}
