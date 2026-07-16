impl PacketTx {
    pub(crate) fn set_fast_ingress_sink(&mut self, sink: Arc<dyn PacketFastIngressSink>) {
        self.fast_ingress = Some(sink);
    }

    pub(crate) fn try_fast_ingress_packet_batch(&self, batch: &mut PacketBatch) -> usize {
        let Some(sink) = &self.fast_ingress else {
            return 0;
        };
        sink.try_ingest_batch(&mut batch.packets)
    }

    pub(crate) fn packet_batch(&self, capacity: usize) -> PacketBatch {
        self.batch_pool.take(capacity)
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    pub(crate) fn recv_buffer(&self, capacity: usize) -> Vec<u8> {
        self.buffer_pool.take(capacity)
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    pub(crate) fn packet_buffer(&self, data: Vec<u8>) -> PacketBuffer {
        PacketBuffer::pooled(data, self.buffer_pool.clone())
    }

    pub fn send(
        &self,
        packet: ReceivedPacket,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ReceivedPacket>> {
        let tx = if packet.is_transport_priority() {
            PacketQueueTx::Priority
        } else {
            PacketQueueTx::Bulk
        };
        self.send_item(tx, PacketQueueItem::One(packet))
            .map_err(|item| match item {
                PacketQueueItem::One(packet) => tokio::sync::mpsc::error::SendError(packet),
                PacketQueueItem::Batch(_) => {
                    unreachable!("single packet send cannot fail with a batch item")
                }
            })
    }

    pub(crate) fn send_packet_batch(&self, mut batch: PacketBatch) -> Result<(), ()> {
        if batch.is_empty() {
            return Ok(());
        }

        let packet_count = batch.packets.len();
        let priority_count = batch
            .packets
            .iter()
            .filter(|packet| packet.is_transport_priority())
            .count();
        if priority_count == 0 || priority_count == packet_count {
            let tx = if priority_count == 0 {
                PacketQueueTx::Bulk
            } else {
                PacketQueueTx::Priority
            };
            return self.send_packet_items(tx, batch);
        }

        let mut priority_packets = self.packet_batch(priority_count);
        let mut bulk_packets = self.packet_batch(packet_count - priority_count);
        for packet in batch.packets.drain(..) {
            if packet.is_transport_priority() {
                priority_packets.push(packet);
            } else {
                bulk_packets.push(packet);
            }
        }

        self.send_packet_items(PacketQueueTx::Priority, priority_packets)?;
        self.send_packet_items(PacketQueueTx::Bulk, bulk_packets)?;
        Ok(())
    }

    fn send_packet_items(&self, tx: PacketQueueTx, packets: PacketBatch) -> Result<(), ()> {
        if matches!(tx, PacketQueueTx::Bulk) {
            return self.send_bulk_packet_items(packets);
        }

        let item = match packets.packets.len() {
            0 => return Ok(()),
            _ => PacketQueueItem::Batch(packets),
        };
        self.send_item(tx, item).map_err(|_| ())
    }

    fn send_bulk_packet_items(&self, mut packets: PacketBatch) -> Result<(), ()> {
        let packet_count = packets.packets.len();
        if packet_count == 0 {
            return Ok(());
        }

        let granted = self.try_reserve_bulk_packet_prefix(packet_count);
        if granted == 0 {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::TransportBulkDropped,
                packet_count as u64,
            );
            return Ok(());
        }

        if granted < packet_count {
            let dropped = packet_count - granted;
            let _dropped_tail = packets.packets.split_off(granted);
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::TransportBulkDropped,
                dropped as u64,
            );
        }

        let item = match packets.packets.len() {
            0 => return Ok(()),
            _ => PacketQueueItem::Batch(packets),
        };
        self.send_reserved_item(PacketQueueTx::Bulk, item, Some(granted))
            .map_err(|_| ())
    }

    fn send_item(&self, tx: PacketQueueTx, item: PacketQueueItem) -> Result<(), PacketQueueItem> {
        let packet_count = item.packet_count();
        let bulk_reserved = if matches!(tx, PacketQueueTx::Bulk) && packet_count > 0 {
            if !self.try_reserve_bulk_packets(packet_count) {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::TransportBulkDropped,
                    packet_count as u64,
                );
                return Ok(());
            }
            Some(packet_count)
        } else {
            None
        };
        self.send_reserved_item(tx, item, bulk_reserved)
    }

    fn send_reserved_item(
        &self,
        tx: PacketQueueTx,
        item: PacketQueueItem,
        bulk_reserved: Option<usize>,
    ) -> Result<(), PacketQueueItem> {
        let packet_count = item.packet_count();
        debug_assert_eq!(
            bulk_reserved,
            matches!(tx, PacketQueueTx::Bulk)
                .then_some(packet_count)
                .filter(|count| *count > 0)
        );
        let priority_reserved = matches!(tx, PacketQueueTx::Priority)
            .then_some(packet_count)
            .filter(|count| *count > 0);
        if let Some(count) = priority_reserved {
            self.priority_queued_packets.fetch_add(count, Relaxed);
        }

        let tracked_count = if self.track_backlog {
            Some(packet_count)
        } else {
            None
        };
        let previous = tracked_count.map(|count| self.queued_packets.fetch_add(count, Relaxed));
        match tx.try_send(self, item) {
            Ok(()) => {
                if let (Some(count), Some(previous)) = (tracked_count, previous) {
                    let queued = previous.saturating_add(count);
                    if previous < TRANSPORT_CHANNEL_BACKLOG_HIGH_WATER
                        && queued >= TRANSPORT_CHANNEL_BACKLOG_HIGH_WATER
                    {
                        crate::perf_profile::record_event(
                            crate::perf_profile::Event::TransportChannelBacklogHigh,
                        );
                    }
                }
                Ok(())
            }
            Err(PacketSendFailure::Closed(item)) => {
                if let Some(count) = tracked_count {
                    self.queued_packets.fetch_sub(count, Relaxed);
                }
                if let Some(count) = priority_reserved {
                    release_priority_packets(&self.priority_queued_packets, count);
                }
                if let Some(count) = bulk_reserved {
                    self.release_bulk_packets(count);
                }
                Err(item)
            }
            Err(PacketSendFailure::DroppedBulk(dropped_count)) => {
                if let Some(count) = tracked_count {
                    self.queued_packets.fetch_sub(count, Relaxed);
                }
                if let Some(count) = priority_reserved {
                    release_priority_packets(&self.priority_queued_packets, count);
                }
                if let Some(count) = bulk_reserved {
                    self.release_bulk_packets(count);
                }
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::TransportBulkDropped,
                    dropped_count as u64,
                );
                Ok(())
            }
        }
    }

    fn try_reserve_bulk_packets(&self, count: usize) -> bool {
        self.bulk_queued_packets
            .fetch_update(Relaxed, Relaxed, |current| {
                current
                    .checked_add(count)
                    .filter(|next| *next <= self.bulk_packet_capacity)
            })
            .is_ok()
    }

    fn try_reserve_bulk_packet_prefix(&self, requested: usize) -> usize {
        if requested == 0 {
            return 0;
        }

        let mut current = self.bulk_queued_packets.load(Relaxed);
        loop {
            let available = self.bulk_packet_capacity.saturating_sub(current);
            let granted = requested.min(available);
            if granted == 0 {
                return 0;
            }
            match self.bulk_queued_packets.compare_exchange_weak(
                current,
                current + granted,
                Relaxed,
                Relaxed,
            ) {
                Ok(_) => return granted,
                Err(actual) => current = actual,
            }
        }
    }

    fn release_bulk_packets(&self, count: usize) {
        release_reserved_bulk_packets(&self.bulk_queued_packets, count);
    }
}

impl PacketRx {
    #[cfg(test)]
    pub(crate) fn queued_packets_for_test(&self) -> usize {
        self.pending_priority
            .as_ref()
            .map_or(0, |packets| packets.batch.packets.len())
            .saturating_add(
                self.pending_bulk
                    .as_ref()
                    .map_or(0, |packets| packets.batch.packets.len()),
            )
            .saturating_add(self.queued_packets.load(Relaxed))
    }

    pub(crate) fn priority_queued_packets(&self) -> usize {
        self.priority_queued_packets.load(Relaxed)
    }

    pub(crate) fn priority_ready_packets(&self) -> usize {
        self.pending_priority
            .as_ref()
            .map_or(0, |packets| packets.batch.packets.len())
            .saturating_add(self.priority_queued_packets())
    }

    pub async fn recv(&mut self) -> Option<ReceivedPacket> {
        loop {
            match self.try_recv() {
                Ok(packet) => return Some(packet),
                Err(TryRecvError::Disconnected) => return None,
                Err(TryRecvError::Empty) => {}
            }

            tokio::select! {
                biased;
                item = self.priority.recv(), if !self.priority_closed => {
                    match item {
                        Some(item) => {
                            if let Some(packet) = self.packet_from_item(item, PacketLane::Priority) {
                                return Some(packet);
                            }
                        }
                        None => self.priority_closed = true,
                    }
                }
                item = self.bulk.recv(), if !self.bulk_closed => {
                    match item {
                        Some(item) => {
                            if let Some(packet) = self.packet_from_item(item, PacketLane::Bulk) {
                                return Some(packet);
                            }
                        }
                        None => self.bulk_closed = true,
                    }
                }
            }
        }
    }

    pub fn try_recv(&mut self) -> Result<ReceivedPacket, TryRecvError> {
        if let Some(packet) = Self::take_pending(&mut self.pending_priority) {
            return Ok(packet);
        }

        if self.should_probe_priority() {
            match self.priority.try_recv() {
                Ok(item) => {
                    if let Some(packet) = self.packet_from_item(item, PacketLane::Priority) {
                        return Ok(packet);
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.priority_closed = true;
                }
            }
        }

        if let Some(packet) = Self::take_pending(&mut self.pending_bulk) {
            return Ok(packet);
        }

        match self.bulk.try_recv() {
            Ok(item) => self
                .packet_from_item(item, PacketLane::Bulk)
                .ok_or(TryRecvError::Empty),
            Err(TryRecvError::Empty) => {
                if self.priority_closed && self.bulk_closed {
                    Err(TryRecvError::Disconnected)
                } else {
                    Err(TryRecvError::Empty)
                }
            }
            Err(TryRecvError::Disconnected) => {
                self.bulk_closed = true;
                if self.priority_closed {
                    Err(TryRecvError::Disconnected)
                } else {
                    Err(TryRecvError::Empty)
                }
            }
        }
    }

    pub(crate) fn drain_ready<F>(&mut self, limit: usize, mut consume: F) -> usize
    where
        F: FnMut(ReceivedPacket) -> bool,
    {
        let mut drained = 0usize;
        while drained < limit {
            if !self.drain_pending_priority(limit, &mut drained, &mut consume) {
                break;
            }
            if drained >= limit {
                break;
            }

            if self.should_probe_priority() {
                match self.priority.try_recv() {
                    Ok(item) => {
                        if !self.drain_item(
                            item,
                            PacketLane::Priority,
                            limit,
                            &mut drained,
                            &mut consume,
                        ) {
                            break;
                        }
                        continue;
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        self.priority_closed = true;
                    }
                }
            }
            if drained >= limit {
                break;
            }

            if !self.drain_pending_bulk(limit, &mut drained, &mut consume) {
                break;
            }
            if drained >= limit {
                break;
            }

            match self.bulk.try_recv() {
                Ok(item) => {
                    if !self.drain_item(item, PacketLane::Bulk, limit, &mut drained, &mut consume) {
                        break;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.bulk_closed = true;
                    break;
                }
            }
        }
        drained
    }

    fn packet_from_item(
        &mut self,
        item: PacketQueueItem,
        lane: PacketLane,
    ) -> Option<ReceivedPacket> {
        item.record_dequeue_wait(lane);
        let packet_count = item.packet_count();
        if self.track_backlog {
            self.queued_packets.fetch_sub(packet_count, Relaxed);
        }
        if matches!(lane, PacketLane::Priority) {
            release_priority_packets(&self.priority_queued_packets, packet_count);
        }
        if matches!(lane, PacketLane::Bulk) {
            release_reserved_bulk_packets(&self.bulk_queued_packets, packet_count);
        }
        let rx_loop_owned_at = crate::perf_profile::stamp();
        match item {
            PacketQueueItem::One(mut packet) => {
                packet.trace_rx_loop_owned_at = rx_loop_owned_at;
                Some(packet)
            }
            PacketQueueItem::Batch(packets) => {
                let mut pending = PendingPackets::new(packets, rx_loop_owned_at);
                let packet = pending.next()?;
                if !pending.batch.packets.is_empty() {
                    match lane {
                        PacketLane::Priority => self.pending_priority = Some(pending),
                        PacketLane::Bulk => self.pending_bulk = Some(pending),
                    }
                }
                Some(packet)
            }
        }
    }

    fn drain_item<F>(
        &mut self,
        item: PacketQueueItem,
        lane: PacketLane,
        limit: usize,
        drained: &mut usize,
        consume: &mut F,
    ) -> bool
    where
        F: FnMut(ReceivedPacket) -> bool,
    {
        if let Some(packet) = self.packet_from_item(item, lane) {
            *drained += 1;
            if !consume(packet) {
                return false;
            }
        }

        match lane {
            PacketLane::Priority => self.drain_pending_priority(limit, drained, consume),
            PacketLane::Bulk => self.drain_pending_bulk(limit, drained, consume),
        }
    }

    fn drain_pending_priority<F>(
        &mut self,
        limit: usize,
        drained: &mut usize,
        consume: &mut F,
    ) -> bool
    where
        F: FnMut(ReceivedPacket) -> bool,
    {
        while *drained < limit {
            let Some(packet) = Self::take_pending(&mut self.pending_priority) else {
                return true;
            };
            *drained += 1;
            if !consume(packet) {
                return false;
            }
        }
        true
    }

    fn drain_pending_bulk<F>(&mut self, limit: usize, drained: &mut usize, consume: &mut F) -> bool
    where
        F: FnMut(ReceivedPacket) -> bool,
    {
        while *drained < limit {
            if self.should_probe_priority() {
                return true;
            }
            let Some(packet) = Self::take_pending(&mut self.pending_bulk) else {
                return true;
            };
            *drained += 1;
            if !consume(packet) {
                return false;
            }
        }
        true
    }

    fn should_probe_priority(&self) -> bool {
        !self.priority_closed
            && (self.priority_queued_packets.load(Relaxed) > 0 || self.bulk_closed)
    }

    fn take_pending(pending: &mut Option<PendingPackets>) -> Option<ReceivedPacket> {
        let packets = pending.as_mut()?;
        let packet = packets.next();
        if packets.batch.packets.is_empty() {
            *pending = None;
        }
        packet
    }
}

#[inline]
fn packet_channel_tracks_backlog() -> bool {
    cfg!(test) || crate::perf_profile::enabled()
}

fn release_reserved_bulk_packets(counter: &AtomicUsize, count: usize) {
    if count == 0 {
        return;
    }

    let previous = counter.fetch_sub(count, Relaxed);
    debug_assert!(
        previous >= count,
        "transport bulk queued packet accounting underflow"
    );
}

fn release_priority_packets(counter: &AtomicUsize, count: usize) {
    if count == 0 {
        return;
    }

    let previous = counter.fetch_sub(count, Relaxed);
    debug_assert!(
        previous >= count,
        "transport priority queued packet accounting underflow"
    );
}

/// Create a packet channel.
///
/// The capacity applies to bulk packets. Priority traffic is intentionally
/// unbounded so small control-shaped packets can still wake the rx loop while a
/// bulk receiver is saturated.
pub fn packet_channel(buffer: usize) -> (PacketTx, PacketRx) {
    let (priority_tx, priority_rx) = tokio::sync::mpsc::unbounded_channel();
    let (bulk_tx, bulk_rx) = tokio::sync::mpsc::channel(buffer.max(1));
    let priority_queued_packets = Arc::new(AtomicUsize::new(0));
    let queued_packets = Arc::new(AtomicUsize::new(0));
    let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
    let track_backlog = packet_channel_tracks_backlog();
    (
        PacketTx {
            priority: priority_tx,
            bulk: bulk_tx,
            fast_ingress: None,
            batch_pool: PacketBatchPool::new(),
            #[cfg(any(test, target_os = "linux", target_os = "macos"))]
            buffer_pool: PacketBufferPool::new(),
            priority_queued_packets: Arc::clone(&priority_queued_packets),
            queued_packets: Arc::clone(&queued_packets),
            bulk_queued_packets: Arc::clone(&bulk_queued_packets),
            bulk_packet_capacity: buffer.max(1),
            track_backlog,
        },
        PacketRx {
            priority: priority_rx,
            bulk: bulk_rx,
            priority_queued_packets,
            queued_packets,
            bulk_queued_packets,
            track_backlog,
            pending_priority: None,
            pending_bulk: None,
            priority_closed: false,
            bulk_closed: false,
        },
    )
}

#[cfg(test)]
#[path = "packet_channel/tests.rs"]
mod tests;
