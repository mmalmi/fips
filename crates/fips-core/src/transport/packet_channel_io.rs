impl PacketTx {
    #[cfg(test)]
    pub(crate) fn reserved_packets_for_test(&self) -> usize {
        self.priority_reserved_packets
            .load(Relaxed)
            .saturating_add(self.bulk_reserved_packets.load(Relaxed))
    }

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

    /// Reliable readers wait for control capacity instead of silently losing
    /// an already received record. Bulk retains nonblocking overload behavior.
    /// Waiting owns no queue credit and is safe to cancel with the connection.
    pub(crate) async fn send_stream_packet(
        &self,
        packet: ReceivedPacket,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ReceivedPacket>> {
        if !packet.is_transport_priority() {
            return self.send(packet);
        }
        // A notification is not a reservation: a hot reader could otherwise
        // repeatedly take released credits before a woken reader is polled.
        // FIFO stream admission keeps that reader's turn across the capacity
        // wait. Native datagrams and bulk retain their nonblocking paths.
        let _turn = self.priority_stream_turn.lock().await;
        let available = self.priority_space.notified();
        tokio::pin!(available);
        loop {
            // Register before checking: multiple readers can otherwise miss a
            // release between finding no capacity and first polling Notified.
            available.as_mut().enable();
            if self.priority.is_closed() {
                return Err(tokio::sync::mpsc::error::SendError(packet));
            }
            if reserve_packet_prefix(
                &self.priority_reserved_packets,
                TRANSPORT_PRIORITY_PACKET_CAPACITY,
                1,
            ) == 1
            {
                // No await between reserving and handing ownership to credits.
                return self
                    .send_reserved_item(PacketQueueTx::Priority, PacketQueueItem::One(packet))
                    .map_err(|item| match item {
                        PacketQueueItem::One(packet) => tokio::sync::mpsc::error::SendError(packet),
                        PacketQueueItem::Batch(_) => unreachable!("stream sends one packet"),
                    });
            }
            tokio::select! {
                _ = available.as_mut() => {},
                _ = self.priority.closed() => {
                    return Err(tokio::sync::mpsc::error::SendError(packet));
                }
            }
            available.set(self.priority_space.notified());
        }
    }

    fn send_packet_items(&self, tx: PacketQueueTx, mut packets: PacketBatch) -> Result<(), ()> {
        let packet_count = packets.packets.len();
        if packet_count == 0 {
            return Ok(());
        }
        if tx.sender(self).is_closed() {
            return Err(());
        }
        let granted = reserve_packet_prefix(tx.reserved(self), tx.capacity(self), packet_count);
        if granted < packet_count {
            tx.record_drop(packet_count - granted);
            packets.packets.truncate(granted);
        }
        if granted == 0 {
            return Ok(());
        }
        self.send_reserved_item(tx, PacketQueueItem::Batch(packets))
            .map_err(|_| ())
    }

    fn send_item(&self, tx: PacketQueueTx, item: PacketQueueItem) -> Result<(), PacketQueueItem> {
        if tx.sender(self).is_closed() {
            return Err(item);
        }
        let count = item.packet_count();
        let granted = reserve_packet_prefix(tx.reserved(self), tx.capacity(self), count);
        if granted != count {
            release_reserved_packets(tx.reserved(self), granted);
            tx.record_drop(count);
            return Ok(());
        }
        self.send_reserved_item(tx, item)
    }

    fn send_reserved_item(
        &self,
        tx: PacketQueueTx,
        item: PacketQueueItem,
    ) -> Result<(), PacketQueueItem> {
        let count = item.packet_count();
        let item = ReservedPacketQueueItem {
            item,
            credits: PacketCredits::new(tx, self, count),
        };
        match tx.try_send(self, item) {
            Ok(()) => Ok(()),
            Err(PacketSendFailure::Closed(item)) => Err(item),
            Err(PacketSendFailure::Dropped(count)) => {
                tx.record_drop(count);
                Ok(())
            }
        }
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
        item: ReservedPacketQueueItem,
        lane: PacketLane,
    ) -> Option<ReceivedPacket> {
        let ReservedPacketQueueItem { item, mut credits } = item;
        item.record_dequeue_wait(lane);
        credits.leave_channel();
        let rx_loop_owned_at = crate::perf_profile::stamp();
        match item {
            PacketQueueItem::One(mut packet) => {
                packet.trace_rx_loop_owned_at = rx_loop_owned_at;
                credits.consume();
                Some(packet)
            }
            PacketQueueItem::Batch(packets) => {
                let mut pending = PendingPackets::new(packets, rx_loop_owned_at, Some(credits));
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
        item: ReservedPacketQueueItem,
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

fn reserve_packet_prefix(counter: &AtomicUsize, capacity: usize, requested: usize) -> usize {
    let mut current = counter.load(Relaxed);
    loop {
        let granted = requested.min(capacity.saturating_sub(current));
        if granted == 0 {
            return 0;
        }
        match counter.compare_exchange_weak(current, current + granted, Relaxed, Relaxed) {
            Ok(_) => return granted,
            Err(actual) => current = actual,
        }
    }
}

fn release_reserved_packets(counter: &AtomicUsize, count: usize) {
    if count > 0 {
        let previous = counter.fetch_sub(count, Relaxed);
        debug_assert!(previous >= count, "transport packet reservation underflow");
    }
}

/// Create a packet channel.
///
/// The configured capacity applies to bulk packets. Priority has an independent
/// 64-packet reserve. Both bounds include dequeued batch tails until each packet
/// is returned to the consumer; pressure drops do not close either lane.
pub fn packet_channel(buffer: usize) -> (PacketTx, PacketRx) {
    let (priority_tx, priority_rx) = tokio::sync::mpsc::channel(TRANSPORT_PRIORITY_PACKET_CAPACITY);
    let (bulk_tx, bulk_rx) = tokio::sync::mpsc::channel(buffer.max(1));
    let priority_queued_packets = Arc::new(AtomicUsize::new(0));
    let priority_reserved_packets = Arc::new(AtomicUsize::new(0));
    let queued_packets = Arc::new(AtomicUsize::new(0));
    let bulk_reserved_packets = Arc::new(AtomicUsize::new(0));
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
            priority_reserved_packets: Arc::clone(&priority_reserved_packets),
            priority_space: Arc::new(tokio::sync::Notify::new()),
            priority_stream_turn: Arc::new(tokio::sync::Mutex::new(())),
            queued_packets: Arc::clone(&queued_packets),
            bulk_reserved_packets: Arc::clone(&bulk_reserved_packets),
            bulk_packet_capacity: buffer.max(1),
            track_backlog,
        },
        PacketRx {
            priority: priority_rx,
            bulk: bulk_rx,
            priority_queued_packets,
            #[cfg(test)]
            queued_packets,
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
