pub(crate) trait PacketMover2TransportOutput {
    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), PacketMover2OutputError>;
}

impl<T: PacketMover2TransportOutput + ?Sized> PacketMover2TransportOutput for &mut T {
    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), PacketMover2OutputError> {
        (**self).send_transport(transport_id, remote_addr, output)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2TransportSendPlan {
    transport_id: TransportId,
    remote_addr: TransportAddr,
    output: PacketOutput,
}

impl PacketMover2TransportSendPlan {
    pub(crate) fn new(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Self {
        Self {
            transport_id,
            remote_addr,
            output,
        }
    }

    pub(crate) fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    pub(crate) fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    pub(crate) fn output(&self) -> &PacketOutput {
        &self.output
    }
}

#[derive(Debug, Default)]
pub(crate) struct PacketMover2TransportSendPlanOutput {
    plans: Vec<PacketMover2TransportSendPlan>,
}

impl PacketMover2TransportSendPlanOutput {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn clear(&mut self) {
        self.plans.clear();
    }

    pub(crate) fn plans(&self) -> &[PacketMover2TransportSendPlan] {
        &self.plans
    }
}

impl PacketMover2TransportOutput for PacketMover2TransportSendPlanOutput {
    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), PacketMover2OutputError> {
        self.plans.push(PacketMover2TransportSendPlan::new(
            transport_id,
            remote_addr,
            output,
        ));
        Ok(())
    }
}

impl PacketMover2OutputSink for PacketMover2TransportSendPlanOutput {
    fn send(&mut self, output: PacketOutput) -> Result<(), PacketMover2OutputError> {
        let Some((transport_id, remote_addr)) = output.path.as_ref().and_then(|path| match path {
            TransportPath::Live {
                transport_id,
                remote_addr,
            } => Some((*transport_id, remote_addr.clone())),
            TransportPath::Scratch(_) => None,
        }) else {
            return Err(PacketMover2OutputError::NoRoute);
        };
        self.send_transport(transport_id, remote_addr, output)
    }
}

pub(crate) trait PacketMover2TransportResolver {
    fn resolve_packet_mover2_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle>;
}

impl PacketMover2TransportResolver for HashMap<TransportId, TransportHandle> {
    fn resolve_packet_mover2_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle> {
        self.get(&transport_id)
    }
}

impl<T: PacketMover2TransportResolver + ?Sized> PacketMover2TransportResolver for &T {
    fn resolve_packet_mover2_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle> {
        (**self).resolve_packet_mover2_transport(transport_id)
    }
}

pub(crate) async fn send_packet_mover2_transport_plans<R>(
    transports: &R,
    plans: &[PacketMover2TransportSendPlan],
    drops: &mut Vec<PacketMover2OutputDrop>,
) -> usize
where
    R: PacketMover2TransportResolver + ?Sized,
{
    send_packet_mover2_transport_plans_inner(transports, plans, drops, None).await
}

pub(crate) async fn send_packet_mover2_transport_plans_collect_sent<R>(
    transports: &R,
    plans: &[PacketMover2TransportSendPlan],
    drops: &mut Vec<PacketMover2OutputDrop>,
    sent_outputs: &mut Vec<PacketOutput>,
) -> usize
where
    R: PacketMover2TransportResolver + ?Sized,
{
    send_packet_mover2_transport_plans_inner(transports, plans, drops, Some(sent_outputs)).await
}

async fn send_packet_mover2_transport_plans_inner<R>(
    transports: &R,
    plans: &[PacketMover2TransportSendPlan],
    drops: &mut Vec<PacketMover2OutputDrop>,
    mut sent_outputs: Option<&mut Vec<PacketOutput>>,
) -> usize
where
    R: PacketMover2TransportResolver + ?Sized,
{
    let mut sent = 0;
    let mut batch = Vec::new();
    for lane in [Lane::Priority, Lane::Bulk] {
        let mut start = 0usize;
        while let Some((range_start, range_end, transport_id)) =
            next_transport_lane_batch_range(plans, start, lane)
        {
            batch.clear();
            append_transport_batch_plans(plans, range_start, range_end, lane, &mut batch);

            let Some(transport) = transports.resolve_packet_mover2_transport(transport_id) else {
                for (plan_index, _, _) in batch.iter().copied() {
                    drops.push(PacketMover2OutputDrop::from_output(
                        plans[plan_index].output(),
                        PacketMover2OutputError::NoRoute,
                    ));
                }
                start = range_end;
                continue;
            };

            if batch.len() == 1 {
                let plan_index = batch[0].0;
                let plan = &plans[plan_index];
                let result = transport
                    .send(plan.remote_addr(), plan.output().payload())
                    .await;
                record_transport_send_result(
                    plans,
                    plan_index,
                    result,
                    &mut sent,
                    drops,
                    &mut sent_outputs,
                );
                start = range_end;
                continue;
            }

            transport
                .send_batch(&batch, |plan_index, result| {
                    record_transport_send_result(
                        plans,
                        plan_index,
                        result,
                        &mut sent,
                        drops,
                        &mut sent_outputs,
                    );
                })
                .await;
            start = range_end;
        }
    }
    sent
}

fn next_transport_lane_batch_range(
    plans: &[PacketMover2TransportSendPlan],
    start: usize,
    lane: Lane,
) -> Option<(usize, usize, TransportId)> {
    let mut range_start = start;
    while range_start < plans.len() && plans[range_start].output().lane() != lane {
        range_start += 1;
    }
    if range_start == plans.len() {
        return None;
    }

    let transport_id = plans[range_start].transport_id;
    let mut range_end = range_start + 1;
    while range_end < plans.len() {
        if plans[range_end].output().lane() == lane
            && plans[range_end].transport_id != transport_id
        {
            break;
        }
        range_end += 1;
    }
    Some((range_start, range_end, transport_id))
}

fn record_transport_send_result(
    plans: &[PacketMover2TransportSendPlan],
    plan_index: usize,
    result: Result<usize, TransportError>,
    sent: &mut usize,
    drops: &mut Vec<PacketMover2OutputDrop>,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
) {
    let plan = &plans[plan_index];
    match result {
        Ok(_) => {
            *sent += 1;
            if let Some(sent_outputs) = sent_outputs.as_deref_mut() {
                sent_outputs.push(plan.output().clone());
            }
        }
        Err(error) => drops.push(PacketMover2OutputDrop::from_output(
            plan.output(),
            packet_mover2_output_error_for_transport(&error),
        )),
    }
}

fn append_transport_batch_plans<'a>(
    plans: &'a [PacketMover2TransportSendPlan],
    start: usize,
    end: usize,
    lane: Lane,
    batch: &mut Vec<(usize, &'a TransportAddr, &'a [u8])>,
) {
    batch.extend(
        plans[start..end]
            .iter()
            .enumerate()
            .filter_map(|(relative_index, plan)| {
                if plan.output().lane() != lane {
                    return None;
                }
                Some((start + relative_index, plan.remote_addr(), plan.output().payload()))
            }),
    );
}

fn packet_mover2_output_error_for_transport(error: &TransportError) -> PacketMover2OutputError {
    match error {
        TransportError::MtuExceeded { .. } => PacketMover2OutputError::MtuExceeded,
        error if error.is_local_route_unavailable() => PacketMover2OutputError::NoRoute,
        TransportError::NotStarted | TransportError::NotSupported(_) => {
            PacketMover2OutputError::Unavailable
        }
        _ => PacketMover2OutputError::TransportFailed,
    }
}
