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
    let mut start = 0usize;
    while start < plans.len() {
        let transport_id = plans[start].transport_id;
        let mut end = start + 1;
        while end < plans.len() && plans[end].transport_id == transport_id {
            end += 1;
        }

        let Some(transport) = transports.resolve_packet_mover2_transport(transport_id) else {
            for plan in &plans[start..end] {
                drops.push(PacketMover2OutputDrop::from_output(
                    plan.output(),
                    PacketMover2OutputError::NoRoute,
                ));
            }
            start = end;
            continue;
        };

        if end - start == 1 {
            let plan = &plans[start];
            match transport.send(plan.remote_addr(), plan.output().payload()).await {
                Ok(_) => {
                    sent += 1;
                    if let Some(sent_outputs) = sent_outputs.as_deref_mut() {
                        sent_outputs.push(plan.output().clone());
                    }
                }
                Err(error) => drops.push(PacketMover2OutputDrop::from_output(
                    plan.output(),
                    packet_mover2_output_error_for_transport(&error),
                )),
            }
            start = end;
            continue;
        }

        batch.clear();
        append_transport_batch_plans(plans, start, end, Lane::Priority, &mut batch);
        append_transport_batch_plans(plans, start, end, Lane::Bulk, &mut batch);
        transport
            .send_batch(&batch, |plan_index, result| {
                let plan = &plans[plan_index];
                match result {
                    Ok(_) => {
                        sent += 1;
                        if let Some(sent_outputs) = sent_outputs.as_deref_mut() {
                            sent_outputs.push(plan.output().clone());
                        }
                    }
                    Err(error) => drops.push(PacketMover2OutputDrop::from_output(
                        plan.output(),
                        packet_mover2_output_error_for_transport(&error),
                    )),
                }
            })
            .await;
        start = end;
    }
    sent
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
