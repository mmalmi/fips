use super::OwnerReservation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputTarget {
    Tun,
    Endpoint,
    Transport,
}

pub(crate) trait PacketOutputTarget {
    fn output_target(&self) -> Option<OutputTarget>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputDropReason {
    AdmissionPressure,
    Replay,
    Aead,
    Malformed,
    StaleGeneration,
    RetirePressure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutputDrop {
    pub(crate) reason: OutputDropReason,
    pub(crate) packet_count: usize,
    pub(crate) byte_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RetireOutput<P> {
    Payload { target: OutputTarget, packet: P },
    Control,
    Drop(OutputDrop),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetiredPacket<P> {
    pub(crate) reservation: OwnerReservation,
    pub(crate) output: RetireOutput<P>,
}

pub(crate) trait PacketOutput<P> {
    fn push_output(&mut self, packet: RetiredPacket<P>) -> Result<(), OutputDrop>;
}

#[derive(Debug, Default)]
pub(crate) struct VecOutputSink<P> {
    outputs: Vec<RetiredPacket<P>>,
}

impl<P> VecOutputSink<P> {
    pub(crate) fn into_outputs(self) -> Vec<RetiredPacket<P>> {
        self.outputs
    }
}

impl<P> PacketOutput<P> for VecOutputSink<P> {
    fn push_output(&mut self, packet: RetiredPacket<P>) -> Result<(), OutputDrop> {
        self.outputs.push(packet);
        Ok(())
    }
}
