struct PipelinedEndpointWire {
    wire_buf: Vec<u8>,
    fsp_aad_offset: usize,
    fsp_plaintext_offset: usize,
    link_plaintext_len: usize,
    fmp_inner_len: usize,
    wire_capacity: usize,
}

struct PipelinedEndpointWirePlan<'a> {
    source_addr: NodeAddr,
    dest_addr: NodeAddr,
    body: PipelinedEndpointWireBody<'a>,
    my_coords: Option<&'a crate::tree::TreeCoordinate>,
    dest_coords: Option<&'a crate::tree::TreeCoordinate>,
    path_mtu: u16,
    default_ttl: u8,
    link_plaintext_len: usize,
    fmp_payload_len: u16,
}

struct PipelinedEndpointWorkerWire {
    fmp_cipher: ring::aead::LessSafeKey,
    fmp_counter: u64,
    fsp_counter: u64,
    wire_buf: Vec<u8>,
    fsp_seal: crate::node::encrypt_worker::FspSealJob,
    link_plaintext_len: usize,
    wire_capacity: usize,
}

#[derive(Clone)]
struct PipelinedEndpointSendTarget {
    socket: crate::transport::udp::socket::AsyncUdpSocket,
    socket_addr: std::net::SocketAddr,
}

struct PipelinedEndpointBatchTarget {
    send_target: PipelinedEndpointSendTarget,
    path_mtu: u16,
}

struct PipelinedEndpointDispatchPlan<'a> {
    next_hop_addr: NodeAddr,
    payload: &'a EndpointDataPayload,
    timestamp: u32,
    now_ms: u64,
    fsp_flags: u8,
    path_mtu: u16,
    inner_plaintext_len: usize,
    fsp_payload_len: u16,
    bulk_endpoint_data: bool,
    drop_on_backpressure: bool,
    scheduling_weight: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PipelinedEndpointRoutePlan {
    source_addr: NodeAddr,
    next_hop_addr: NodeAddr,
    path_mtu: u16,
    default_ttl: u8,
    scheduling_weight: u8,
    direct_path_blocks_direct_payload: bool,
}

struct PipelinedEndpointPeerRuntimeRoute {
    source_addr: NodeAddr,
    peer_snapshot: crate::node::PeerRuntimeRouteSnapshot,
    default_ttl: u8,
    scheduling_weight: u8,
    direct_path_blocks_direct_payload: bool,
}

struct PipelinedEndpointPeerRuntimeRouteRequest {
    source_addr: NodeAddr,
    dest_addr: NodeAddr,
    now_ms: u64,
    default_ttl: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointSendPlanError {
    FmpPayloadTooLarge,
    FspPayloadTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointPeerRuntimeRouteRequestError {
    NoRoute {
        dest_addr: NodeAddr,
    },
    FmpPreparation {
        next_hop_addr: NodeAddr,
        error: crate::node::FmpSendPreparationError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointRuntimeSendPlanError {
    SendPlan(PipelinedEndpointSendPlanError),
    RoutePeerMismatch {
        route_next_hop: NodeAddr,
        peer_snapshot_addr: NodeAddr,
    },
    FmpPayloadMismatch {
        prepared_payload_len: u16,
        plan_payload_len: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointRuntimeSendAttemptError {
    FspReservation {
        dest_addr: NodeAddr,
        error: crate::node::FspWorkerSendReservationError,
    },
    FmpReservation {
        next_hop_addr: NodeAddr,
        error: crate::node::FmpSendPreparationError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointRuntimeSendError {
    TransportNotFound(crate::transport::TransportId),
    Attempt(PipelinedEndpointRuntimeSendAttemptError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointPeerRuntimeSendError {
    RuntimePlan {
        dest_addr: NodeAddr,
        next_hop_addr: NodeAddr,
        error: PipelinedEndpointRuntimeSendPlanError,
    },
    RuntimeSend(PipelinedEndpointRuntimeSendError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelinedEndpointPeerRuntimeSendRequestError {
    Route(PipelinedEndpointPeerRuntimeRouteRequestError),
    Send(PipelinedEndpointPeerRuntimeSendError),
}

struct PipelinedEndpointSendPlan<'a> {
    wire_plan: PipelinedEndpointWirePlan<'a>,
    dispatch_plan: PipelinedEndpointDispatchPlan<'a>,
}

struct PipelinedEndpointRuntimeSendPlan<'a> {
    route_plan: PipelinedEndpointRoutePlan,
    send_plan: PipelinedEndpointSendPlan<'a>,
    peer_snapshot: crate::node::PeerRuntimeSendSnapshot,
}

struct PipelinedEndpointRuntimeSendDispatch<'a> {
    runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
    send_target: PipelinedEndpointSendTarget,
    fmp_reservation: crate::node::PreparedFmpWorkerReservation,
    fsp_reservation: crate::node::session::FspSendReservation,
}

struct PipelinedEndpointRuntimeSendAttempt<'a> {
    runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
    send_target: PipelinedEndpointSendTarget,
}

struct PipelinedEndpointRuntimeBatchSendAttempt<'a> {
    runtime_plans: Vec<PipelinedEndpointRuntimeSendPlan<'a>>,
    send_target: PipelinedEndpointSendTarget,
}

struct PipelinedEndpointRuntimeSend<'a> {
    runtime_plan: PipelinedEndpointRuntimeSendPlan<'a>,
}

struct PipelinedEndpointPeerRuntimeSend<'a> {
    runtime_route: PipelinedEndpointPeerRuntimeRoute,
    send: PipelinedEndpointSend<'a>,
}

struct PipelinedEndpointPeerRuntimeBatchSend;

struct PipelinedEndpointPeerRuntimeSendRequest<'a> {
    route_request: PipelinedEndpointPeerRuntimeRouteRequest,
    send: PipelinedEndpointSend<'a>,
}

struct PipelinedEndpointPreparedSend {
    dest_addr: NodeAddr,
    next_hop_addr: NodeAddr,
    fmp_counter: u64,
    fmp_timestamp_ms: u32,
    fmp_wire_capacity: usize,
    originated_bytes: usize,
    fsp_path_mtu: u16,
    fsp_bookkeeping: FspSendBookkeepingInput,
    worker_job: crate::node::encrypt_worker::FmpSendJob,
}

fn pipelined_endpoint_link_plaintext_len(
    inner_plaintext_len: usize,
    my_coords: Option<&crate::tree::TreeCoordinate>,
    dest_coords: Option<&crate::tree::TreeCoordinate>,
) -> usize {
    let coords_size = match (my_coords, dest_coords) {
        (Some(src), Some(dst)) => coords_wire_size(src) + coords_wire_size(dst),
        _ => 0,
    };
    SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + coords_size + inner_plaintext_len
}

fn pipelined_endpoint_fmp_payload_len(link_plaintext_len: usize) -> Option<u16> {
    let payload_len = 4usize
        .checked_add(link_plaintext_len)?
        .checked_add(crate::noise::TAG_SIZE)?;
    u16::try_from(payload_len).ok()
}
