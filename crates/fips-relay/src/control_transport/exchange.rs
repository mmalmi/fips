//! One bounded request and response; completed records release admission.
use super::*;

pub(super) struct Exchange {
    pub(super) peer: PeerIdentity,
    pub(super) outbound: bool,
    admission: AdmissionCheck,
    started: Instant,
    outgoing: Vec<u8>,
    sent: usize,
    incoming: Vec<u8>,
    dispatched: bool,
    checking_record: bool,
    client: Option<oneshot::Sender<Result<Vec<u8>, String>>>,
    server_reply: Option<oneshot::Receiver<Vec<u8>>>,
}

impl Exchange {
    pub(super) fn server(peer: PeerIdentity, admission: AdmissionCheck, incoming: Vec<u8>) -> Self {
        Self {
            peer,
            outbound: false,
            admission,
            started: Instant::now(),
            outgoing: Vec::new(),
            sent: 0,
            incoming,
            dispatched: false,
            checking_record: false,
            client: None,
            server_reply: None,
        }
    }

    pub(super) fn client(command: Command, admission: AdmissionCheck) -> Self {
        let mut exchange = Self::server(command.peer, admission, Vec::new());
        exchange.outbound = true;
        exchange.outgoing = frame(command.body).expect("bounded at command entry");
        exchange.client = Some(command.response);
        exchange
    }

    pub(super) fn fail(&mut self, reason: &str) {
        if let Some(response) = self.client.take() {
            let _ = response.send(Err(reason.to_string()));
        }
    }
}

fn frame(body: Vec<u8>) -> Result<Vec<u8>, String> {
    if body.len() > MAX_RECORD_BYTES {
        return Err("control record exceeds size limit".into());
    }
    let mut result = Vec::with_capacity(body.len() + 4);
    result.extend_from_slice(&(body.len() as u32).to_be_bytes());
    result.extend_from_slice(&body);
    Ok(result)
}

fn complete_frame(bytes: &[u8]) -> Result<bool, String> {
    if bytes.len() < 4 {
        return Ok(false);
    }
    let size = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if size > MAX_RECORD_BYTES || bytes.len() > size + 4 {
        return Err("invalid control record length".into());
    }
    Ok(bytes.len() == size + 4)
}

pub(super) async fn drive(
    tcp: &mut FipsTcpEndpoint,
    id: ConnectionId,
    exchange: &mut Exchange,
    incoming: &mpsc::Sender<IncomingRequest>,
    now: u64,
    statistics: &ControlStatistics,
) -> Result<bool, String> {
    if exchange.started.elapsed() >= REQUEST_TIMEOUT
        || exchange.client.as_ref().is_some_and(|c| c.is_closed())
    {
        return Err("control request expired or canceled".into());
    }
    let Some(state) = tcp.state(id) else {
        return Err("control stream closed".into());
    };
    if !exchange.admission.ready().await? {
        return Ok(true);
    }
    if !matches!(state, State::Established | State::CloseWait) {
        return Ok(true);
    }
    if let Some(receiver) = exchange.server_reply.as_mut() {
        match receiver.try_recv() {
            Ok(reply) => {
                exchange.outgoing = frame(reply)?;
                exchange.server_reply = None;
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                return Err("control handler canceled request".into());
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
    }
    if exchange.sent < exchange.outgoing.len() {
        let end = (exchange.sent + 16 * 1024).min(exchange.outgoing.len());
        let written = tcp
            .write(id, &exchange.outgoing[exchange.sent..end], now)
            .await
            .map_err(|e| e.to_string())?;
        exchange.sent += written;
        statistics.sent.fetch_add(written as u64, Ordering::Relaxed);
    }
    if exchange.client.is_none()
        && exchange.dispatched
        && !exchange.outgoing.is_empty()
        && exchange.sent == exchange.outgoing.len()
    {
        return Ok(false);
    }
    if exchange.dispatched {
        return Ok(true);
    }
    let bytes = tcp
        .read(id, MAX_RECORD_BYTES + 4 - exchange.incoming.len(), now)
        .await
        .map_err(|e| e.to_string())?;
    statistics
        .received
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    exchange.incoming.extend_from_slice(&bytes);
    if complete_frame(&exchange.incoming)? {
        if exchange.outbound && exchange.sent != exchange.outgoing.len() {
            return Err("control response preceded its complete request".into());
        }
        if let Some(response) = exchange.client.take() {
            let body = exchange.incoming.split_off(4);
            let _ = response.send(Ok(body));
            return Ok(false);
        }
        if !exchange.checking_record {
            exchange.admission.recheck();
            exchange.checking_record = true;
            return Ok(true);
        }
        let body = exchange.incoming.split_off(4);
        let (respond, receiver) = oneshot::channel();
        statistics.requests_received.fetch_add(1, Ordering::Relaxed);
        incoming
            .try_send(IncomingRequest {
                peer: exchange.peer,
                body,
                respond,
            })
            .map_err(|_| "control handler queue is closed or full".to_string())?;
        exchange.server_reply = Some(receiver);
        exchange.dispatched = true;
    } else if tcp.is_read_closed(id) {
        return Err("control stream ended before its record".into());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_decoder_rejects_oversize_and_extra_records() {
        assert!(!complete_frame(&[0, 0, 1]).unwrap());
        assert!(complete_frame(&frame(vec![1; MAX_RECORD_BYTES]).unwrap()).unwrap());
        assert!(complete_frame(&[0, 1, 0, 1]).is_err());
        assert!(complete_frame(&[0, 0, 0, 0, 1]).is_err());
    }
}
