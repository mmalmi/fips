//! Shared native endpoint and control-service assembly, also used after reopen.
use super::*;
use fips_relay::control_transport::IncomingRequest;
use tokio::sync::mpsc;

pub(super) async fn endpoint(
    config: Config,
    buyer: Arc<BuyerAuthorizer>,
    seller: Arc<DurableRelay>,
) -> (Arc<FipsEndpoint>, Arc<Gate>, FipsEndpointServiceReceiver) {
    let gate = Arc::new(Gate {
        paid: PaidForwarder::for_billing(seller, buyer.clone(), BillingBasis::ForwardingData)
            .with_return_allowance()
            .unwrap(),
        blackhole: AtomicBool::new(false),
        dropped: AtomicU64::new(0),
        refused: AtomicU64::new(0),
    });
    let node = Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .forwarding_policy(gate.clone())
            .originated_session_observer(buyer)
            .bind()
            .await
            .unwrap(),
    );
    let receiver = node.register_service_receiver(44_740).await.unwrap();
    (node, gate, receiver)
}

pub(super) struct Setup {
    pub index: usize,
    pub node: Arc<FipsEndpoint>,
    pub buyer: Arc<BuyerAuthorizer>,
    pub seller: Arc<DurableRelay>,
    pub wallet: PathBuf,
    pub receiver: FileSpilmanPaymentReceiver,
    pub admission: Arc<ControlAdmission>,
    pub quote_policy: QuotePolicy,
    pub selection: Option<PriceSelectionPolicy>,
}

pub(super) struct Services {
    pub service: ControllerServices,
    pub quote_server: QuoteServer,
    pub payment_server: PaymentServer,
    pub quote_input: (Arc<ControlTransport>, QuotePolicy),
    pub incoming: mpsc::Receiver<IncomingRequest>,
}

impl Setup {
    pub async fn start(self) -> Services {
        let (transport, requests) = ControlTransport::start_with_admission(
            self.node.clone(),
            44_741,
            self.admission.clone(),
            self.index as u64 + 1,
        )
        .await
        .unwrap();
        let transport = Arc::new(transport);
        let quote_input = (transport.clone(), self.quote_policy.clone());
        let quotes = RouteQuotes::new(self.node.clone(), transport, self.quote_policy).unwrap();
        let quotes = Arc::new(if let Some(selection) = self.selection {
            quotes
                .with_price_selection(selection, self.buyer.clone())
                .unwrap()
        } else {
            quotes
        });
        let quote_server = QuoteServer::start(quotes.clone(), requests);
        let (acceptance, incoming) = ControlTransport::start_with_admission(
            self.node.clone(),
            44_742,
            self.admission.clone(),
            self.index as u64 + 10,
        )
        .await
        .unwrap();
        let (payment, requests) = ControlTransport::start_with_admission(
            self.node.clone(),
            44_743,
            self.admission,
            self.index as u64 + 20,
        )
        .await
        .unwrap();
        let payment_control = Arc::new(PaymentControl::new(
            self.receiver,
            self.wallet.clone(),
            self.seller.clone(),
        ));
        let payment_server = PaymentServer::start_shared(payment_control.clone(), requests);
        Services {
            service: ControllerServices {
                endpoint: self.node,
                quotes,
                acceptance: Arc::new(acceptance),
                payments: Arc::new(payment),
                payment_control,
                seller: self.seller,
                buyer: self.buyer,
                wallet_directory: self.wallet,
            },
            quote_server,
            payment_server,
            quote_input,
            incoming,
        }
    }
}
