//! Reopen the promotion source with no retained native or accounting owners.
use super::*;
use fips_relay::control_transport::IncomingRequest;
use tokio::sync::mpsc;

impl Bench {
    pub(crate) async fn restart_promotion_source(&mut self) -> mpsc::Receiver<IncomingRequest> {
        let old_node = Arc::downgrade(&self.nodes[0]);
        let old_buyer = Arc::downgrade(&self.buyers[0]);
        let old_seller = Arc::downgrade(&self.sellers[0]);
        let old_controller = Arc::downgrade(&self.controllers[0]);
        let old_wallet_control = Arc::downgrade(&self.services[0].payment_control);
        let quote_policy = self.quote_inputs[0].1.clone();
        let config = self.configs[0].clone();
        assert_eq!(
            config.peers.len(),
            2,
            "promotion source's original neighbors"
        );
        let neighbors = self
            .peers
            .iter()
            .filter(|peer| {
                config
                    .peers
                    .iter()
                    .any(|configured| configured.npub == peer.npub())
            })
            .copied()
            .collect();

        // Drop even the returned request receiver. A restart must establish new
        // transport streams instead of reusing controller-only reload state.
        drop(
            tokio::time::timeout(Duration::from_secs(20), self.tasks.remove(0).stop())
                .await
                .expect("source controller workers stop"),
        );
        self.quote_servers.remove(0).stop().await;
        self.payment_servers.remove(0).stop().await;
        drop(self.controllers.remove(0));
        drop(self.services.remove(0));
        drop(self.quote_inputs.remove(0));
        drop(self.admissions.remove(0));
        drop(self.receivers.remove(0));
        let node = self.nodes.remove(0);
        node.shutdown().await.unwrap();
        drop(node);
        drop(self.gates.remove(0));
        drop(self.buyers.remove(0));
        drop(self.sellers.remove(0));
        tokio::time::timeout(Duration::from_secs(5), async {
            while old_node.upgrade().is_some()
                || old_buyer.upgrade().is_some()
                || old_seller.upgrade().is_some()
                || old_controller.upgrade().is_some()
                || old_wallet_control.upgrade().is_some()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all old source runtime and accounting owners released");

        let buyer = Arc::new(BuyerAuthorizer::load(&self.root.path().join("buyer-0")).unwrap());
        let seller = Arc::new(DurableRelay::load(&self.root.path().join("seller-0")).unwrap());
        let (node, gate, incoming) = control::endpoint(config, buyer.clone(), seller.clone()).await;
        let admission = ControlAdmission::new(
            node.clone(),
            neighbors,
            None,
            NeighborAdmission::ConfiguredOnly,
        )
        .unwrap();
        let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
            &self.root.path().join("receiver-0"),
            FileSpilmanPaymentReceiverConfig::new([quote_policy.mint_url.clone()]),
        )
        .await
        .unwrap();
        let controls = control::Setup {
            index: 0,
            node: node.clone(),
            buyer: buyer.clone(),
            seller: seller.clone(),
            wallet: self.wallets[0].clone(),
            receiver,
            admission: admission.clone(),
            quote_policy,
            selection: Some(PriceSelectionPolicy::default()),
        }
        .start()
        .await;
        let controller = Arc::new(
            Controller::load(
                &self.root.path().join("controller-0"),
                self.controller_policy.clone(),
                controls.service.clone(),
            )
            .unwrap(),
        );
        self.nodes.insert(0, node);
        self.buyers.insert(0, buyer);
        self.sellers.insert(0, seller);
        self.gates.insert(0, gate);
        self.receivers.insert(0, incoming);
        self.controllers.insert(0, controller.clone());
        self.services.insert(0, controls.service);
        self.quote_servers.insert(0, controls.quote_server);
        self.payment_servers.insert(0, controls.payment_server);
        self.quote_inputs.insert(0, controls.quote_input);
        self.admissions.insert(0, admission);
        controls.incoming
    }
}
