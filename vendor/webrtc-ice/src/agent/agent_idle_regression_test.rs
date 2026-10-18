use std::sync::Arc;
use std::time::Duration;

use stun::textattrs::Username;
use tokio::net::UdpSocket;

use super::*;
use crate::candidate::candidate_base::CandidateBaseConfig;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::control::AttrControlling;
use crate::priority::PriorityAttr;
use crate::use_candidate::UseCandidateAttr;

struct Fixture {
    agent: Agent,
    local: Arc<dyn Candidate + Send + Sync>,
    peer: UdpSocket,
    remote_password: String,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let agent = Agent::new(AgentConfig {
            keepalive_interval: Some(Duration::from_millis(10)),
            ..Default::default()
        })
        .await?;
        let remote_password = "remote-test-password".to_owned();
        agent
            .internal
            .set_remote_credentials("remote-test".to_owned(), remote_password.clone())
            .await?;
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let local: Arc<dyn Candidate + Send + Sync> = Arc::new(
            CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network: "udp".to_owned(),
                    address: "127.0.0.1".to_owned(),
                    port: socket.local_addr()?.port(),
                    component: 1,
                    conn: Some(socket),
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()?,
        );
        Ok(Self {
            agent,
            local,
            peer: UdpSocket::bind("127.0.0.1:0").await?,
            remote_password,
        })
    }

    async fn request(&self, nominate: bool) -> Result<TransactionId> {
        let (username, password) = {
            let credentials = self.agent.internal.ufrag_pwd.lock().await;
            (
                format!("{}:{}", credentials.local_ufrag, credentials.remote_ufrag),
                credentials.local_pwd.clone(),
            )
        };
        let transaction = TransactionId::new();
        let mut attributes: Vec<Box<dyn Setter>> = vec![
            Box::new(BINDING_REQUEST),
            Box::new(transaction),
            Box::new(Username::new(ATTR_USERNAME, username)),
            Box::new(AttrControlling(123)),
            Box::new(PriorityAttr(self.local.priority())),
        ];
        if nominate {
            attributes.push(Box::new(UseCandidateAttr::new()));
        }
        attributes.push(Box::new(MessageIntegrity::new_short_term_integrity(
            password,
        )));
        attributes.push(Box::new(FINGERPRINT));
        let mut message = Message::new();
        message.build(&attributes)?;
        self.agent
            .internal
            .handle_inbound(&mut message, &self.local, self.peer.local_addr()?)
            .await;
        Ok(transaction)
    }

    async fn receive(&self) -> Result<Message> {
        let mut buffer = [0; 1500];
        let (size, _) =
            tokio::time::timeout(Duration::from_secs(1), self.peer.recv_from(&mut buffer))
                .await
                .expect("STUN output should arrive promptly")?;
        let mut message = Message::new();
        message.raw = buffer[..size].to_vec();
        message.decode()?;
        Ok(message)
    }

    async fn complete_check(&self, request: &Message) -> Result<()> {
        assert_eq!(request.typ, BINDING_REQUEST);
        let mut response = Message::new();
        response.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(request.transaction_id),
            Box::new(MessageIntegrity::new_short_term_integrity(
                self.remote_password.clone(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        self.agent
            .internal
            .handle_inbound(&mut response, &self.local, self.peer.local_addr()?)
            .await;
        Ok(())
    }
}

#[tokio::test]
async fn succeeded_pair_answers_consent_without_restarting_connectivity_checks() -> Result<()> {
    let fixture = Fixture::new().await?;
    let transaction = fixture.request(false).await?;
    let response = fixture.receive().await?;
    assert_eq!(response.typ, BINDING_SUCCESS);
    assert_eq!(response.transaction_id, transaction);
    let initial_check = fixture.receive().await?;
    fixture.complete_check(&initial_check).await?;
    assert!(fixture
        .agent
        .internal
        .pending_binding_requests
        .lock()
        .await
        .is_empty());

    // The first request nominates the already validated pair. Further requests
    // are consent/keepalive checks and still require successful STUN responses.
    for index in 0..4 {
        let transaction = fixture.request(index == 0).await?;
        let response = fixture.receive().await?;
        assert_eq!(response.typ, BINDING_SUCCESS);
        assert_eq!(response.transaction_id, transaction);
        assert!(fixture
            .agent
            .internal
            .agent_conn
            .get_selected_pair()
            .is_some());
        assert!(
            fixture
                .agent
                .internal
                .pending_binding_requests
                .lock()
                .await
                .is_empty(),
            "A succeeded pair must not start another check for each incoming consent request"
        );
    }
    fixture.agent.close().await?;
    Ok(())
}

#[tokio::test]
async fn unvalidated_nomination_still_checks_and_selects_on_success() -> Result<()> {
    let fixture = Fixture::new().await?;
    let transaction = fixture.request(true).await?;
    let response = fixture.receive().await?;
    assert_eq!(response.typ, BINDING_SUCCESS);
    assert_eq!(response.transaction_id, transaction);
    assert!(fixture
        .agent
        .internal
        .agent_conn
        .get_selected_pair()
        .is_none());
    let initial_check = fixture.receive().await?;
    fixture.complete_check(&initial_check).await?;
    assert!(fixture
        .agent
        .internal
        .agent_conn
        .get_selected_pair()
        .is_some());
    fixture.agent.close().await?;
    Ok(())
}

#[tokio::test]
async fn succeeded_pair_still_sends_periodic_consent_checks() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.request(true).await?;
    assert_eq!(fixture.receive().await?.typ, BINDING_SUCCESS);
    let initial_check = fixture.receive().await?;
    fixture.complete_check(&initial_check).await?;
    assert!(fixture
        .agent
        .internal
        .agent_conn
        .get_selected_pair()
        .is_some());
    tokio::time::sleep(Duration::from_millis(20)).await;
    fixture.agent.internal.check_keepalive().await;
    let consent_check = fixture.receive().await?;
    assert_ne!(consent_check.transaction_id, initial_check.transaction_id);
    fixture.complete_check(&consent_check).await?;
    assert!(fixture
        .agent
        .internal
        .pending_binding_requests
        .lock()
        .await
        .is_empty());
    fixture.agent.close().await?;
    Ok(())
}
