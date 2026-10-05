//! One local test barrier around the SDK's real committed mint response.
use cashu_service::simulation::MintProxy;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use tokio::sync::oneshot;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum FaultAction {
    ArmSwapReply,
    Status,
    Release { generation: u64 },
}

struct Gate {
    reached: oneshot::Receiver<()>,
    release: Option<oneshot::Sender<()>>,
    held: bool,
}

impl Drop for Gate {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

pub(super) struct MintFaults {
    proxy: MintProxy,
    generation: u64,
    gate: Option<Gate>,
}

impl MintFaults {
    pub(super) async fn start(upstream: &str) -> Self {
        Self {
            proxy: MintProxy::start(upstream).await,
            generation: 0,
            gate: None,
        }
    }

    pub(super) fn url(&self) -> &str {
        &self.proxy.url
    }

    pub(super) fn active(&self) -> bool {
        self.gate
            .as_ref()
            .is_some_and(|gate| gate.release.is_some())
    }

    pub(super) fn request(&mut self, action: FaultAction) -> Result<Value, String> {
        if let Some(gate) = &mut self.gate
            && !gate.held
        {
            match gate.reached.try_recv() {
                Ok(()) => gate.held = true,
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    return Err("mint response barrier disappeared".into());
                }
            }
        }
        match action {
            FaultAction::ArmSwapReply => {
                if self.active() {
                    return Err("a mint response barrier is already armed".into());
                }
                self.generation = self.generation.checked_add(1).ok_or("barrier limit")?;
                let (reached, release) = self.proxy.state.pause_next_swap_reply();
                self.gate = Some(Gate {
                    reached,
                    release: Some(release),
                    held: false,
                });
            }
            FaultAction::Release { generation } => {
                if generation != self.generation {
                    return Err("mint response barrier generation differs".into());
                }
                let gate = self.gate.as_mut().ok_or("no mint response barrier")?;
                if !gate.held {
                    return Err("mint response has not reached its barrier".into());
                }
                if let Some(release) = gate.release.take() {
                    // A disconnected HTTP client may already have cancelled
                    // its waiter. The mint's committed result remains durable.
                    let _ = release.send(());
                }
            }
            FaultAction::Status => {}
        }
        let phase = match &self.gate {
            None => "idle",
            Some(gate) if gate.release.is_none() => "released",
            Some(gate) if gate.held => "held",
            Some(_) => "armed",
        };
        Ok(json!({
            "generation": self.generation, "phase": phase,
            "swap_attempts": self.proxy.state.swap_attempts.load(Ordering::SeqCst),
            "swaps": self.proxy.state.swaps.load(Ordering::SeqCst),
            "restores": self.proxy.state.restores.load(Ordering::SeqCst),
        }))
    }
}
