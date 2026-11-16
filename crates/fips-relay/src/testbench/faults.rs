//! One local test barrier around the SDK's real committed mint response.
use cashu_service::simulation::MintProxy;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::atomic::Ordering};
use tokio::sync::oneshot;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum FaultAction {
    ArmSwapReply {
        /// SHA-256 commitments to input secrets select one channel without exposing them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_hashes: Option<Vec<String>>,
    },
    Status,
    Release {
        generation: u64,
    },
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
            FaultAction::ArmSwapReply { input_hashes } => {
                if self.active() {
                    return Err("a mint response barrier is already armed".into());
                }
                let inputs = input_hashes.map(selected_inputs).transpose()?;
                self.generation = self.generation.checked_add(1).ok_or("barrier limit")?;
                let (reached, release) = self.proxy.state.pause_matching_swap_reply(move |swap| {
                    inputs.as_ref().is_none_or(|expected| {
                        swap.inputs().len() == expected.len()
                            && swap.inputs().iter().all(|proof| {
                                expected.contains(&format!(
                                    "{:x}",
                                    Sha256::digest(proof.secret.as_bytes())
                                ))
                            })
                    })
                });
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

fn selected_inputs(inputs: Vec<String>) -> Result<BTreeSet<String>, String> {
    if inputs.is_empty() || inputs.len() > 128 {
        return Err("mint barrier requires 1..=128 distinct input identifiers".into());
    }
    let mut selected = BTreeSet::new();
    for input in inputs {
        if input.len() != 64
            || !input
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !selected.insert(input)
        {
            return Err("invalid or duplicate mint barrier input identifier".into());
        }
    }
    Ok(selected)
}
