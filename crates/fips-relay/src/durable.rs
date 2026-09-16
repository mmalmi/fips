//! Durable, bounded forwarding windows. Disk I/O stays off the node loop.
//!
//! A controller checkpoints submissions before asking for payment. Before
//! admission resumes, it also records the maximum exposure of the next window.
//! Recovery consumes the entire unrecorded remainder without billing it.

use crate::ledger::{
    ChannelTerms, ChannelUsage, Contract, LedgerError, Limits, RelayLedger, Snapshot, Usage,
};
use fips_core::node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Mutex, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const MAX_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum DurableError {
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error("accounting journal I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("accounting journal format is invalid")]
    Format,
    #[error("accounting journal already has an owner or is initialized")]
    InUse,
    #[error("accounting writer is suspended; restart and recover its journal")]
    Suspended,
}

#[derive(Debug, Serialize, Deserialize)]
struct Journal {
    version: u16,
    window_msat: u64,
    ledger: Snapshot,
    ceilings: BTreeMap<String, u64>,
}

#[derive(Debug, Default)]
struct PublishedWindows {
    ceilings: BTreeMap<String, u64>,
    reserved_at_checkpoint: BTreeMap<String, u64>,
    ready: bool,
}

/// Single controller ownership is enforced by an OS file lock. Public mutation
/// methods perform synchronous disk I/O: call them from a controller worker,
/// never from a `ForwardingPolicy` callback. Numeric credit methods accept only
/// the output of a trusted payment verifier, not unverified network requests.
#[derive(Debug)]
pub struct DurableRelay {
    ledger: RelayLedger,
    directory: PathBuf,
    window_msat: u64,
    windows: RwLock<PublishedWindows>,
    writer: Mutex<()>,
    _owner: File,
}

impl DurableRelay {
    pub fn create(
        directory: &Path,
        limits: Limits,
        window_msat: u64,
    ) -> Result<Self, DurableError> {
        if window_msat == 0 {
            return Err(DurableError::Format);
        }
        let owner = acquire_owner(directory)?;
        if directory.join("ledger.json").try_exists()? {
            return Err(DurableError::InUse);
        }
        let relay = Self {
            ledger: RelayLedger::new(limits),
            directory: directory.to_path_buf(),
            window_msat,
            windows: RwLock::new(PublishedWindows::default()),
            writer: Mutex::new(()),
            _owner: owner,
        };
        relay.initialize()?;
        Ok(relay)
    }

    pub fn load(directory: &Path) -> Result<Self, DurableError> {
        let owner = acquire_owner(directory)?;
        let file = File::open(directory.join("ledger.json"))?;
        if file.metadata()?.len() > MAX_JOURNAL_BYTES {
            return Err(DurableError::Format);
        }
        let mut bytes = Vec::new();
        file.take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(DurableError::Format);
        }
        let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| DurableError::Format)?;
        if journal.version != 1 || journal.window_msat == 0 {
            return Err(DurableError::Format);
        }
        let relay = Self {
            ledger: RelayLedger::recover_windows(journal.ledger, &journal.ceilings)?,
            directory: directory.to_path_buf(),
            window_msat: journal.window_msat,
            windows: RwLock::new(PublishedWindows::default()),
            writer: Mutex::new(()),
            _owner: owner,
        };
        // Persist lost exposure and the next window before anyone can send.
        relay.initialize()?;
        Ok(relay)
    }

    fn initialize(&self) -> Result<(), DurableError> {
        let _writer = self.writer.lock().map_err(|_| DurableError::Suspended)?;
        self.persist(true)?;
        Ok(())
    }

    /// Return only the totals captured in this durable checkpoint. A completion
    /// racing with disk I/O belongs to a later checkpoint, not this claim.
    pub fn checkpoint(&self) -> Result<BTreeMap<String, ChannelUsage>, DurableError> {
        self.mutate(|_| Ok(())).map(|(_, usage)| usage)
    }

    /// A local checkpoint can advance a consumed durable window independently
    /// of payment cadence. Unchanged/credit-exhausted windows do not cause idle
    /// writes. This is only a scheduling hint; `checkpoint` revalidates bounds.
    pub fn checkpoint_due(&self) -> Result<bool, DurableError> {
        let windows = self.windows.read().map_err(|_| DurableError::Suspended)?;
        if !windows.ready {
            return Err(DurableError::Suspended);
        }
        for (id, ceiling) in &windows.ceilings {
            let usage = self.ledger.channel_usage(id).ok_or(DurableError::Format)?;
            let recorded = windows.reserved_at_checkpoint.get(id).copied().unwrap_or(0);
            if usage.reserved_msat > recorded
                && ceiling.saturating_sub(usage.reserved_msat) <= self.window_msat / 2
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Stop admission and checkpoint without granting another window. After
    /// stopping the endpoint, use this for an orderly restart of the same
    /// channels/quotes. Pending sends remain reserved if completion is unknown.
    pub fn suspend(&self) -> Result<BTreeMap<String, ChannelUsage>, DurableError> {
        let _writer = self.writer.lock().map_err(|_| DurableError::Suspended)?;
        {
            let mut windows = self.windows.write().map_err(|_| DurableError::Suspended)?;
            if !windows.ready {
                return Err(DurableError::Suspended);
            }
            windows.ready = false;
        }
        self.persist(false)
    }

    pub fn open_channel_verified(
        &self,
        terms: ChannelTerms,
        paid_msat: u64,
    ) -> Result<(), DurableError> {
        self.mutate(|l| l.open_channel_verified(terms, paid_msat))
            .map(|_| ())
    }

    pub fn add_contract(&self, contract: Contract) -> Result<(), DurableError> {
        self.mutate(|l| l.add_contract(contract)).map(|_| ())
    }

    pub fn apply_verified_balance(&self, id: &str, paid_msat: u64) -> Result<(), DurableError> {
        self.mutate(|l| l.apply_verified_balance(id, paid_msat))
            .map(|_| ())
    }

    pub fn close_contract(&self, id: &str) -> Result<Usage, DurableError> {
        self.mutate(|l| l.close_contract(id))
            .map(|(usage, _)| usage)
    }

    pub fn close_channel(&self, id: &str) -> Result<ChannelUsage, DurableError> {
        self.mutate(|l| l.close_channel(id)).map(|(usage, _)| usage)
    }

    pub fn seal_channel(&self, id: &str) -> Result<ChannelUsage, DurableError> {
        self.mutate(|l| l.seal_channel(id)).map(|(usage, _)| usage)
    }

    /// Live metrics are not a payment claim. Use `checkpoint` for that.
    pub fn channel_usage(&self, id: &str) -> Option<ChannelUsage> {
        self.ledger.channel_usage(id)
    }

    pub fn usage(&self, id: &str) -> Option<Usage> {
        self.ledger.usage(id)
    }

    pub fn channel_terms(&self, id: &str) -> Option<ChannelTerms> {
        self.ledger.channel_terms(id)
    }

    pub fn contract(&self, id: &str) -> Option<Contract> {
        self.ledger.contract(id)
    }

    pub(crate) fn has_active_route(
        &self,
        buyer: fips_core::NodeAddr,
        destination: fips_core::NodeAddr,
        now: u64,
    ) -> bool {
        self.ledger.has_active_route(buyer, destination, now)
    }

    fn mutate<T>(
        &self,
        change: impl FnOnce(&RelayLedger) -> Result<T, LedgerError>,
    ) -> Result<(T, BTreeMap<String, ChannelUsage>), DurableError> {
        let _writer = self.writer.lock().map_err(|_| DurableError::Suspended)?;
        if !self
            .windows
            .read()
            .map_err(|_| DurableError::Suspended)?
            .ready
        {
            return Err(DurableError::Suspended);
        }
        let result = change(&self.ledger)?;
        let usage = self.persist(true)?;
        Ok((result, usage))
    }

    fn persist(
        &self,
        allow_next_window: bool,
    ) -> Result<BTreeMap<String, ChannelUsage>, DurableError> {
        let result = self.persist_next(allow_next_window);
        if result.is_err() {
            self.windows
                .write()
                .map_err(|_| DurableError::Suspended)?
                .ready = false;
        }
        result
    }

    fn persist_next(
        &self,
        allow_next_window: bool,
    ) -> Result<BTreeMap<String, ChannelUsage>, DurableError> {
        // Any failure leaves admission suspended, even if rename succeeded but
        // the final directory sync failed. Recovery resolves the durable state.
        // Admissions continue against their PREVIOUSLY durable ceiling during
        // fsync. The next journal covers that whole ceiling as well as its new
        // window, so racing submissions remain bounded even after a crash.
        let previous = self
            .windows
            .read()
            .map_err(|_| DurableError::Suspended)?
            .ceilings
            .clone();
        let ledger = self.ledger.snapshot();
        let mut ceilings = BTreeMap::new();
        let mut usage = BTreeMap::new();
        for channel in &ledger.channels {
            usage.insert(channel.terms.id.clone(), channel.usage);
            if channel.active
                && ledger
                    .accounts
                    .iter()
                    .any(|a| a.active && a.contract.channel_id == channel.terms.id)
            {
                let maximum = ledger
                    .reservation_limit(&channel.terms.id)
                    .ok_or(DurableError::Format)?;
                let window = if allow_next_window {
                    self.window_msat
                } else {
                    0
                };
                let mut ceiling = channel
                    .usage
                    .reserved_msat
                    .saturating_add(window)
                    .min(maximum);
                if allow_next_window {
                    ceiling = ceiling.max(previous.get(&channel.terms.id).copied().unwrap_or(0));
                    if ceiling > maximum {
                        return Err(DurableError::Format);
                    }
                }
                ceilings.insert(channel.terms.id.clone(), ceiling);
            }
        }
        let journal = Journal {
            version: 1,
            window_msat: self.window_msat,
            ledger,
            ceilings: ceilings.clone(),
        };
        let bytes = serde_json::to_vec(&journal).map_err(|_| DurableError::Format)?;
        write_private_journal(&self.directory, "ledger.json", &bytes)?;
        let mut published = self.windows.write().map_err(|_| DurableError::Suspended)?;
        published.reserved_at_checkpoint = usage
            .iter()
            .map(|(id, u)| (id.clone(), u.reserved_msat))
            .collect();
        published.ceilings = ceilings;
        published.ready = allow_next_window;
        Ok(usage)
    }
}

impl ForwardingPolicy for DurableRelay {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        // Never wait for the disk-writing controller on the native node loop.
        let windows = self.windows.read().ok()?;
        if !windows.ready {
            return None;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        self.ledger
            .admit_with_windows(request, now, Some(&windows.ceilings))
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        // Completion never needs the controller gate. A pending outcome captured
        // before this completion remains conservatively unconfirmed on recovery.
        self.ledger.complete(token, outcome);
    }
}

pub(crate) fn write_private_journal(
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), DurableError> {
    use crate::measurements::{JournalEvent, journal};
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(DurableError::Format);
    }
    let mut pending = tempfile::NamedTempFile::new_in(directory)?;
    pending.write_all(bytes)?;
    journal(JournalEvent::Written(bytes.len()));
    pending.as_file().sync_all()?;
    journal(JournalEvent::Synced);
    pending
        .persist(directory.join(name))
        .map_err(|e| DurableError::Io(e.error))?;
    File::open(directory)?.sync_all()?;
    journal(JournalEvent::Synced);
    journal(JournalEvent::Committed);
    Ok(())
}

pub(crate) fn acquire_owner(directory: &Path) -> Result<File, DurableError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        builder.mode(0o700);
        options.mode(0o600);
        builder.create(directory)?;
        if std::fs::metadata(directory)?.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "accounting directory must be private",
            )
            .into());
        }
    }
    #[cfg(not(unix))]
    builder.create(directory)?;
    let owner = options.open(directory.join("owner.lock"))?;
    // Rust 1.94's std File::try_lock excludes Android. fs2 uses the same OS
    // lock on our desktop/router targets and also supports the phone target.
    fs2::FileExt::try_lock_exclusive(&owner).map_err(|error| {
        if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
            DurableError::InUse
        } else {
            DurableError::Io(error)
        }
    })?;
    Ok(owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips_core::{Identity, NodeAddr, PeerIdentity};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    #[test]
    fn node_callbacks_do_not_wait_for_a_checkpoint_writer() {
        let root = tempfile::tempdir().unwrap();
        let relay = Arc::new(
            DurableRelay::create(&root.path().join("relay"), Limits::default(), 10).unwrap(),
        );
        let identity = Identity::from_secret_bytes(&[1; 32]).unwrap();
        let terms = ChannelTerms {
            id: "channel".into(),
            buyer: *identity.node_addr(),
            mint_url: "http://test.invalid".into(),
            expires_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 600,
            capacity_sat: 1,
            grace_msat: 100,
        };
        relay.open_channel_verified(terms.clone(), 0).unwrap();
        relay
            .add_contract(Contract {
                billing: Default::default(),
                id: "quote".into(),
                channel_id: terms.id,
                destination: NodeAddr::from_bytes([2; 16]),
                next_hop: NodeAddr::from_bytes([3; 16]),
                expires_unix: terms.expires_unix,
                price: crate::ledger::BytePrice {
                    msat: 1,
                    per_bytes: 1,
                },
                max_units: 100,
            })
            .unwrap();
        let gate = relay.writer.lock().unwrap();
        let worker = Arc::clone(&relay);
        let (sent, received) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let identity = Identity::from_secret_bytes(&[1; 32]).unwrap();
            let request = ForwardingRequest {
                ingress: PeerIdentity::from_pubkey_full(identity.pubkey_full()),
                source: NodeAddr::from_bytes([1; 16]),
                destination: NodeAddr::from_bytes([2; 16]),
                next_hop: NodeAddr::from_bytes([3; 16]),
                session_payload: b"packet",
            };
            let token = worker
                .admit(&request)
                .expect("previous durable window stays usable during the writer's work");
            worker.complete(token, ForwardingOutcome::Submitted);
            assert_eq!(worker.channel_usage("channel").unwrap().submitted_msat, 6);
            sent.send(()).unwrap();
        });
        let result = received.recv_timeout(Duration::from_secs(1));
        drop(gate);
        thread.join().unwrap();
        result.expect("callbacks must return while the controller owns the disk gate");
    }
}
