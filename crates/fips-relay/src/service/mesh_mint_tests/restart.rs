//! Restart the real mint process and SQLite store, never reissue test funding.
//! Lightning state is deliberately not resumed: after initial issuance this
//! closed-loop fixture exercises only proof swaps, checks and restoration.
use super::*;
use std::{net::SocketAddr, process::Stdio};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const WORKER: &str = "service::mesh_mint_tests::restart::mint_worker";
const SPEC: &str = "FIPS_TEST_MINT_WORKER";
const PREFIX: &str = "MINT_WORKER ";

struct Session {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Session {
    async fn start(root: &Path, address: SocketAddr, generation: u32) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", WORKER, "--nocapture", "--test-threads=1"])
            .env(
                SPEC,
                json!({"root": root, "address": address, "generation": generation}).to_string(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        Self {
            input: child.stdin.take().unwrap(),
            output: BufReader::new(child.stdout.take().unwrap()),
            child,
        }
    }

    async fn response(&mut self) -> Value {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let mut line = String::new();
                assert!(
                    self.output.read_line(&mut line).await.unwrap() > 0,
                    "mint worker exited"
                );
                if let Some((_, value)) = line.split_once(PREFIX) {
                    return serde_json::from_str(value).unwrap();
                }
            }
        })
        .await
        .expect("mint worker response deadline")
    }

    async fn request(&mut self, value: Value) -> Value {
        let bytes = format!("{value}\n");
        self.input.write_all(bytes.as_bytes()).await.unwrap();
        self.input.flush().await.unwrap();
        self.response().await
    }
}

pub(super) struct ProcessMint {
    root: PathBuf,
    address: SocketAddr,
    identity: Value,
    generation: u32,
    session: Option<Session>,
    pub(super) proxy: MintProxy,
}

impl ProcessMint {
    pub(super) async fn start(root: &Path) -> Self {
        let root = root.join("mint-process");
        assert!(!root.exists());
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut session = Session::start(&root, address, 0).await;
        let identity = session.response().await;
        assert!(identity["keyset"].is_string());
        assert!(Path::new(identity["database"].as_str().unwrap()).is_file());
        let proxy = MintProxy::start(&format!("http://{address}")).await;
        Self {
            root,
            address,
            identity,
            generation: 0,
            session: Some(session),
            proxy,
        }
    }

    pub(super) async fn fund(&mut self, payment_request: &str) {
        assert_eq!(self.generation, 0, "restart must never replace funding");
        let response = self
            .session
            .as_mut()
            .unwrap()
            .request(json!({"fund": payment_request}))
            .await;
        assert_eq!(response["external_funding_sat"], 16);
    }

    pub(super) async fn crash(&mut self) {
        use std::os::unix::process::ExitStatusExt;
        let mut session = self.session.take().unwrap();
        let report = session.request(json!({"report": true})).await;
        assert_eq!(
            report["external_funding_sat"],
            if self.generation == 0 { 16 } else { 0 }
        );
        session.child.start_kill().unwrap();
        let status = tokio::time::timeout(Duration::from_secs(5), session.child.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.signal(), Some(9));
        assert!(TcpStream::connect(self.address).await.is_err());
        eprintln!(
            "mesh mint: generation {} killed after commitment",
            self.generation
        );
    }

    pub(super) async fn reopen(&mut self) {
        assert!(self.session.is_none());
        self.generation += 1;
        let mut session = Session::start(&self.root, self.address, self.generation).await;
        assert_eq!(
            session.response().await,
            self.identity,
            "original database and keyset must survive"
        );
        self.session = Some(session);
        eprintln!(
            "mesh mint: generation {} reopened original database and keys",
            self.generation
        );
    }

    pub(super) async fn shutdown(mut self) {
        assert_eq!(
            self.generation, 2,
            "funding and close must both cross a mint restart"
        );
        let mut session = self.session.take().unwrap();
        let report = session.request(json!({"stop": true})).await;
        assert_eq!(report["external_funding_sat"], 0);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), session.child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
}

fn reply(value: Value) {
    use std::io::Write;
    let mut output = std::io::stdout().lock();
    writeln!(output, "{PREFIX}{value}").unwrap();
    output.flush().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mint_worker() {
    use std::io::BufRead;
    let Ok(spec) = std::env::var(SPEC) else {
        return;
    };
    let spec: Value = serde_json::from_str(&spec).unwrap();
    let root = Path::new(spec["root"].as_str().unwrap());
    let generation = spec["generation"].as_u64().unwrap();
    assert_eq!(root.join("mints").exists(), generation > 0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let network = PaymentNetwork::new(317, 0, Arc::new(VirtualClock::new(now)));
    let mint = LocalMint::start(root, network.clone(), "mesh-mint", IssuerMode::ClosedLoop)
        .await
        .unwrap();
    let backend = mint.url().strip_prefix("http://").unwrap().parse().unwrap();
    let listener = TcpListener::bind(spec["address"].as_str().unwrap())
        .await
        .unwrap();
    let proxy = crate::testbench::proxy::spawn(listener, backend);
    reply(
        json!({"database": mint.database_path(), "keyset": mint.active_sat_keyset().unwrap().to_string()}),
    );
    let mut funded = false;
    for line in std::io::stdin().lock().lines() {
        let command: Value = serde_json::from_str(&line.unwrap()).unwrap();
        if let Some(invoice) = command["fund"].as_str() {
            assert_eq!(generation, 0, "no new simulated funding after restart");
            assert!(!funded, "one original grant only");
            network
                .orchestrator_funding()
                .settle_external(invoice)
                .unwrap();
            funded = true;
        }
        let accounting = network.accounting().unwrap();
        assert!(accounting.is_conserved());
        reply(json!({"external_funding_sat": accounting.external_funding_sat}));
        if command["stop"] == true {
            break;
        }
    }
    proxy.abort();
    assert!(proxy.await.unwrap_err().is_cancelled());
}
