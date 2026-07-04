use fips_sim::run_default_wot_admission_sim;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let report = run_default_wot_admission_sim().await;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report serializes")
    );
}
