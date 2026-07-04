use fips_sim::run_default_wot_admission_sim;

fn main() {
    let report = run_default_wot_admission_sim();
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report serializes")
    );
}
