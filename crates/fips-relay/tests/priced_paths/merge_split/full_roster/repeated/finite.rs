//! Measure short contacts separately from sustained paid recovery.
use super::super::super::super::brief;
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crowded_finite_contacts_preserve_authority_and_recover_paid_routes() {
    run(EncounterProfile {
        seed: 139,
        finite_contacts: true,
        ..EncounterProfile::baseline(false)
    })
    .await;
}

pub(super) async fn contacts(
    bench: &Bench,
    anchor: &[Account],
    warm: bool,
) -> brief::ContactResult {
    let original = bridge_epochs(bench).await;
    assert_eq!(original.is_some(), warm);
    let cohort = brief::contact_cohort(bench, warm, None);
    tokio::pin!(cohort);
    let result = loop {
        tokio::select! {
            result = &mut cohort => break result,
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                retain(anchor, &accounts(bench).await, true);
                assert_watches(bench).await;
                if warm {
                    assert_eq!(bridge_epochs(bench).await, original,
                        "short warm cuts must retain the original authenticated owners");
                }
            }
        }
    };
    retain(anchor, &accounts(bench).await, true);
    assert_watches(bench).await;
    if warm {
        assert_eq!(bridge_epochs(bench).await, original);
        result.assert_carrier_interrupted();
    }
    let contacts = result.validate_offers();
    let mut offered = 0;
    let mut before_cut = 0;
    let mut after_cut = 0;
    let mut unobserved = 0;
    for contact in contacts {
        assert_eq!(contact.warm, warm);
        assert_eq!(
            contact.offered_ids.len(),
            contact.received_before_cut.len()
                + contact.received_after_cut.len()
                + contact.unobserved_at_deadline.len(),
            "every fresh in-window offer must have exactly one outcome"
        );
        offered += contact.offered_ids.len();
        before_cut += contact.received_before_cut.len();
        after_cut += contact.received_after_cut.len();
        unobserved += contact.unobserved_at_deadline.len();
    }
    eprintln!(
        "crowded finite contacts: {}",
        serde_json::json!({
            "warm": warm, "direction_windows": contacts.len(),
            "offered": offered, "received_before_cut": before_cut,
            "received_after_cut": after_cut, "unobserved_at_deadline": unobserved,
            "final_opening_elapsed_ms": result.last_up().elapsed().as_millis(),
        })
    );
    result
}
