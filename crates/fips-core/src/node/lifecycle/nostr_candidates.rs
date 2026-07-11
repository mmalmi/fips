fn order_open_discovery_candidates(
    candidates: Vec<OpenDiscoveryCandidate>,
    trust_scores: &std::collections::HashMap<String, i64>,
    enqueue_budget: usize,
    newcomer_probe_slots: usize,
) -> Vec<OpenDiscoveryCandidate> {
    if candidates.len() <= 1 || enqueue_budget == 0 {
        return candidates;
    }

    let mut positive = Vec::new();
    let mut unknown = Vec::new();
    let mut negative = Vec::new();
    for candidate in candidates {
        match trust_scores.get(&candidate.0).copied() {
            Some(score) if score > 0 => positive.push((score, candidate)),
            Some(score) if score < 0 => negative.push((score, candidate)),
            _ => unknown.push(candidate),
        }
    }

    positive.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| left.0.cmp(&right.0))
    });
    unknown.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0)));
    negative.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| left.0.cmp(&right.0))
    });

    let reserved_newcomers = newcomer_probe_slots.min(enqueue_budget).min(unknown.len());
    let trusted_slots = enqueue_budget.saturating_sub(reserved_newcomers);

    let mut ordered = Vec::new();
    let mut positive = positive.into_iter();
    for _ in 0..trusted_slots {
        let Some((_, candidate)) = positive.next() else {
            break;
        };
        ordered.push(candidate);
    }
    let mut unknown = unknown.into_iter();
    for _ in 0..reserved_newcomers {
        let Some(candidate) = unknown.next() else {
            break;
        };
        ordered.push(candidate);
    }
    ordered.extend(positive.map(|(_, candidate)| candidate));
    ordered.extend(unknown);
    ordered.extend(negative.into_iter().map(|(_, candidate)| candidate));
    ordered
}
