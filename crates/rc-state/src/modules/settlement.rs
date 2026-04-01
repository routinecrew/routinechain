use rc_store::Store;
use rc_types::*;
use super::token;

pub fn record(
    store: &Store,
    sender: &Id,
    participant_id: &Id,
    data: &SettlementData,
    timestamp: i64,
    reward_amount: u64,
) -> Result<Vec<Event>, String> {
    // Authorization: sender must be the participant recording their own settlement
    if sender != participant_id {
        return Err("Unauthorized: sender must match participant id".to_string());
    }

    let mut p = store
        .get_participant(participant_id)?
        .ok_or("Participant not found")?;

    // Save settlement record
    let record = SettlementRecord {
        record_id: data.record_id,
        participant_id: *participant_id,
        gross_amount: data.gross_amount,
        platform_fee: data.platform_fee,
        net_amount: data.net_amount,
        currency: data.currency,
        settled_at: data.settled_at,
        recorded_at: timestamp,
    };
    store.set_settlement(&data.record_id, &record)?;

    // Update participant stats (saturating arithmetic to prevent overflow)
    p.total_tx = p.total_tx.saturating_add(1);
    p.success_tx = p.success_tx.saturating_add(1);
    p.total_volume = p.total_volume.saturating_add(data.gross_amount);
    p.total_settled = p.total_settled.saturating_add(data.net_amount);
    p.last_activity_at = timestamp;
    store.set_participant(participant_id, &p)?;

    // Mint RCW reward
    let mut events = vec![Event::SettlementRecorded {
        participant_id: *participant_id,
        record_id: data.record_id,
    }];

    if reward_amount > 0 {
        let reward_events = token::mint(store, participant_id, reward_amount, "settlement_reward")?;
        events.extend(reward_events);
    }

    Ok(events)
}

pub fn record_rating(
    store: &Store,
    participant_id: &Id,
    rating: u16,
    success: bool,
    timestamp: i64,
    reward_amount: u64,
) -> Result<Vec<Event>, String> {
    let mut p = store
        .get_participant(participant_id)?
        .ok_or("Participant not found")?;

    // Update rating
    if rating > 0 && rating <= 500 {
        p.rating_sum += rating as u64;
        p.rating_count += 1;
    }

    // Update success count
    if !success {
        p.total_tx += 1;
        // success_tx not incremented = failure recorded
    }

    p.last_activity_at = timestamp;
    store.set_participant(participant_id, &p)?;

    let new_score = compute_trust_score(&p);

    let mut events = vec![Event::RatingRecorded {
        participant_id: *participant_id,
        new_score,
    }];

    // Reward for submitting rating
    if reward_amount > 0 {
        let reward_events = token::mint(store, participant_id, reward_amount, "rating_reward")?;
        events.extend(reward_events);
    }

    Ok(events)
}
