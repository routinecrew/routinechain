use rc_store::Store;
use rc_types::*;
use super::token;

pub fn raise(
    store: &Store,
    dispute_id: &Id,
    escrow_id: &Id,
    raised_by: &Id,
    reason: DisputeReason,
    evidence_hash: &[u8; 32],
    timestamp: i64,
) -> Result<Vec<Event>, String> {
    // Verify escrow exists and is active
    let mut escrow = store.get_escrow(escrow_id)?.ok_or("Escrow not found")?;

    // Authorization: only buyer or seller of the escrow can raise a dispute
    if raised_by != &escrow.buyer && raised_by != &escrow.seller {
        return Err("Unauthorized: only escrow buyer or seller can raise dispute".to_string());
    }

    if escrow.state == EscrowState::Released || escrow.state == EscrowState::Refunded {
        return Err("Escrow already settled".to_string());
    }

    // Mark escrow as disputed
    escrow.state = EscrowState::Disputed;
    escrow.dispute_id = Some(*dispute_id);
    store.set_escrow(escrow_id, &escrow)?;

    // Create dispute -- starts in Raised state
    let dispute = Dispute {
        id: *dispute_id,
        escrow_id: *escrow_id,
        raised_by: *raised_by,
        reason: reason as u8,
        evidence_hashes: vec![*evidence_hash],
        votes: Vec::new(),
        state: DisputeState::Raised,
        resolution: None,
        raised_at: timestamp,
        resolved_at: None,
    };
    store.set_dispute(dispute_id, &dispute)?;

    // Update dispute count for the other party
    let other_party = if *raised_by == escrow.buyer {
        escrow.seller
    } else {
        escrow.buyer
    };
    if let Some(mut p) = store.get_participant(&other_party)? {
        p.dispute_count = p.dispute_count.saturating_add(1);
        store.set_participant(&other_party, &p)?;
    }

    Ok(vec![Event::DisputeRaised {
        dispute_id: *dispute_id,
        escrow_id: *escrow_id,
    }])
}

pub fn submit_evidence(
    store: &Store,
    sender: &Id,
    dispute_id: &Id,
    evidence_hash: &[u8; 32],
) -> Result<Vec<Event>, String> {
    let mut dispute = store.get_dispute(dispute_id)?.ok_or("Dispute not found")?;

    // Authorization: only parties to the escrow can submit evidence
    let escrow = store.get_escrow(&dispute.escrow_id)?.ok_or("Escrow not found")?;
    if sender != &escrow.buyer && sender != &escrow.seller {
        return Err("Unauthorized: only escrow parties can submit evidence".to_string());
    }

    if dispute.state != DisputeState::Raised && dispute.state != DisputeState::Evidence {
        return Err("Dispute not in evidence phase".to_string());
    }

    // Transition Raised -> Evidence on first evidence submission
    if dispute.state == DisputeState::Raised {
        dispute.state = DisputeState::Evidence;
    }

    dispute.evidence_hashes.push(*evidence_hash);
    store.set_dispute(dispute_id, &dispute)?;

    Ok(Vec::new())
}

pub fn vote(
    store: &Store,
    dispute_id: &Id,
    voter: &Id,
    decision: DisputeDecision,
    timestamp: i64,
    dispute_won_reward: u64,
    vote_threshold: usize,
) -> Result<Vec<Event>, String> {
    let mut dispute = store.get_dispute(dispute_id)?.ok_or("Dispute not found")?;

    // Authorization: voter must be a registered Arbiter
    let voter_participant = store.get_participant(voter)?
        .ok_or("Voter not registered as participant")?;
    if voter_participant.p_type != ParticipantType::Arbiter as u8 {
        return Err("Unauthorized: only Arbiter participants can vote on disputes".to_string());
    }

    // Move to voting phase if still in evidence or raised
    if dispute.state == DisputeState::Raised || dispute.state == DisputeState::Evidence {
        dispute.state = DisputeState::Voting;
    }

    if dispute.state != DisputeState::Voting {
        return Err("Dispute not in voting phase".to_string());
    }

    // Check voter hasn't already voted
    if dispute.votes.iter().any(|v| v.voter == *voter) {
        return Err("Already voted".to_string());
    }

    dispute.votes.push(DisputeVote {
        voter: *voter,
        decision: decision as u8,
        voted_at: timestamp,
    });

    // Check if enough votes to resolve
    let mut events = Vec::new();

    if dispute.votes.len() >= vote_threshold {
        // Tally votes
        let mut favor_buyer = 0u32;
        let mut favor_seller = 0u32;

        for v in &dispute.votes {
            match v.decision {
                0 => favor_buyer += 1,     // FavorBuyer
                1 => favor_seller += 1,    // FavorSeller
                2 => {                     // Split: counts for both sides
                    favor_buyer += 1;
                    favor_seller += 1;
                }
                _ => {}
            }
        }

        let resolution = if favor_buyer > favor_seller {
            0u8 // FavorBuyer
        } else if favor_seller > favor_buyer {
            1u8 // FavorSeller
        } else {
            2u8 // Split (tie)
        };

        dispute.state = DisputeState::Resolved;
        dispute.resolution = Some(resolution);
        dispute.resolved_at = Some(timestamp);

        // Update winner's dispute_won count and reward
        let escrow = store.get_escrow(&dispute.escrow_id)?.ok_or("Escrow not found")?;

        if resolution != 2 {
            let winner = if resolution == 0 { escrow.buyer } else { escrow.seller };
            let loser = if resolution == 0 { escrow.seller } else { escrow.buyer };

            if let Some(mut p) = store.get_participant(&winner)? {
                p.dispute_won = p.dispute_won.saturating_add(1);
                if dispute.raised_by != winner {
                    p.dispute_count = p.dispute_count.saturating_sub(1);
                }
                store.set_participant(&winner, &p)?;
            }

            if let Some(mut p) = store.get_participant(&loser)? {
                let penalty = if dispute.raised_by == loser { 2 } else { 1 };
                p.dispute_count = p.dispute_count.saturating_add(penalty);
                store.set_participant(&loser, &p)?;
            }

            if dispute_won_reward > 0 {
                let reward_events = token::mint(store, &winner, dispute_won_reward, "dispute_won")?;
                events.extend(reward_events);
            }
        }

        events.push(Event::DisputeResolved {
            dispute_id: *dispute_id,
            decision: resolution,
        });
    }

    store.set_dispute(dispute_id, &dispute)?;

    Ok(events)
}
