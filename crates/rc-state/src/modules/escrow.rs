use rc_store::Store;
use rc_types::*;
use super::token;

#[allow(clippy::too_many_arguments)]
pub fn create(
    store: &Store,
    sender: &Id,
    escrow_id: &Id,
    buyer: &Id,
    seller: &Id,
    amount: u64,
    expires_at: i64,
    timestamp: i64,
) -> Result<Vec<Event>, String> {
    // Authorization: only the buyer can create an escrow
    if sender != buyer {
        return Err("Unauthorized: only buyer can create escrow".to_string());
    }

    // Check escrow doesn't exist
    if store.get_escrow(escrow_id)?.is_some() {
        return Err("Escrow already exists".to_string());
    }

    // Verify buyer and seller exist
    store.get_participant(buyer)?.ok_or("Buyer not found")?;
    store.get_participant(seller)?.ok_or("Seller not found")?;

    let escrow = Escrow {
        id: *escrow_id,
        buyer: *buyer,
        seller: *seller,
        amount,
        state: EscrowState::Created,
        created_at: timestamp,
        expires_at,
        evidence_hash: None,
        dispute_id: None,
    };

    store.set_escrow(escrow_id, &escrow)?;

    Ok(vec![Event::EscrowCreated {
        escrow_id: *escrow_id,
        buyer: *buyer,
        seller: *seller,
        amount,
    }])
}

pub fn release(
    store: &Store,
    sender: &Id,
    escrow_id: &Id,
    evidence_hash: &[u8; 32],
    timestamp: i64,
    reward_amount: u64,
) -> Result<Vec<Event>, String> {
    let mut escrow = store
        .get_escrow(escrow_id)?
        .ok_or("Escrow not found")?;

    // Authorization: only the buyer can confirm delivery and release
    if sender != &escrow.buyer {
        return Err("Unauthorized: only buyer can release escrow".to_string());
    }

    if escrow.state != EscrowState::Created && escrow.state != EscrowState::Funded {
        return Err(format!("Escrow cannot be released in state {:?}", escrow.state));
    }

    // Check not expired
    if timestamp > escrow.expires_at {
        return Err("Escrow has expired".to_string());
    }

    escrow.state = EscrowState::Released;
    escrow.evidence_hash = Some(*evidence_hash);
    store.set_escrow(escrow_id, &escrow)?;

    // Update both parties' stats (saturating arithmetic)
    let mut buyer = store.get_participant(&escrow.buyer)?.ok_or("Buyer not found")?;
    buyer.total_tx = buyer.total_tx.saturating_add(1);
    buyer.success_tx = buyer.success_tx.saturating_add(1);
    buyer.last_activity_at = timestamp;
    store.set_participant(&escrow.buyer, &buyer)?;

    let mut seller = store.get_participant(&escrow.seller)?.ok_or("Seller not found")?;
    seller.total_tx = seller.total_tx.saturating_add(1);
    seller.success_tx = seller.success_tx.saturating_add(1);
    seller.total_volume = seller.total_volume.saturating_add(escrow.amount);
    seller.last_activity_at = timestamp;
    store.set_participant(&escrow.seller, &seller)?;

    let mut events = vec![Event::EscrowReleased {
        escrow_id: *escrow_id,
    }];

    // Reward both parties
    if reward_amount > 0 {
        let buyer_rewards = token::mint(store, &escrow.buyer, reward_amount, "escrow_complete")?;
        let seller_rewards = token::mint(store, &escrow.seller, reward_amount, "escrow_complete")?;
        events.extend(buyer_rewards);
        events.extend(seller_rewards);
    }

    Ok(events)
}

pub fn refund(
    store: &Store,
    sender: &Id,
    escrow_id: &Id,
    timestamp: i64,
) -> Result<Vec<Event>, String> {
    let mut escrow = store
        .get_escrow(escrow_id)?
        .ok_or("Escrow not found")?;

    // Authorization: buyer can refund anytime, anyone can refund after expiry
    let is_buyer = sender == &escrow.buyer;
    let is_expired = timestamp > escrow.expires_at;
    if !is_buyer && !is_expired {
        return Err("Unauthorized: only buyer can refund, or escrow must be expired".to_string());
    }

    if escrow.state != EscrowState::Created && escrow.state != EscrowState::Funded {
        return Err(format!("Escrow cannot be refunded in state {:?}", escrow.state));
    }

    escrow.state = EscrowState::Refunded;
    store.set_escrow(escrow_id, &escrow)?;

    // Update seller stats (refund implies failure)
    let mut seller = store.get_participant(&escrow.seller)?.ok_or("Seller not found")?;
    seller.total_tx = seller.total_tx.saturating_add(1);
    seller.last_activity_at = timestamp;
    store.set_participant(&escrow.seller, &seller)?;

    Ok(vec![Event::EscrowRefunded {
        escrow_id: *escrow_id,
    }])
}
