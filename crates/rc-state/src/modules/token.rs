use rc_store::Store;
use rc_types::*;

/// Mint RCW tokens as reward
pub fn mint(
    store: &Store,
    to: &Id,
    amount: u64,
    reason: &str,
) -> Result<Vec<Event>, String> {
    let mut balance = store.get_balance(to)?;
    balance.earned += amount;
    store.set_balance(to, &balance)?;

    Ok(vec![Event::RCWMinted {
        to: *to,
        amount,
        reason: reason.to_string(),
    }])
}

/// Transfer RCW between participants
pub fn transfer(
    store: &Store,
    from: &Id,
    to: &Id,
    amount: u64,
    _memo: &str,
) -> Result<Vec<Event>, String> {
    if amount == 0 {
        return Err("Amount must be positive".to_string());
    }

    let mut from_balance = store.get_balance(from)?;
    if from_balance.total() < amount {
        return Err(format!(
            "Insufficient balance: have {}, need {}",
            from_balance.total(),
            amount
        ));
    }

    // Deduct from sender (earned first, then purchased)
    if from_balance.earned >= amount {
        from_balance.earned -= amount;
    } else {
        let remaining = amount - from_balance.earned;
        from_balance.earned = 0;
        from_balance.purchased -= remaining;
    }
    store.set_balance(from, &from_balance)?;

    // Add to receiver
    let mut to_balance = store.get_balance(to)?;
    to_balance.earned += amount;
    store.set_balance(to, &to_balance)?;

    Ok(vec![Event::RCWTransferred {
        from: *from,
        to: *to,
        amount,
    }])
}

/// Spend RCW (for AI tools, badges, etc.)
pub fn spend(
    store: &Store,
    from: &Id,
    amount: u64,
    purpose: &str,
) -> Result<Vec<Event>, String> {
    if amount == 0 {
        return Err("Amount must be positive".to_string());
    }

    let mut balance = store.get_balance(from)?;
    if balance.total() < amount {
        return Err(format!(
            "Insufficient balance: have {}, need {}",
            balance.total(),
            amount
        ));
    }

    // Deduct (earned first)
    if balance.earned >= amount {
        balance.earned -= amount;
    } else {
        let remaining = amount - balance.earned;
        balance.earned = 0;
        balance.purchased -= remaining;
    }
    store.set_balance(from, &balance)?;

    Ok(vec![Event::RCWSpent {
        from: *from,
        amount,
        purpose: purpose.to_string(),
    }])
}
