use rc_store::Store;
use rc_types::*;

pub fn register(
    store: &Store,
    sender: &Id,
    id: &Id,
    p_type: ParticipantType,
    metadata: &str,
    timestamp: i64,
) -> Result<Vec<Event>, String> {
    // Authorization: sender must be the participant being registered (self-registration)
    if sender != id {
        return Err("Unauthorized: sender must match participant id".to_string());
    }

    // Check not already registered
    if store.get_participant(id)?.is_some() {
        return Err("Participant already exists".to_string());
    }

    let participant = Participant {
        id: *id,
        p_type: p_type as u8,
        metadata: metadata.to_string(),
        total_tx: 0,
        success_tx: 0,
        dispute_count: 0,
        dispute_won: 0,
        rating_sum: 0,
        rating_count: 0,
        total_volume: 0,
        total_settled: 0,
        registered_at: timestamp,
        last_activity_at: timestamp,
        is_active: true,
    };

    store.set_participant(id, &participant)?;

    Ok(vec![Event::ParticipantRegistered {
        id: *id,
        p_type: p_type as u8,
    }])
}

pub fn update(
    store: &Store,
    sender: &Id,
    id: &Id,
    metadata: &str,
    timestamp: i64,
) -> Result<Vec<Event>, String> {
    // Authorization: only the participant can update their own data
    if sender != id {
        return Err("Unauthorized: sender must match participant id".to_string());
    }

    let mut p = store
        .get_participant(id)?
        .ok_or("Participant not found")?;

    p.metadata = metadata.to_string();
    p.last_activity_at = timestamp;
    store.set_participant(id, &p)?;

    Ok(vec![Event::ParticipantUpdated { id: *id }])
}

pub fn deactivate(store: &Store, sender: &Id, id: &Id) -> Result<Vec<Event>, String> {
    // Authorization: only the participant can deactivate themselves
    if sender != id {
        return Err("Unauthorized: sender must match participant id".to_string());
    }

    let mut p = store
        .get_participant(id)?
        .ok_or("Participant not found")?;

    p.is_active = false;
    store.set_participant(id, &p)?;

    Ok(vec![Event::ParticipantDeactivated { id: *id }])
}
