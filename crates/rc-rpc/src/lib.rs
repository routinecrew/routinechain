use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json,
};
use rc_store::Store;
use rc_types::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use tower_http::cors::CorsLayer;

/// Shared application state
pub struct AppState {
    pub store: Store,
    pub tx_sender: mpsc::Sender<Transaction>,
}

/// Standard API response
#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub result: bool,
    pub message: String,
    pub data: Option<T>,
}

/// Trust Score response
#[derive(Serialize)]
pub struct TrustScoreResponse {
    pub participant_id: String,
    pub score: f64,
    pub total_tx: u64,
    pub success_tx: u64,
    pub success_rate: f64,
    pub dispute_count: u64,
    pub dispute_rate: f64,
    pub avg_rating: f64,
    pub total_volume: u64,
    pub registered_at: i64,
    pub last_activity_at: i64,
}

/// RCW Balance response
#[derive(Serialize)]
pub struct BalanceResponse {
    pub owner: String,
    pub earned: u64,
    pub purchased: u64,
    pub total: u64,
}

/// Chain status response
#[derive(Serialize)]
pub struct StatusResponse {
    pub chain: String,
    pub latest_height: u64,
    pub version: String,
}

/// Transaction submit request
#[derive(Deserialize)]
pub struct SubmitTxRequest {
    pub payload: TxPayload,
    pub sender: String,
    pub signature: String,
    pub nonce: u64,
}

pub async fn create_router(store: Store, tx_sender: mpsc::Sender<Transaction>) -> Router {
    let state = Arc::new(AppState { store, tx_sender });

    Router::new()
        // Chain
        .route("/status", get(get_status))
        .route("/block/{height}", get(get_block))
        // Transactions
        .route("/tx", post(submit_tx))
        // CTP: Participant
        .route("/participant/{id}", get(get_participant))
        .route("/participant/{id}/trust", get(get_trust_score))
        // CTP: Settlement
        .route("/settlement/{id}", get(get_settlement))
        // CTP: Escrow
        .route("/escrow/{id}", get(get_escrow))
        // CTP: Dispute
        .route("/dispute/{id}", get(get_dispute))
        // RCW
        .route("/balance/{id}", get(get_balance))
        // Middleware
        .layer({
            if cfg!(debug_assertions) {
                CorsLayer::permissive()
            } else {
                CorsLayer::new()
                    .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                    .allow_headers([axum::http::header::CONTENT_TYPE])
            }
        })
        .with_state(state)
}

// ── Handlers ──

async fn get_status(State(state): State<Arc<AppState>>) -> Json<ApiResponse<StatusResponse>> {
    let height = state.store.get_latest_height();
    Json(ApiResponse {
        result: true,
        message: "ok".to_string(),
        data: Some(StatusResponse {
            chain: "routinechain".to_string(),
            latest_height: height,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
    })
}

async fn get_block(
    State(state): State<Arc<AppState>>,
    Path(height): Path<u64>,
) -> Result<Json<ApiResponse<Block>>, StatusCode> {
    match state.store.get_block(height) {
        Ok(Some(block)) => Ok(Json(ApiResponse {
            result: true,
            message: "ok".to_string(),
            data: Some(block),
        })),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn submit_tx(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitTxRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // Parse sender public key
    let sender = hex_to_id(&req.sender).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Parse signature (128 hex chars = 64 bytes)
    let sig_bytes = hex::decode(&req.signature).map_err(|_| StatusCode::BAD_REQUEST)?;
    if sig_bytes.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    // Verify Ed25519 signature over serialized payload
    let payload_bytes = bincode::serialize(&req.payload).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !rc_crypto::verify(&payload_bytes, &sig_arr, &sender) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let tx = Transaction {
        payload: req.payload,
        sender,
        signature: Signature(sig_arr),
        timestamp: now_ms(),
        nonce: req.nonce,
    };

    state
        .tx_sender
        .send(tx)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiResponse {
        result: true,
        message: "Transaction submitted".to_string(),
        data: Some("accepted".to_string()),
    }))
}

async fn get_participant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Participant>>, StatusCode> {
    let id = hex_to_id(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    match state.store.get_participant(&id) {
        Ok(Some(p)) => Ok(Json(ApiResponse {
            result: true,
            message: "ok".to_string(),
            data: Some(p),
        })),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_trust_score(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<TrustScoreResponse>>, StatusCode> {
    let id_bytes = hex_to_id(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let p = state
        .store
        .get_participant(&id_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let score = compute_trust_score(&p);

    let response = TrustScoreResponse {
        participant_id: id,
        score: score as f64 / 100.0,
        total_tx: p.total_tx,
        success_tx: p.success_tx,
        success_rate: if p.total_tx > 0 {
            p.success_tx as f64 / p.total_tx as f64 * 100.0
        } else {
            0.0
        },
        dispute_count: p.dispute_count,
        dispute_rate: if p.total_tx > 0 {
            p.dispute_count as f64 / p.total_tx as f64 * 100.0
        } else {
            0.0
        },
        avg_rating: if p.rating_count > 0 {
            p.rating_sum as f64 / p.rating_count as f64 / 100.0
        } else {
            0.0
        },
        total_volume: p.total_volume,
        registered_at: p.registered_at,
        last_activity_at: p.last_activity_at,
    };

    Ok(Json(ApiResponse {
        result: true,
        message: "ok".to_string(),
        data: Some(response),
    }))
}

async fn get_settlement(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<SettlementRecord>>, StatusCode> {
    let id = hex_to_id(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    match state.store.get_settlement(&id) {
        Ok(Some(s)) => Ok(Json(ApiResponse {
            result: true,
            message: "ok".to_string(),
            data: Some(s),
        })),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_escrow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Escrow>>, StatusCode> {
    let id = hex_to_id(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    match state.store.get_escrow(&id) {
        Ok(Some(e)) => Ok(Json(ApiResponse {
            result: true,
            message: "ok".to_string(),
            data: Some(e),
        })),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_dispute(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Dispute>>, StatusCode> {
    let id = hex_to_id(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    match state.store.get_dispute(&id) {
        Ok(Some(d)) => Ok(Json(ApiResponse {
            result: true,
            message: "ok".to_string(),
            data: Some(d),
        })),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_balance(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<BalanceResponse>>, StatusCode> {
    let id_bytes = hex_to_id(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bal = state
        .store
        .get_balance(&id_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiResponse {
        result: true,
        message: "ok".to_string(),
        data: Some(BalanceResponse {
            owner: id,
            earned: bal.earned,
            purchased: bal.purchased,
            total: bal.total(),
        }),
    }))
}

// ── Helpers ──

fn hex_to_id(hex: &str) -> Result<Id, String> {
    let bytes = hex::decode(hex).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("ID must be 32 bytes".to_string());
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode as SC};
    use tower::ServiceExt;

    async fn setup(name: &str) -> (Router, Store) {
        let path = format!("/tmp/rcw_test_rpc_{}", name);
        let _ = std::fs::remove_dir_all(&path);
        let store = Store::open(&path).unwrap();
        let (tx, _rx) = mpsc::channel(100);
        let router = create_router(store.clone(), tx).await;
        (router, store)
    }

    #[tokio::test]
    async fn test_get_status() {
        let (app, _store) = setup("status").await;
        let resp = app
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), SC::OK);
    }

    #[tokio::test]
    async fn test_get_participant_not_found() {
        let (app, _store) = setup("participant_404").await;
        let hex_id = "01".repeat(32);
        let resp = app
            .oneshot(
                Request::get(&format!("/participant/{}", hex_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), SC::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_balance_default() {
        let (app, _store) = setup("balance_default").await;
        let hex_id = "02".repeat(32);
        let resp = app
            .oneshot(
                Request::get(&format!("/balance/{}", hex_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), SC::OK);
    }

    #[tokio::test]
    async fn test_get_block_not_found() {
        let (app, _store) = setup("block_404").await;
        let resp = app
            .oneshot(Request::get("/block/999").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), SC::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_dispute_not_found() {
        let (app, _store) = setup("dispute_404").await;
        let hex_id = "03".repeat(32);
        let resp = app
            .oneshot(
                Request::get(&format!("/dispute/{}", hex_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), SC::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_block_found() {
        let (app, store) = setup("block_found").await;
        let block = rc_types::Block::genesis(1000, [0u8; 32]);
        store.put_block(&block).unwrap();
        let resp = app
            .oneshot(Request::get("/block/0").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), SC::OK);
    }

    #[tokio::test]
    async fn test_invalid_hex_id() {
        let (app, _store) = setup("invalid_hex").await;
        let resp = app
            .oneshot(
                Request::get("/participant/not-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), SC::BAD_REQUEST);
    }
}
