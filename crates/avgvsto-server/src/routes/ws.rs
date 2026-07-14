use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade, Utf8Bytes},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::SinkExt;

use avgvsto_audit::{AuditAction, AuditQuery, CreateAuditEvent};

use super::AppState;
use crate::middleware::auth::AuthenticatedUser;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/ws/encrypt", get(ws_encrypt_handler))
        .route("/ws/decrypt", get(ws_decrypt_handler))
        .route("/ws/audit", get(ws_audit_handler))
}

async fn ws_encrypt_handler(
    ws: WebSocketUpgrade,
    user: AuthenticatedUser,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_encrypt_ws(socket, user, state))
}

async fn handle_encrypt_ws(mut socket: WebSocket, user: AuthenticatedUser, state: AppState) {
    let welcome = serde_json::json!({
        "type": "connected",
        "channel": "encrypt",
        "user_id": user.user_id,
    });
    if socket.send(Message::Text(Utf8Bytes::from(welcome.to_string()))).await.is_err() {
        return;
    }

    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Text(text) => {
                let response = serde_json::json!({
                    "type": "encrypt_progress",
                    "status": "processing",
                    "message": "Encryption in progress (WebSocket mode)",
                });
                if socket.send(Message::Text(Utf8Bytes::from(response.to_string()))).await.is_err() {
                    break;
                }

                state
                    .audit_store
                    .create_event(CreateAuditEvent {
                        user_id: Some(user.user_id),
                        action: AuditAction::FileEncrypted,
                        resource: Some("ws/encrypt".to_string()),
                        details: serde_json::json!({ "mode": "websocket", "data_size": text.len() }),
                        ip_address: None,
                        user_agent: None,
                    })
                    .await
                    .ok();
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

async fn ws_decrypt_handler(
    ws: WebSocketUpgrade,
    user: AuthenticatedUser,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_decrypt_ws(socket, user, state))
}

async fn handle_decrypt_ws(mut socket: WebSocket, user: AuthenticatedUser, state: AppState) {
    let welcome = serde_json::json!({
        "type": "connected",
        "channel": "decrypt",
        "user_id": user.user_id,
    });
    if socket.send(Message::Text(Utf8Bytes::from(welcome.to_string()))).await.is_err() {
        return;
    }

    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Text(text) => {
                let response = serde_json::json!({
                    "type": "decrypt_progress",
                    "status": "processing",
                    "message": "Decryption in progress (WebSocket mode)",
                });
                if socket.send(Message::Text(Utf8Bytes::from(response.to_string()))).await.is_err() {
                    break;
                }

                state
                    .audit_store
                    .create_event(CreateAuditEvent {
                        user_id: Some(user.user_id),
                        action: AuditAction::FileDecrypted,
                        resource: Some("ws/decrypt".to_string()),
                        details: serde_json::json!({ "mode": "websocket", "data_size": text.len() }),
                        ip_address: None,
                        user_agent: None,
                    })
                    .await
                    .ok();
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

async fn ws_audit_handler(
    ws: WebSocketUpgrade,
    user: AuthenticatedUser,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if !user.is_admin() {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }
    ws.on_upgrade(move |socket| handle_audit_ws(socket, user, state)).into_response()
}

async fn handle_audit_ws(mut socket: WebSocket, user: AuthenticatedUser, state: AppState) {
    let welcome = serde_json::json!({
        "type": "connected",
        "channel": "audit",
        "user_id": user.user_id,
    });
    if socket.send(Message::Text(Utf8Bytes::from(welcome.to_string()))).await.is_err() {
        return;
    }

    // Stream recent audit events
    let query = AuditQuery {
        user_id: None,
        action: None,
        from: None,
        to: None,
        limit: Some(50),
        offset: Some(0),
    };

    if let Ok(events) = state.audit_store.query_events(query).await {
        for event in events {
            let msg = serde_json::json!({
                "type": "audit_event",
                "event": event,
            });
            if socket.send(Message::Text(Utf8Bytes::from(msg.to_string()))).await.is_err() {
                break;
            }
        }
    }

    // Keep connection alive, forwarding new events in a real implementation
    // would use PostgreSQL LISTEN/NOTIFY or a channel
    let _ = socket.close().await;
}
