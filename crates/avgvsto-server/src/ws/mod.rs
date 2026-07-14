/// AVGVSTO Server — WebSocket module
/// WebSocket handlers are in routes/ws.rs
/// This module provides utilities for WebSocket connections.

use axum::extract::ws::{Message, WebSocket, Utf8Bytes};
use futures::stream::SplitSink;
use futures::SinkExt;
use std::sync::Arc;
use tokio::sync::Mutex;

pub type WsSender = Arc<Mutex<SplitSink<WebSocket, Message>>>;

pub async fn send_message(sender: &mut WsSender, msg: serde_json::Value) -> Result<(), ()> {
    sender
        .lock()
        .await
        .send(Message::Text(Utf8Bytes::from(msg.to_string())))
        .await
        .map_err(|_| ())
}
