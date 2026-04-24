//! HTTP Tunnel Node for MasterHttpRelayVPN "full" mode.
//!
//! Bridges HTTP tunnel requests (from Apps Script) to real TCP connections.
//! Supports both single-op (`POST /tunnel`) and batch (`POST /tunnel/batch`)
//! modes. Batch mode processes all active sessions in one HTTP round trip,
//! dramatically reducing the number of Apps Script calls.
//!
//! Env vars:
//!   TUNNEL_AUTH_KEY — shared secret (required)
//!   PORT           — listen port (default 8080, Cloud Run sets this)

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::post, Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

/// Structured error code returned when the tunnel-node receives an op it
/// doesn't recognize. Clients use this (rather than string-matching `e`) to
/// detect a version mismatch and gracefully fall back.
const CODE_UNSUPPORTED_OP: &str = "UNSUPPORTED_OP";

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

struct SessionInner {
    writer: Mutex<OwnedWriteHalf>,
    read_buf: Mutex<Vec<u8>>,
    eof: AtomicBool,
    last_active: Mutex<Instant>,
}

struct ManagedSession {
    inner: Arc<SessionInner>,
    reader_handle: tokio::task::JoinHandle<()>,
}

async fn create_session(host: &str, port: u16) -> std::io::Result<ManagedSession> {
    let addr = format!("{}:{}", host, port);
    let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    let _ = stream.set_nodelay(true);
    let (reader, writer) = stream.into_split();

    let inner = Arc::new(SessionInner {
        writer: Mutex::new(writer),
        read_buf: Mutex::new(Vec::with_capacity(32768)),
        eof: AtomicBool::new(false),
        last_active: Mutex::new(Instant::now()),
    });

    let inner_ref = inner.clone();
    let reader_handle = tokio::spawn(reader_task(reader, inner_ref));

    Ok(ManagedSession { inner, reader_handle })
}

async fn reader_task(mut reader: OwnedReadHalf, session: Arc<SessionInner>) {
    let mut buf = vec![0u8; 65536];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => { session.eof.store(true, Ordering::Release); break; }
            Ok(n) => { session.read_buf.lock().await.extend_from_slice(&buf[..n]); }
            Err(_) => { session.eof.store(true, Ordering::Release); break; }
        }
    }
}

/// Drain whatever is currently buffered — no waiting.
/// Used by batch mode where we poll frequently.
async fn drain_now(session: &SessionInner) -> (Vec<u8>, bool) {
    let mut buf = session.read_buf.lock().await;
    let data = std::mem::take(&mut *buf);
    let eof = session.eof.load(Ordering::Acquire);
    (data, eof)
}

/// Wait for response data with drain window. Used by single-op mode.
async fn wait_and_drain(session: &SessionInner, max_wait: Duration) -> (Vec<u8>, bool) {
    let deadline = Instant::now() + max_wait;
    let mut prev_len = 0usize;
    let mut last_growth = Instant::now();
    let mut ever_had_data = false;

    loop {
        let (cur_len, is_eof) = {
            let buf = session.read_buf.lock().await;
            (buf.len(), session.eof.load(Ordering::Acquire))
        };
        if cur_len > prev_len {
            last_growth = Instant::now();
            prev_len = cur_len;
            ever_had_data = true;
        }
        if is_eof { break; }
        if Instant::now() >= deadline { break; }
        if ever_had_data && last_growth.elapsed() > Duration::from_millis(100) { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut buf = session.read_buf.lock().await;
    let data = std::mem::take(&mut *buf);
    let eof = session.eof.load(Ordering::Acquire);
    (data, eof)
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<HashMap<String, ManagedSession>>>,
    auth_key: String,
}

// ---------------------------------------------------------------------------
// Protocol types — single op (backward compat)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TunnelRequest {
    k: String,
    op: String,
    #[serde(default)] host: Option<String>,
    #[serde(default)] port: Option<u16>,
    #[serde(default)] sid: Option<String>,
    #[serde(default)] data: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
struct TunnelResponse {
    #[serde(skip_serializing_if = "Option::is_none")] sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] eof: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")] e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] code: Option<String>,
}

impl TunnelResponse {
    fn error(msg: impl Into<String>) -> Self {
        Self { sid: None, d: None, eof: None, e: Some(msg.into()), code: None }
    }
    fn unsupported_op(op: &str) -> Self {
        Self {
            sid: None, d: None, eof: None,
            e: Some(format!("unknown op: {}", op)),
            code: Some(CODE_UNSUPPORTED_OP.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol types — batch
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BatchRequest {
    k: String,
    ops: Vec<BatchOp>,
}

#[derive(Deserialize)]
struct BatchOp {
    op: String,
    #[serde(default)] sid: Option<String>,
    #[serde(default)] host: Option<String>,
    #[serde(default)] port: Option<u16>,
    #[serde(default)] d: Option<String>, // base64 data
}

#[derive(Serialize)]
struct BatchResponse {
    r: Vec<TunnelResponse>,
}

// ---------------------------------------------------------------------------
// Single-op handler (backward compat)
// ---------------------------------------------------------------------------

async fn handle_tunnel(
    State(state): State<AppState>,
    Json(req): Json<TunnelRequest>,
) -> Json<TunnelResponse> {
    if req.k != state.auth_key {
        return Json(TunnelResponse::error("unauthorized"));
    }
    match req.op.as_str() {
        "connect" => Json(handle_connect(&state, req.host, req.port).await),
        "connect_data" => {
            Json(handle_connect_data_single(&state, req.host, req.port, req.data).await)
        }
        "data" => Json(handle_data_single(&state, req.sid, req.data).await),
        "close" => Json(handle_close(&state, req.sid).await),
        other => Json(TunnelResponse::unsupported_op(other)),
    }
}

// ---------------------------------------------------------------------------
// Batch handler
// ---------------------------------------------------------------------------

async fn handle_batch(
    State(state): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    // Decompress if gzipped
    let json_bytes = if body.starts_with(&[0x1f, 0x8b]) {
        match decompress_gzip(&body) {
            Ok(b) => b,
            Err(e) => {
                let resp = serde_json::to_vec(&BatchResponse {
                    r: vec![TunnelResponse::error(format!("gzip decode: {}", e))],
                }).unwrap_or_default();
                return (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], resp);
            }
        }
    } else {
        body.to_vec()
    };

    let req: BatchRequest = match serde_json::from_slice(&json_bytes) {
        Ok(r) => r,
        Err(e) => {
            let resp = serde_json::to_vec(&BatchResponse {
                r: vec![TunnelResponse::error(format!("bad json: {}", e))],
            }).unwrap_or_default();
            return (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], resp);
        }
    };

    if req.k != state.auth_key {
        let resp = serde_json::to_vec(&BatchResponse {
            r: vec![TunnelResponse::error("unauthorized")],
        }).unwrap_or_default();
        return (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], resp);
    }

    // Process all ops. For "data" ops, first write all outbound data,
    // then do a short sleep to let servers respond, then drain all.
    // This batches the network round trips on the server side too.

    // Phase 1: process connects and writes.
    //
    // `connect` and `connect_data` ops each establish a brand-new upstream
    // TCP connection which can take up to 10 s (create_session timeout).
    // Running them inline head-of-line-blocks every other op in the batch,
    // so we dispatch both into a JoinSet and await them concurrently below.
    //
    // `connect_data` is expected to dominate in practice (new client) but
    // we still hit `connect` from older clients or from server-speaks-first
    // ports that skip the pre-read — if a slow `connect` landed in the same
    // batch as data-bearing ops it could stall everyone.
    let mut results: Vec<(usize, TunnelResponse)> = Vec::with_capacity(req.ops.len());
    let mut data_ops: Vec<(usize, String)> = Vec::new(); // (index, sid) for data ops needing drain

    enum NewConn {
        Connect(TunnelResponse),
        ConnectData(Result<String, TunnelResponse>),
    }
    let mut new_conn_jobs: JoinSet<(usize, NewConn)> = JoinSet::new();

    for (i, op) in req.ops.iter().enumerate() {
        match op.op.as_str() {
            "connect" => {
                let state = state.clone();
                let host = op.host.clone();
                let port = op.port;
                new_conn_jobs.spawn(async move {
                    (i, NewConn::Connect(handle_connect(&state, host, port).await))
                });
            }
            "connect_data" => {
                let state = state.clone();
                let host = op.host.clone();
                let port = op.port;
                let d = op.d.clone();
                new_conn_jobs.spawn(async move {
                    // Drop the returned Arc<SessionInner>: phase 2 below
                    // holds the sessions-map lock once for the whole batch
                    // and re-looks up each sid, which is cheap. The Arc
                    // return is a convenience for the single-op path only.
                    let r = handle_connect_data_phase1(&state, host, port, d)
                        .await
                        .map(|(sid, _inner)| sid);
                    (i, NewConn::ConnectData(r))
                });
            }
            "data" => {
                let sid = match &op.sid {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => { results.push((i, TunnelResponse::error("missing sid"))); continue; }
                };

                // Write outbound data
                let sessions = state.sessions.lock().await;
                if let Some(session) = sessions.get(&sid) {
                    *session.inner.last_active.lock().await = Instant::now();
                    if let Some(ref data_b64) = op.d {
                        if !data_b64.is_empty() {
                            if let Ok(bytes) = B64.decode(data_b64) {
                                if !bytes.is_empty() {
                                    let mut w = session.inner.writer.lock().await;
                                    let _ = w.write_all(&bytes).await;
                                    let _ = w.flush().await;
                                }
                            }
                        }
                    }
                    drop(sessions);
                    data_ops.push((i, sid));
                } else {
                    drop(sessions);
                    results.push((i, TunnelResponse {
                        sid: Some(sid), d: None, eof: Some(true), e: None, code: None,
                    }));
                }
            }
            "close" => {
                let r = handle_close(&state, op.sid.clone()).await;
                results.push((i, r));
            }
            other => {
                results.push((i, TunnelResponse::unsupported_op(other)));
            }
        }
    }

    // Await all concurrent connect / connect_data jobs. For connect_data,
    // successful ones join the data-drain set in phase 2; plain connects
    // go straight to results because they have no initial data to drain.
    while let Some(join) = new_conn_jobs.join_next().await {
        match join {
            Ok((i, NewConn::Connect(r))) => results.push((i, r)),
            Ok((i, NewConn::ConnectData(Ok(sid)))) => data_ops.push((i, sid)),
            Ok((i, NewConn::ConnectData(Err(r)))) => results.push((i, r)),
            Err(e) => {
                tracing::error!("new-connection task panicked: {}", e);
            }
        }
    }

    // Phase 2: short wait for servers to respond, then drain all data sessions
    if !data_ops.is_empty() {
        // Give servers a moment to respond to the data we just wrote
        tokio::time::sleep(Duration::from_millis(150)).await;

        // First drain pass
        {
            let sessions = state.sessions.lock().await;
            let mut need_retry = Vec::new();
            for (i, sid) in &data_ops {
                if let Some(session) = sessions.get(sid) {
                    let (data, eof) = drain_now(&session.inner).await;
                    if data.is_empty() && !eof {
                        need_retry.push((*i, sid.clone()));
                    } else {
                        results.push((*i, TunnelResponse {
                            sid: Some(sid.clone()),
                            d: if data.is_empty() { None } else { Some(B64.encode(&data)) },
                            eof: Some(eof), e: None, code: None,
                        }));
                    }
                } else {
                    results.push((*i, TunnelResponse {
                        sid: Some(sid.clone()), d: None, eof: Some(true), e: None, code: None,
                    }));
                }
            }
            drop(sessions);

            // Retry sessions that had no data yet
            if !need_retry.is_empty() {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let sessions = state.sessions.lock().await;
                for (i, sid) in &need_retry {
                    if let Some(s) = sessions.get(sid) {
                        let (data, eof) = drain_now(&s.inner).await;
                        results.push((*i, TunnelResponse {
                            sid: Some(sid.clone()),
                            d: if data.is_empty() { None } else { Some(B64.encode(&data)) },
                            eof: Some(eof), e: None, code: None,
                        }));
                    } else {
                        results.push((*i, TunnelResponse {
                            sid: Some(sid.clone()), d: None, eof: Some(true), e: None, code: None,
                        }));
                    }
                }
            }
        }

        // Clean up eof sessions
        let mut sessions = state.sessions.lock().await;
        for (_, sid) in &data_ops {
            if let Some(s) = sessions.get(sid) {
                if s.inner.eof.load(Ordering::Acquire) {
                    if let Some(s) = sessions.remove(sid) {
                        s.reader_handle.abort();
                        tracing::info!("session {} closed by remote (batch)", sid);
                    }
                }
            }
        }
    }

    // Sort results by original index and build response
    results.sort_by_key(|(i, _)| *i);
    let batch_resp = BatchResponse {
        r: results.into_iter().map(|(_, r)| r).collect(),
    };

    let json = serde_json::to_vec(&batch_resp).unwrap_or_default();
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json)
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Shared op handlers
// ---------------------------------------------------------------------------

fn validate_host_port(
    host: Option<String>,
    port: Option<u16>,
) -> Result<(String, u16), TunnelResponse> {
    let host = match host {
        Some(h) if !h.is_empty() => h,
        _ => return Err(TunnelResponse::error("missing host")),
    };
    let port = match port {
        Some(p) if p > 0 => p,
        _ => return Err(TunnelResponse::error("missing or invalid port")),
    };
    Ok((host, port))
}

async fn handle_connect(state: &AppState, host: Option<String>, port: Option<u16>) -> TunnelResponse {
    let (host, port) = match validate_host_port(host, port) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let session = match create_session(&host, port).await {
        Ok(s) => s,
        Err(e) => return TunnelResponse::error(format!("connect failed: {}", e)),
    };
    let sid = uuid::Uuid::new_v4().to_string();
    tracing::info!("session {} -> {}:{}", sid, host, port);
    state.sessions.lock().await.insert(sid.clone(), session);
    TunnelResponse { sid: Some(sid), d: None, eof: Some(false), e: None, code: None }
}

/// Open a session and write the client's first bytes in one round trip.
/// Returns the new sid plus an `Arc<SessionInner>` so unary callers
/// (`handle_connect_data_single`) can drain the first response without a
/// second sessions-map lookup. The batch caller drops the Arc — it takes
/// a single lock across all drain-bound sessions in phase 2, which is
/// cheaper than the Arc plumbing would be.
async fn handle_connect_data_phase1(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
    data: Option<String>,
) -> Result<(String, Arc<SessionInner>), TunnelResponse> {
    let (host, port) = validate_host_port(host, port)?;

    let session = create_session(&host, port)
        .await
        .map_err(|e| TunnelResponse::error(format!("connect failed: {}", e)))?;

    // Any failure below this point must abort the reader task, otherwise
    // the newly-opened upstream TCP connection would leak. Keep the
    // abort paths explicit rather than burying them in `.map_err`.
    if let Some(ref data_b64) = data {
        if !data_b64.is_empty() {
            let bytes = match B64.decode(data_b64) {
                Ok(b) => b,
                Err(e) => {
                    session.reader_handle.abort();
                    return Err(TunnelResponse::error(format!("bad base64: {}", e)));
                }
            };
            if !bytes.is_empty() {
                let mut w = session.inner.writer.lock().await;
                if let Err(e) = w.write_all(&bytes).await {
                    drop(w);
                    session.reader_handle.abort();
                    return Err(TunnelResponse::error(format!("write failed: {}", e)));
                }
                let _ = w.flush().await;
            }
        }
    }

    let inner = session.inner.clone();
    let sid = uuid::Uuid::new_v4().to_string();
    tracing::info!("session {} -> {}:{} (connect_data)", sid, host, port);
    state.sessions.lock().await.insert(sid.clone(), session);
    Ok((sid, inner))
}

async fn handle_connect_data_single(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
    data: Option<String>,
) -> TunnelResponse {
    let (sid, inner) = match handle_connect_data_phase1(state, host, port, data).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (data, eof) = wait_and_drain(&inner, Duration::from_secs(5)).await;
    if eof {
        if let Some(s) = state.sessions.lock().await.remove(&sid) {
            s.reader_handle.abort();
            tracing::info!("session {} closed by remote", sid);
        }
    }
    TunnelResponse {
        sid: Some(sid),
        d: if data.is_empty() { None } else { Some(B64.encode(&data)) },
        eof: Some(eof),
        e: None,
        code: None,
    }
}

async fn handle_data_single(state: &AppState, sid: Option<String>, data: Option<String>) -> TunnelResponse {
    let sid = match sid {
        Some(s) if !s.is_empty() => s,
        _ => return TunnelResponse::error("missing sid"),
    };
    let sessions = state.sessions.lock().await;
    let session = match sessions.get(&sid) {
        Some(s) => s,
        None => return TunnelResponse::error("unknown session"),
    };
    *session.inner.last_active.lock().await = Instant::now();
    if let Some(ref data_b64) = data {
        if !data_b64.is_empty() {
            if let Ok(bytes) = B64.decode(data_b64) {
                if !bytes.is_empty() {
                    let mut w = session.inner.writer.lock().await;
                    if let Err(e) = w.write_all(&bytes).await {
                        drop(w); drop(sessions);
                        state.sessions.lock().await.remove(&sid);
                        return TunnelResponse::error(format!("write failed: {}", e));
                    }
                    let _ = w.flush().await;
                }
            }
        }
    }
    let (data, eof) = wait_and_drain(&session.inner, Duration::from_secs(5)).await;
    drop(sessions);
    if eof {
        if let Some(s) = state.sessions.lock().await.remove(&sid) {
            s.reader_handle.abort();
            tracing::info!("session {} closed by remote", sid);
        }
    }
    TunnelResponse {
        sid: Some(sid),
        d: if data.is_empty() { None } else { Some(B64.encode(&data)) },
        eof: Some(eof), e: None, code: None,
    }
}

async fn handle_close(state: &AppState, sid: Option<String>) -> TunnelResponse {
    let sid = match sid {
        Some(s) if !s.is_empty() => s,
        _ => return TunnelResponse::error("missing sid"),
    };
    if let Some(s) = state.sessions.lock().await.remove(&sid) {
        s.reader_handle.abort();
        tracing::info!("session {} closed by client", sid);
    }
    TunnelResponse { sid: Some(sid), d: None, eof: Some(true), e: None, code: None }
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

async fn cleanup_task(sessions: Arc<Mutex<HashMap<String, ManagedSession>>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let mut map = sessions.lock().await;
        let now = Instant::now();
        let mut stale = Vec::new();
        for (k, s) in map.iter() {
            let last = *s.inner.last_active.lock().await;
            if now.duration_since(last) > Duration::from_secs(300) {
                stale.push(k.clone());
            }
        }
        for k in &stale {
            if let Some(s) = map.remove(k) {
                s.reader_handle.abort();
                tracing::info!("reaped idle session {}", k);
            }
        }
        if !stale.is_empty() {
            tracing::info!("cleanup: reaped {}, {} active", stale.len(), map.len());
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let auth_key = std::env::var("TUNNEL_AUTH_KEY").unwrap_or_else(|_| {
        tracing::warn!("TUNNEL_AUTH_KEY not set — using default (INSECURE)");
        "changeme".into()
    });
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let sessions: Arc<Mutex<HashMap<String, ManagedSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(cleanup_task(sessions.clone()));

    let state = AppState { sessions, auth_key };

    let app = Router::new()
        .route("/tunnel", post(handle_tunnel))
        .route("/tunnel/batch", post(handle_batch))
        .route("/health", axum::routing::get(|| async { "ok" }))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("tunnel-node listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("shutting down");
        })
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn fresh_state() -> AppState {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            auth_key: "test-key".into(),
        }
    }

    /// Spin up a one-shot TCP server that echoes everything it reads back
    /// with a `"ECHO: "` prefix, then returns the bound port.
    async fn start_echo_server() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = sock.read(&mut buf).await {
                    let mut out = b"ECHO: ".to_vec();
                    out.extend_from_slice(&buf[..n]);
                    let _ = sock.write_all(&out).await;
                    let _ = sock.flush().await;
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn unsupported_op_response_has_structured_code() {
        let resp = TunnelResponse::unsupported_op("connect_data");
        assert_eq!(resp.code.as_deref(), Some(CODE_UNSUPPORTED_OP));
        assert_eq!(resp.e.as_deref(), Some("unknown op: connect_data"));
    }

    #[tokio::test]
    async fn validate_host_port_rejects_empty_and_zero() {
        assert!(validate_host_port(None, Some(443)).is_err());
        assert!(validate_host_port(Some("".into()), Some(443)).is_err());
        assert!(validate_host_port(Some("x".into()), None).is_err());
        assert!(validate_host_port(Some("x".into()), Some(0)).is_err());
        assert_eq!(
            validate_host_port(Some("host".into()), Some(443)).unwrap(),
            ("host".to_string(), 443),
        );
    }

    #[tokio::test]
    async fn connect_data_phase1_writes_initial_data_and_returns_inner() {
        let port = start_echo_server().await;
        let state = fresh_state();

        let (sid, inner) = handle_connect_data_phase1(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some(B64.encode(b"hello")),
        )
        .await
        .expect("phase1 should succeed");

        // Session was inserted.
        assert!(state.sessions.lock().await.contains_key(&sid));

        // Echo server sent back "ECHO: hello". Use wait_and_drain on the
        // returned Arc — no map re-lookup needed (this is the fix).
        let (data, _eof) = wait_and_drain(&inner, Duration::from_secs(2)).await;
        assert_eq!(&data[..], b"ECHO: hello");
    }

    #[tokio::test]
    async fn connect_data_single_bundles_connect_and_first_bytes() {
        let port = start_echo_server().await;
        let state = fresh_state();

        let resp = handle_connect_data_single(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some(B64.encode(b"world")),
        )
        .await;

        assert!(resp.e.is_none(), "unexpected error: {:?}", resp.e);
        assert!(resp.sid.is_some());
        let decoded = B64.decode(resp.d.unwrap()).unwrap();
        assert_eq!(&decoded[..], b"ECHO: world");
    }

    #[tokio::test]
    async fn connect_data_rejects_missing_host() {
        let state = fresh_state();
        let resp = handle_connect_data_single(
            &state, None, Some(443), Some(B64.encode(b"x")),
        ).await;
        assert!(resp.e.as_deref().unwrap_or("").contains("missing host"));
        assert!(state.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn connect_data_rejects_bad_base64_and_does_not_leak_session() {
        // Need a live target so we reach the base64-decode step after
        // create_session succeeds — otherwise we'd fail earlier.
        let port = start_echo_server().await;
        let state = fresh_state();
        let resp = handle_connect_data_single(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some("!!!not base64!!!".into()),
        )
        .await;
        assert!(resp.e.as_deref().unwrap_or("").contains("bad base64"));
        // Session should NOT be in the map since phase1 rejected it.
        assert!(state.sessions.lock().await.is_empty());
    }
}

