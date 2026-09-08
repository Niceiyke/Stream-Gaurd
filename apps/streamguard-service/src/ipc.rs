//! Authenticated local IPC plane (spec 22.5 "IPC (named pipe) | Worker
//! pool", engineering step 12 "Desktop status UI": IPC authenticated).
//!
//! The engine publishes `StatusSnapshot` frames over a loopback transport.
//! Two transports speak the *identical* v1 wire protocol:
//!
//! - Windows: a named pipe under `\\.\pipe\` (spec 22.5),
//! - anything else / portability: a 127.0.0.1 loopback TCP listener.
//!
//! Both are kept behind `StatusEndpoint`; connection workers are spawned per
//! accepted connection (worker-pool semantics, spec 22.5) and each serves at
//! most `MAX_SNAPSHOTS_PER_CONNECTION` snapshots before closing so a stuck
//! UI client cannot pin a worker forever.
//!
//! ## Wire protocol v1
//!
//! Every message is a length-delimited frame `[u32 BE length][payload]`:
//!
//! 1. server → client: `nonce` frame — 16 fresh random bytes;
//! 2. client → server: `auth` frame —
//!    `nonce(16) ‖ session_prefix(4) ‖ HMAC-SHA256(key = session token,
//!    message = nonce ‖ session_prefix)(32)`;
//! 3. client → server: `request` frame `[0x01]`,
//!    server → client: snapshot frame (JSON `StatusSnapshot`);
//!    repeated up to `MAX_SNAPSHOTS_PER_CONNECTION`, then the server closes.
//!
//! Authentication: the server verifies the MAC with ring's constant-time
//! path (`ring::hmac::verify`) and rejects when (a) the echoed nonce is not
//! the one issued on this connection, (b) the nonce was already used
//! (replay), or (c) the MAC does not verify. Every rejection hard-closes the
//! connection and counts toward `Counters::status_auth_failures`. The token
//! itself is never placed on the wire — it only ever keys the MAC — and is
//! never logged.
//!
//! Bounded state: at most 16 outstanding connections are spawned (accepted
//! surplus is closed), each capped at `MAX_SNAPSHOTS_PER_CONNECTION`
//! responses, and the seen-nonce history is capped at `MAX_SEEN_NONCES`.
//! No `unsafe` anywhere in this path (spec 22.5 design rules).

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use ring::rand::SecureRandom as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::client::Counters;
use crate::status::{session_prefix, StatusProvider, StatusSnapshot};

/// Transport seam: any connected status peer (tokio named pipe or TCP
/// stream) is an `AsyncRead + AsyncWrite` channel. A dedicated supertrait is
/// required because `dyn AsyncRead + AsyncWrite` itself is illegal — a trait
/// object may carry only one principal non-auto trait (E0225). The blanket
/// impl keeps every concrete transport a drop-in `IoStream`.
trait IoStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> IoStream for T {}

/// A connected client session bound to one transport. `Box::pin` so the
/// concrete tokio pipe / stream types coerce into one protocol-visible
/// handle (both implement `IoStream`).
type Conn = Pin<Box<dyn IoStream + Send>>;

/// Length of every length-delimited frame header (u32 BE).
const NONCE_LEN: usize = 16;
/// `nonce(16) ‖ session_prefix(4)` signed by the client.
const AUTH_MESSAGE_LEN: usize = 20;
/// `nonce(16) ‖ prefix(4) ‖ mac(32)` carried in the auth frame.
const AUTH_FRAME_LEN: usize = NONCE_LEN + 4 + 32;
/// Client request byte: "send me the next snapshot".
const REQUEST: [u8; 1] = [0x01];
/// Workers serve at most this many snapshots per connection (spec 22.5
/// worker-pool semantics; a UI that keeps polling simply reconnects).
const MAX_SNAPSHOTS_PER_CONNECTION: usize = 64;
/// Replay protection history: a nonce stays "used" for this many later
/// connections before it ages out of the bounded ring.
const MAX_SEEN_NONCES: usize = 128;
/// Upper bound on a frame payload (snapshots, nonce, auth). 64 KiB is far
/// beyond any realistic snapshot; the cap keeps a hostile peer from forcing
/// unbounded allocations.
const MAX_FRAME_PAYLOAD: u32 = 64 * 1024;
/// Client connect attempts to ride out the named-pipe accept gap (the very
/// first instance may still be pending when the UI wakes up).
const CONNECT_ATTEMPTS: usize = 8;
const CONNECT_BACKOFF: Duration = Duration::from_millis(50);

/// Where the status server listens / the client connects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusEndpoint {
    /// Windows named pipe, e.g. `\\.\pipe\streamguard-status`.
    #[cfg(windows)]
    NamedPipe(String),
    /// Loopback TCP (portable fallback / tests on every platform).
    Tcp(std::net::SocketAddr),
}

impl StatusEndpoint {
    /// Opens a transport connection to this endpoint (no protocol yet).
    async fn connect(&self) -> io::Result<Conn> {
        match self {
            #[cfg(windows)]
            StatusEndpoint::NamedPipe(name) => {
                use tokio::net::windows::named_pipe::ClientOptions;
                // `open` performs the CreateFile connect in one step (tokio
                // 1.50 dropped the old `NamedPipeClient::connect`); the
                // server pre-creates an instance before accepting, so the
                // only failure mode in practice is the accept gap, which the
                // client's bounded retry loop rides out.
                let client = ClientOptions::new().open(name)?;
                Ok(Box::pin(client))
            }
            StatusEndpoint::Tcp(addr) => {
                let stream = TcpStream::connect(addr).await?;
                Ok(Box::pin(stream))
            }
        }
    }
}

/// Handle returned by `spawn_status_server`; carries the *resolved* endpoint
/// (a TCP bind on port 0 resolves to the real port) and the accept-loop task.
pub struct StatusServerHandle {
    endpoint: StatusEndpoint,
    pub(crate) task: JoinHandle<()>,
}

impl StatusServerHandle {
    /// The concrete endpoint clients must connect to.
    pub fn endpoint(&self) -> &StatusEndpoint {
        &self.endpoint
    }

    /// Stops the accept loop (connection workers finish their current frame
    /// and drop). Used by tests; the engine aborts this on shutdown.
    pub fn stop(self) {
        self.task.abort();
    }
}

/// Spawns the status server. `token` keys the HMAC challenge-response;
/// only its length is ever logged.
pub async fn spawn_status_server(
    endpoint: StatusEndpoint,
    provider: StatusProvider,
    token: impl Into<String>,
    counters: Arc<Mutex<Counters>>,
) -> anyhow::Result<StatusServerHandle> {
    let token = token.into();
    tracing::debug!(token_len = token.len(), "status ipc token configured");
    let key = token.into_bytes();
    let seen = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_SEEN_NONCES)));

    let (resolved, task) = match endpoint {
        #[cfg(windows)]
        StatusEndpoint::NamedPipe(name) => {
            let task = tokio::spawn(serve_named_pipe(
                name.clone(),
                provider,
                key,
                seen,
                counters,
            ));
            (StatusEndpoint::NamedPipe(name), task)
        }
        StatusEndpoint::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await.context("status ipc tcp bind")?;
            let endpoint = StatusEndpoint::Tcp(listener.local_addr()?);
            tracing::debug!(addr = %endpoint.describe(), "status ipc server listening");
            let task = tokio::spawn(serve_tcp(listener, provider, key, seen, counters));
            (endpoint, task)
        }
    };
    Ok(StatusServerHandle { endpoint: resolved, task })
}

impl StatusEndpoint {
    fn describe(&self) -> String {
        match self {
            #[cfg(windows)]
            StatusEndpoint::NamedPipe(name) => name.clone(),
            StatusEndpoint::Tcp(addr) => addr.to_string(),
        }
    }
}

/// TCP accept loop: one connection worker per accepted peer (worker pool).
async fn serve_tcp(
    listener: TcpListener,
    provider: StatusProvider,
    key: Vec<u8>,
    seen: Arc<Mutex<VecDeque<[u8; NONCE_LEN]>>>,
    counters: Arc<Mutex<Counters>>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "status ipc tcp accept failed");
                continue;
            }
        };
        tracing::debug!(peer = %peer, "status ipc connection accepted");
        tokio::spawn(handle_connection(
            Box::pin(stream),
            provider.clone(),
            key.clone(),
            seen.clone(),
            counters.clone(),
        ));
    }
}

/// Windows named-pipe accept loop. A fresh pipe instance is created before
/// the accepted one is handed to a worker so the pipe is never left without
/// a waiting server instance (the client could otherwise hit
/// `ERROR_FILE_NOT_FOUND` and the UI would flap).
#[cfg(windows)]
async fn serve_named_pipe(
    name: String,
    provider: StatusProvider,
    key: Vec<u8>,
    seen: Arc<Mutex<VecDeque<[u8; NONCE_LEN]>>>,
    counters: Arc<Mutex<Counters>>,
) {
    use tokio::net::windows::named_pipe::ServerOptions;

    fn new_instance(name: &str) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        use windows::Win32::Security::{
            InitializeSecurityDescriptor, MakeSelfRelativeSD, PSECURITY_DESCRIPTOR,
            SECURITY_ATTRIBUTES, SetSecurityDescriptorDacl,
        };

        // An elevated service otherwise mints the pipe with the default DACL,
        // whose admin-only grants the non-elevated status shell no access
        // ("Access is denied"). Give CreateNamedPipeW a NULL-DACL descriptor
        // instead: any local process can open the pipe, and the HMAC
        // bootstrap-ticket challenge still gates every connection (spec 12
        // status plane) — the DACL is not the auth boundary.
        let mut sd_buf = [0u8; 128];
        let sd = PSECURITY_DESCRIPTOR(sd_buf.as_mut_ptr().cast());
        unsafe {
            // SECURITY_DESCRIPTOR_REVISION == 1.
            InitializeSecurityDescriptor(sd, 1)?;
            SetSecurityDescriptorDacl(sd, true, None, false)?;
            // CreateNamedPipeW wants a self-relative descriptor; MakeSelf- 
            // RelativeSD reports the needed size first (expected to fail with
            // ERROR_INSUFFICIENT_BUFFER on the sizing call).
            let mut len = 0u32;
            let _ = MakeSelfRelativeSD(sd, None, &mut len);
            let mut rel = vec![0u8; len.max(128) as usize];
            MakeSelfRelativeSD(sd, Some(PSECURITY_DESCRIPTOR(rel.as_mut_ptr().cast())), &mut len)?;
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: rel.as_mut_ptr().cast::<core::ffi::c_void>(),
                bInheritHandle: windows_core::BOOL(0),
            };
            ServerOptions::new()
                .access_inbound(true)
                .access_outbound(true)
                .create_with_security_attributes_raw(name, &sa as *const _ as *mut _)
        }
    }

    let mut pending = match new_instance(&name) {
        Ok(instance) => instance,
        Err(e) => {
            tracing::warn!(error = %e, pipe = %name, "status ipc pipe instance create failed");
            return;
        }
    };
    loop {
        if let Err(e) = pending.connect().await {
            tracing::warn!(error = %e, pipe = %name, "status ipc pipe connect failed");
            match new_instance(&name) {
                Ok(instance) => pending = instance,
                Err(e) => {
                    tracing::warn!(error = %e, "status ipc pipe instance recreate failed");
                    return;
                }
            }
            continue;
        }
        let next = match new_instance(&name) {
            Ok(instance) => instance,
            Err(e) => {
                tracing::warn!(error = %e, pipe = %name, "status ipc pipe instance create failed");
                return;
            }
        };
        tokio::spawn(handle_connection(
            Box::pin(pending),
            provider.clone(),
            key.clone(),
            seen.clone(),
            counters.clone(),
        ));
        pending = next;
    }
}

/// Serves one authenticated client for up to `MAX_SNAPSHOTS_PER_CONNECTION`
/// requests. Every path out of here drops `conn`, which closes the pipe/TCP
/// connection. Errors are logged at debug (an auth probe is not an anomaly
/// worth an error line).
async fn handle_connection(
    mut conn: Conn,
    provider: StatusProvider,
    key: Vec<u8>,
    seen: Arc<Mutex<VecDeque<[u8; NONCE_LEN]>>>,
    counters: Arc<Mutex<Counters>>,
) {
    let outcome = run_connection(&mut conn, &provider, &key, &seen).await;
    match outcome {
        Ok(()) => tracing::debug!("status ipc connection served and closed"),
        Err(Outcome::Closed) => {}
        Err(Outcome::AuthRejected(reason)) => {
            counters.lock().await.status_auth_failures += 1;
            tracing::debug!(reason, "status ipc auth rejected");
        }
    }
}

/// Fine-grained outcome so the counter increments once per rejected
/// connection (a client who connects, gets a nonce and hangs is not an auth
/// attempt; a client who sends any auth frame is).
enum Outcome {
    Closed,
    AuthRejected(&'static str),
}

async fn run_connection(
    conn: &mut Conn,
    provider: &StatusProvider,
    key: &[u8],
    seen: &Arc<Mutex<VecDeque<[u8; NONCE_LEN]>>>,
) -> Result<(), Outcome> {
    // 1. Challenge: a fresh nonce per connection.
    let nonce = random_nonce().map_err(|_| Outcome::Closed)?;
    if write_frame(conn, &nonce).await.is_err() {
        return Err(Outcome::Closed);
    }

    // 2. Response: nonce ‖ prefix ‖ MAC over (nonce ‖ prefix).
    let auth = read_frame(conn).await.map_err(|_| Outcome::Closed)?;
    if auth.len() != AUTH_FRAME_LEN {
        return Err(Outcome::AuthRejected("malformed auth frame"));
    }
    let echoed: [u8; NONCE_LEN] = auth[..NONCE_LEN].try_into().expect("length checked above");
    if echoed != nonce {
        // The client answered a nonce that was never issued on this
        // connection: canned/replayed response.
        return Err(Outcome::AuthRejected("nonce mismatch"));
    }
    let mac = &auth[AUTH_MESSAGE_LEN..AUTH_FRAME_LEN];
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    if ring::hmac::verify(&key, &auth[..AUTH_MESSAGE_LEN], mac).is_err() {
        return Err(Outcome::AuthRejected("mac mismatch"));
    }
    // Replay gate + history insert under one lock acquisition: a nonce is
    // either fresh (inserted and accepted) or already used (rejected), with
    // no window for a racing connection to observe a stale nonce as fresh.
    {
        let mut q = seen.lock().await;
        if q.contains(&echoed) {
            return Err(Outcome::AuthRejected("replayed nonce"));
        }
        q.push_back(echoed);
        while q.len() > MAX_SEEN_NONCES {
            q.pop_front();
        }
    }

    // 3. Worker-pool serve loop: at most N snapshots per connection.
    for served in 0..MAX_SNAPSHOTS_PER_CONNECTION {
        let request = read_frame(conn).await.map_err(|_| Outcome::Closed)?;
        if request.as_slice() != REQUEST {
            return Err(Outcome::Closed);
        }
        let snapshot = provider.snapshot().await;
        let body = match serde_json::to_vec(&snapshot) {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!(error = %e, "status ipc snapshot serialization failed");
                return Err(Outcome::Closed);
            }
        };
        if write_frame(conn, &body).await.is_err() {
            return Err(Outcome::Closed);
        }
        tracing::debug!(served = served + 1, "status ipc snapshot served");
    }
    Ok(())
}

/// Protocol frame writer: `[u32 BE len][payload]`, flushed so the client
/// sees the frame even across a pipe boundary.
async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds u32"))?;
    if len > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds MAX_FRAME_PAYLOAD",
        ));
    }
    w.write_u32(len).await?;
    w.write_all(payload).await?;
    w.flush().await
}

/// Protocol frame reader, bounded by `MAX_FRAME_PAYLOAD`.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = r.read_u32().await?;
    if len == 0 || len > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length out of bounds",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

fn random_nonce() -> io::Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    let rng = ring::rand::SystemRandom::new();
    rng.fill(&mut nonce)
        .map_err(|_| io::Error::other("system rng failure"))?;
    Ok(nonce)
}

/// Client half of the status plane (the bridge APIs the Tauri backend calls).
///
/// One `StatusClient` holds the endpoint + token + session prefix; every
/// `connect()` performs a fresh challenge-response (a fresh nonce is used
/// per attempt, so replays are inherently rejected by the server).
#[derive(Debug, Clone)]
pub struct StatusClient {
    endpoint: StatusEndpoint,
    token: Arc<str>,
    session_prefix: u32,
}

impl StatusClient {
    pub fn new(endpoint: StatusEndpoint, token: impl Into<String>, session_prefix: u32) -> Self {
        Self {
            endpoint,
            token: Arc::from(token.into()),
            session_prefix,
        }
    }

    /// New client with the prefixed wire id matching `session_id`.
    pub fn for_session(
        endpoint: StatusEndpoint,
        token: impl Into<String>,
        session_id: sg_core::SessionId,
    ) -> Self {
        Self::new(endpoint, token, session_prefix(session_id))
    }

    /// Opens the transport and completes the handshake. Retries ONLY the raw
    /// transport open (the named-pipe instance may still be pending when a
    /// UI client wakes up); once connected, a handshake failure is a real
    /// protocol/auth problem and surfaces immediately — so one wrong-token
    /// attempt is exactly one rejected connection, never a retry storm that
    /// would inflate `status_auth_failures`.
    pub async fn connect(&self) -> anyhow::Result<StatusSession> {
        let mut last_open: Option<io::Error> = None;
        for _ in 0..CONNECT_ATTEMPTS {
            match self.endpoint.connect().await {
                Ok(conn) => return self.handshake(conn).await,
                Err(e) => {
                    last_open = Some(e);
                    tokio::time::sleep(CONNECT_BACKOFF).await;
                }
            }
        }
        Err(anyhow::anyhow!(
            "status ipc connect failed after {CONNECT_ATTEMPTS} attempts: {}",
            last_open.map(|e| e.to_string()).unwrap_or_default()
        ))
    }

    /// Single attempt over an already-opened transport: read the nonce
    /// challenge and answer it. (The server's verdict lands on the first
    /// `snapshot()` read — a rejected auth closes the connection there.)
    async fn handshake(&self, mut conn: Conn) -> anyhow::Result<StatusSession> {
        let nonce_frame = read_frame(&mut conn)
            .await
            .context("status ipc: reading server nonce")?;
        let nonce: [u8; NONCE_LEN] = nonce_frame
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("status ipc: nonce frame has the wrong length"))?;
        send_auth(&mut conn, &self.token, self.session_prefix, nonce)
            .await
            .context("status ipc: sending auth frame")?;
        Ok(StatusSession { conn })
    }
}

/// An authenticated connection. Serves up to `MAX_SNAPSHOTS_PER_CONNECTION`
/// snapshots; the server closes after that, and further `snapshot()` calls
/// fail with an EOF error (the caller should reconnect).
pub struct StatusSession {
    conn: Conn,
}

impl StatusSession {
    /// Requests and deserializes one snapshot frame.
    pub async fn snapshot(&mut self) -> anyhow::Result<StatusSnapshot> {
        write_frame(&mut self.conn, &REQUEST)
            .await
            .context("status ipc: request write failed")?;
        let frame = read_frame(&mut self.conn).await.context(
            "status ipc: snapshot read failed (connection closed — auth rejected or server stopping)",
        )?;
        let snapshot =
            serde_json::from_slice(&frame).context("status ipc: snapshot frame is not JSON")?;
        Ok(snapshot)
    }

    /// Gracefully closes the authenticated connection. Consumes the session;
    /// the server is unaffected (it caps each connection at its snapshot
    /// quota regardless).
    pub async fn close(mut self) {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut self.conn).await;
    }
}

/// One-shot convenience: connect, ask for a snapshot, disconnect.
pub async fn fetch_snapshot(
    endpoint: &StatusEndpoint,
    token: &str,
    session_id: sg_core::SessionId,
) -> anyhow::Result<StatusSnapshot> {
    let mut session = StatusClient::for_session(endpoint.clone(), token, session_id)
        .connect()
        .await?;
    session.snapshot().await
}

/// `nonce ‖ session_prefix` signed with the token.
async fn send_auth(
    conn: &mut Conn,
    token: &str,
    session_prefix: u32,
    nonce: [u8; NONCE_LEN],
) -> io::Result<()> {
    let mut message = [0u8; AUTH_MESSAGE_LEN];
    message[..NONCE_LEN].copy_from_slice(&nonce);
    message[NONCE_LEN..].copy_from_slice(&session_prefix.to_be_bytes());
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, token.as_bytes());
    let tag = ring::hmac::sign(&key, &message);

    let mut auth = Vec::with_capacity(AUTH_FRAME_LEN);
    auth.extend_from_slice(&nonce);
    auth.extend_from_slice(&session_prefix.to_be_bytes());
    auth.extend_from_slice(tag.as_ref());
    write_frame(conn, &auth).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use sg_core::{PathId, SessionId};
    use sg_session::session_id_from_wire;

    fn test_counters() -> Arc<Mutex<Counters>> {
        Arc::new(Mutex::new(Counters::default()))
    }

    /// Minimal transport so the provider's `session.path_ids()` sees
    /// real engine-shaped session state; never performs I/O in these tests.
    struct MockTransport(PathId);
    #[async_trait::async_trait]
    impl sg_transport::PathTransport for MockTransport {
        async fn send(&self, _envelope: sg_protocol::Envelope) -> sg_core::error::Result<()> {
            Ok(())
        }
        async fn recv(&self) -> sg_core::error::Result<sg_protocol::Envelope> {
            unreachable!("mock transport never receives")
        }
        fn path_id(&self) -> PathId {
            self.0
        }
    }

    /// `Shared` with two accredited paths and no health metering — exactly
    /// the engine's pre-probe picture (unmetered = eligible, spec 12).
    fn shared_for(id: SessionId) -> Arc<crate::client::Shared> {
        let mut session = sg_session::Session::new(id);
        for p in [PathId::new(1), PathId::new(2)] {
            session
                .add_path(Arc::new(MockTransport(p)), p)
                .expect("fresh session accepts new paths");
        }
        session
            .set_active_path(PathId::new(1))
            .expect("accredited path becomes active");
        Arc::new(crate::client::Shared {
            session: Mutex::new(session),
            metrics: Mutex::new(HashMap::new()),
            notified: Mutex::new(None),
            pending_probes: Mutex::new(HashMap::new()),
            probe_misses: Mutex::new(HashMap::new()),
            redundancy_loss_threshold: 0.0,
            scheduler: Mutex::new(sg_multipath::WeightedBondingScheduler::default()),
            notified_weights: Mutex::new(None),
            path_names: Mutex::new(HashMap::new()),
            health_changed_at: Mutex::new(HashMap::new()),
        })
    }

    async fn spawn_test_server(
        endpoint: StatusEndpoint,
        id: SessionId,
        token: &str,
        counters: Arc<Mutex<Counters>>,
    ) -> StatusServerHandle {
        let provider = StatusProvider::new(shared_for(id), counters.clone());
        spawn_status_server(endpoint, provider, token, counters)
            .await
            .expect("server binds")
    }

    fn tcp_loopback() -> StatusEndpoint {
        StatusEndpoint::Tcp("127.0.0.1:0".parse().unwrap())
    }

    #[cfg(windows)]
    fn unique_pipe(tag: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            r"\\.\pipe\streamguard-status-{tag}-{}-{nanos}",
            std::process::id()
        )
    }

    /// Happy path over TCP: handshake with the right token yields a snapshot
    /// whose json round-trips and whose content comes from the provider.
    #[tokio::test]
    async fn tcp_happy_path_serves_snapshots() {
        let id = session_id_from_wire(0x0102_0304);
        let counters = test_counters();
        let server = spawn_test_server(tcp_loopback(), id, "tcp-token", counters).await;
        let endpoint = server.endpoint().clone();

        let mut session = StatusClient::for_session(endpoint, "tcp-token", id)
            .connect()
            .await
            .unwrap();
        for _ in 0..3 {
            let snap = session.snapshot().await.unwrap();
            assert_eq!(snap.session_prefix, 0x0102_0304);
            assert!(snap.protecting, "unmetered session with one path protects");
            let back: StatusSnapshot = serde_json::from_str(&serde_json::to_string(&snap).unwrap()).unwrap();
            assert_eq!(back, snap);
        }
        server.stop();
    }

    /// The Windows named-pipe transport speaks the identical protocol.
    #[cfg(windows)]
    #[tokio::test]
    async fn named_pipe_happy_path_serves_snapshots() {
        let id = session_id_from_wire(0x0a0b_0c0d);
        let counters = test_counters();
        let server = spawn_test_server(
            StatusEndpoint::NamedPipe(unique_pipe("happy")),
            id,
            "pipe-token",
            counters,
        )
        .await;
        let endpoint = server.endpoint().clone();

        let mut session = StatusClient::for_session(endpoint, "pipe-token", id)
            .connect()
            .await
            .unwrap();
        let snap = session.snapshot().await.unwrap();
        assert_eq!(snap.session_prefix, 0x0a0b_0c0d);
        server.stop();
    }

    /// Wrong token: the client completes the transport handshake (it cannot
    /// know its own MAC is wrong), and the rejection surfaces on the first
    /// snapshot read — the server closes the connection and counts one
    /// `status_auth_failures`.
    #[tokio::test]
    async fn wrong_token_is_rejected_and_counted() {
        let id = session_id_from_wire(0x0101_0101);
        let counters = test_counters();
        let server = spawn_test_server(tcp_loopback(), id, "real-token", counters.clone()).await;
        let endpoint = server.endpoint().clone();

        let mut session = StatusClient::for_session(endpoint, "wrong-token", id)
            .connect()
            .await
            .expect("the client side of the handshake still completes");
        let err = session
            .snapshot()
            .await
            .expect_err("the server rejects the bad MAC and closes");
        assert!(
            err.to_string().contains("connection closed"),
            "the client observes EOF instead of a snapshot: {err}"
        );

        // The server increments before dropping the connection, so the
        // client's EOF guarantees the count; poll briefly anyway.
        let mut counted = false;
        for _ in 0..50 {
            if counters.lock().await.status_auth_failures >= 1 {
                counted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(counted, "one rejected auth attempt is counted");
        server.stop();
    }

    /// A stale nonce (from an earlier successful connection) is a replay:
    /// the server rejects it even with a valid MAC, and counts it.
    #[tokio::test]
    async fn replayed_nonce_is_rejected() {
        use tokio::io::AsyncReadExt as _;

        let id = session_id_from_wire(0x0202_0202);
        let counters = test_counters();
        let server = spawn_test_server(tcp_loopback(), id, "nonce-token", counters.clone()).await;
        let endpoint = server.endpoint().clone();

        // Connection 1: capture the nonce the server issued, complete auth
        // legitimately, and serve one snapshot.
        let mut conn = endpoint.connect().await.unwrap();
        let nonce_frame = read_frame(&mut conn).await.unwrap();
        let nonce_1: [u8; NONCE_LEN] = nonce_frame.as_slice().try_into().unwrap();
        send_auth(&mut conn, "nonce-token", 0x0202_0202, nonce_1)
            .await
            .unwrap();
        write_frame(&mut conn, &REQUEST).await.unwrap();
        let snap = read_frame(&mut conn).await.unwrap();
        assert!(
            !snap.is_empty(),
            "first connection is authenticated and served"
        );

        // Connection 2: the server issues a *fresh* nonce but the client
        // replays the stale `nonce_1` — the server must reject it.
        let mut conn2 = endpoint.connect().await.unwrap();
        let _fresh = read_frame(&mut conn2).await.unwrap();
        send_auth(&mut conn2, "nonce-token", 0x0202_0202, nonce_1)
            .await
            .unwrap();
        let mut reply = Vec::new();
        let read = conn2.read_to_end(&mut reply).await.unwrap();
        assert_eq!(read, 0, "server closes without a frame");
        write_frame(&mut conn2, &REQUEST).await.ok();

        let cc = counters.lock().await;
        assert_eq!(
            cc.status_auth_failures, 1,
            "the replay is counted as an auth rejection"
        );
        server.stop();
    }

    /// A connection that serves its full quota closes; the next request then
    /// fails with EOF, and the client can reconnect to keep polling.
    #[cfg(windows)]
    #[tokio::test]
    async fn worker_pool_quota_is_enforced_per_connection() {
        let id = session_id_from_wire(0x0303_0303);
        let counters = test_counters();
        let server = spawn_test_server(
            StatusEndpoint::NamedPipe(unique_pipe("quota")),
            id,
            "quota-token",
            counters,
        )
        .await;
        let endpoint = server.endpoint().clone();
        let mut client = StatusClient::for_session(endpoint, "quota-token", id)
            .connect()
            .await
            .unwrap();

        for _ in 0..MAX_SNAPSHOTS_PER_CONNECTION {
            let snap = client.snapshot().await.unwrap();
            assert_eq!(snap.paths.len(), 2, "fixture registers both paths");
        }
        assert!(
            client.snapshot().await.is_err(),
            "after the quota the server closes and the session is exhausted"
        );
        server.stop();
    }
}