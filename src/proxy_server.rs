use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::Config;
use crate::domain_fronter::DomainFronter;
use crate::mitm::MitmCertManager;

// Domains that are served from Google's core frontend IP pool and therefore
// respond correctly when we connect to `google_ip` with SNI=`front_domain`
// and Host=<the real domain>. Routing these via the tunnel instead of the
// Apps Script relay also avoids Apps Script's fixed "Google-Apps-Script"
// User-Agent, which makes Google serve the bot/no-JS fallback for search.
// Kept conservative: anything on a separate CDN (googlevideo, ytimg,
// doubleclick, etc.) is DROPPED because routing to the wrong backend breaks
// rather than helps. Those fall through to MITM+relay (slower but works).
// Domains that are hosted on the Google Front End and therefore reachable via
// the same SNI-rewrite tunnel used for www.google.com itself. Adding a suffix
// here means "TLS CONNECT to google_ip, SNI = front_domain, Host = real name"
// for requests to it — bypassing the Apps Script relay entirely, so there's no
// User-Agent locking and no Apps Script quota.
// When in doubt leave it out: sites that aren't actually on GFE will 404 or
// return a wrong-cert error instead of loading.
const SNI_REWRITE_SUFFIXES: &[&str] = &[
    // Core Google
    "google.com",
    "gstatic.com",
    "googleusercontent.com",
    "googleapis.com",
    "ggpht.com",
    // YouTube family
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "ytimg.com",
    // Blogger / Blog.google
    "blogspot.com",
    "blogger.com",
];

fn matches_sni_rewrite(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    SNI_REWRITE_SUFFIXES
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
}

fn hosts_override<'a>(
    hosts: &'a std::collections::HashMap<String, String>,
    host: &str,
) -> Option<&'a str> {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if let Some(ip) = hosts.get(h) {
        return Some(ip.as_str());
    }
    let parts: Vec<&str> = h.split('.').collect();
    for i in 1..parts.len() {
        let parent = parts[i..].join(".");
        if let Some(ip) = hosts.get(&parent) {
            return Some(ip.as_str());
        }
    }
    None
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct ProxyServer {
    host: String,
    port: u16,
    socks5_port: u16,
    fronter: Arc<DomainFronter>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
}

pub struct RewriteCtx {
    pub google_ip: String,
    pub front_domain: String,
    pub hosts: std::collections::HashMap<String, String>,
    pub tls_connector: TlsConnector,
    pub upstream_socks5: Option<String>,
}

impl ProxyServer {
    pub fn new(config: &Config, mitm: Arc<Mutex<MitmCertManager>>) -> Result<Self, ProxyError> {
        let fronter = DomainFronter::new(config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;

        let tls_config = if config.verify_ssl {
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth()
        };
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        let rewrite_ctx = Arc::new(RewriteCtx {
            google_ip: config.google_ip.clone(),
            front_domain: config.front_domain.clone(),
            hosts: config.hosts.clone(),
            tls_connector,
            upstream_socks5: config.upstream_socks5.clone(),
        });

        let socks5_port = config.socks5_port.unwrap_or(config.listen_port + 1);

        Ok(Self {
            host: config.listen_host.clone(),
            port: config.listen_port,
            socks5_port,
            fronter: Arc::new(fronter),
            mitm,
            rewrite_ctx,
        })
    }

    pub fn fronter(&self) -> Arc<DomainFronter> {
        self.fronter.clone()
    }
    pub async fn run(
        self,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), ProxyError> {
        let http_addr = format!("{}:{}", self.host, self.port);
        let socks_addr = format!("{}:{}", self.host, self.socks5_port);
        let http_listener = TcpListener::bind(&http_addr).await?;
        let socks_listener = TcpListener::bind(&socks_addr).await?;
        tracing::warn!(
            "Listening HTTP   on {} — set your browser HTTP proxy to this address.",
            http_addr
        );
        tracing::warn!(
            "Listening SOCKS5 on {} — xray / Telegram / app-level SOCKS5 clients use this.",
            socks_addr
        );
        // Pre-warm the outbound connection pool so the user's first request
        // doesn't pay a fresh TLS handshake to Google edge. Best-effort;
        // failures are logged and ignored.
        let warm_fronter = self.fronter.clone();
        tokio::spawn(async move {
            warm_fronter.warm(3).await;
        });

        let stats_fronter = self.fronter.clone();
        let stats_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let s = stats_fronter.snapshot_stats();
                if s.relay_calls > 0 || s.cache_hits > 0 {
                    tracing::info!("{}", s.fmt_line());
                }
            }
        });

        let http_fronter = self.fronter.clone();
        let http_mitm = self.mitm.clone();
        let http_ctx = self.rewrite_ctx.clone();
        let mut http_task = tokio::spawn(async move {
            loop {
                let (sock, peer) = match http_listener.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::error!("accept (http): {}", e);
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let fronter = http_fronter.clone();
                let mitm = http_mitm.clone();
                let rewrite_ctx = http_ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_http_client(sock, fronter, mitm, rewrite_ctx).await {
                        tracing::debug!("http client {} closed: {}", peer, e);
                    }
                });
            }
        });

        let socks_fronter = self.fronter.clone();
        let socks_mitm = self.mitm.clone();
        let socks_ctx = self.rewrite_ctx.clone();
        let mut socks_task = tokio::spawn(async move {
            loop {
                let (sock, peer) = match socks_listener.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::error!("accept (socks): {}", e);
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let fronter = socks_fronter.clone();
                let mitm = socks_mitm.clone();
                let rewrite_ctx = socks_ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_client(sock, fronter, mitm, rewrite_ctx).await {
                        tracing::debug!("socks client {} closed: {}", peer, e);
                    }
                });
            }
        });

        tokio::select! {
            biased;
            _ = &mut shutdown_rx => {
                tracing::info!("Shutdown signal received, stopping listeners");
                stats_task.abort();
                http_task.abort();
                socks_task.abort();
            }
            _ = &mut http_task => {}
            _ = &mut socks_task => {}
        }

        Ok(())
    }
}

async fn handle_http_client(
    mut sock: TcpStream,
    fronter: Arc<DomainFronter>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
) -> std::io::Result<()> {
    let (head, leftover) = match read_http_head(&mut sock).await? {
        Some(v) => v,
        None => return Ok(()),
    };

    let (method, target, _version, _headers) = parse_request_head(&head)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(&target);
        sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        sock.flush().await?;
        dispatch_tunnel(sock, host, port, fronter, mitm, rewrite_ctx).await
    } else {
        do_plain_http(sock, &head, &leftover, fronter).await
    }
}

// ---------- SOCKS5 ----------

async fn handle_socks5_client(
    mut sock: TcpStream,
    fronter: Arc<DomainFronter>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
) -> std::io::Result<()> {
    // RFC 1928 handshake: VER=5, NMETHODS, METHODS...
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Ok(());
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    // Only "no auth" (0x00) is supported.
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xff]).await?;
        return Ok(());
    }
    sock.write_all(&[0x05, 0x00]).await?;

    // Request: VER=5, CMD, RSV=0, ATYP, DST.ADDR, DST.PORT
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Ok(());
    }
    let cmd = req[1];
    if cmd != 0x01 {
        // CONNECT only.
        sock.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }
    let atyp = req[3];
    let host: String = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            sock.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        0x04 => {
            let mut ip = [0u8; 16];
            sock.read_exact(&mut ip).await?;
            let addr = std::net::Ipv6Addr::from(ip);
            addr.to_string()
        }
        _ => {
            sock.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };
    let mut port_buf = [0u8; 2];
    sock.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    tracing::info!("SOCKS5 CONNECT -> {}:{}", host, port);

    // Success reply with zeroed BND.
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    sock.flush().await?;

    dispatch_tunnel(sock, host, port, fronter, mitm, rewrite_ctx).await
}

// ---------- Smart dispatch (used by both HTTP CONNECT and SOCKS5) ----------

async fn dispatch_tunnel(
    sock: TcpStream,
    host: String,
    port: u16,
    fronter: Arc<DomainFronter>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
) -> std::io::Result<()> {
    // 1. Explicit hosts override or SNI-rewrite suffix: always use the tunnel.
    if matches_sni_rewrite(&host) || hosts_override(&rewrite_ctx.hosts, &host).is_some() {
        return do_sni_rewrite_tunnel_from_tcp(sock, &host, port, mitm, rewrite_ctx).await;
    }

    // 2. Peek at the first byte to detect TLS vs plain. Time-bounded — if the
    //    client doesn't send anything within 300ms, assume server-first
    //    protocol (SMTP, POP3, FTP banner) and jump straight to plain TCP.
    let mut peek_buf = [0u8; 8];
    let peek_n = match tokio::time::timeout(
        std::time::Duration::from_millis(300),
        sock.peek(&mut peek_buf),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => return Ok(()),
        Err(_) => {
            // Client silent: likely a server-first protocol.
            plain_tcp_passthrough(sock, &host, port, rewrite_ctx.upstream_socks5.as_deref()).await;
            return Ok(());
        }
    };

    if peek_n >= 1 && peek_buf[0] == 0x16 {
        // Looks like TLS: MITM + relay via Apps Script.
        run_mitm_then_relay(sock, &host, port, mitm, &fronter).await;
        return Ok(());
    }

    // 3. Not TLS. If bytes look like HTTP, relay on scheme=http. Otherwise
    //    fall back to plain TCP passthrough.
    if peek_n > 0 && looks_like_http(&peek_buf[..peek_n]) {
        let scheme = if port == 443 { "https" } else { "http" };
        relay_http_stream_raw(sock, &host, port, scheme, &fronter).await;
        return Ok(());
    }

    plain_tcp_passthrough(sock, &host, port, rewrite_ctx.upstream_socks5.as_deref()).await;
    Ok(())
}

// ---------- Plain TCP passthrough ----------

async fn plain_tcp_passthrough(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    upstream_socks5: Option<&str>,
) {
    let target_host = host.trim_start_matches('[').trim_end_matches(']');
    let upstream = if let Some(proxy) = upstream_socks5 {
        match socks5_connect_via(proxy, target_host, port).await {
            Ok(s) => {
                tracing::info!("tcp via upstream-socks5 {} -> {}:{}", proxy, host, port);
                s
            }
            Err(e) => {
                tracing::warn!(
                    "upstream-socks5 {} -> {}:{} failed: {} (falling back to direct)",
                    proxy,
                    host,
                    port,
                    e
                );
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    TcpStream::connect((target_host, port)),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    _ => return,
                }
            }
        }
    } else {
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect((target_host, port)),
        )
        .await
        {
            Ok(Ok(s)) => {
                tracing::info!("plain-tcp passthrough -> {}:{}", host, port);
                s
            }
            Ok(Err(e)) => {
                tracing::debug!("plain-tcp connect {}:{} failed: {}", host, port, e);
                return;
            }
            Err(_) => {
                tracing::debug!("plain-tcp connect {}:{} timeout", host, port);
                return;
            }
        }
    };
    let _ = upstream.set_nodelay(true);
    let (mut ar, mut aw) = sock.split();
    let (mut br, mut bw) = {
        let (r, w) = upstream.into_split();
        (r, w)
    };
    let t1 = tokio::io::copy(&mut ar, &mut bw);
    let t2 = tokio::io::copy(&mut br, &mut aw);
    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }
}

/// Open a TCP stream to `(host, port)` through an upstream SOCKS5 proxy
/// (no-auth only). Returns the connected stream after SOCKS5 negotiation.
async fn socks5_connect_via(proxy: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    let mut s = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(proxy))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    let _ = s.set_nodelay(true);

    // Greeting: VER=5, NMETHODS=1, METHOD=no-auth
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("socks5 greet rejected: {:?}", reply),
        ));
    }

    // CONNECT request: VER=5, CMD=1, RSV=0, ATYP=3 (domain) | 1 (IPv4) | 4 (IPv6)
    let mut req: Vec<u8> = Vec::with_capacity(8 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&v6.octets());
    } else {
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hostname > 255",
            ));
        }
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    // Reply header: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("socks5 connect rejected rep=0x{:02x}", head[1]),
        ));
    }
    // Skip BND.ADDR + BND.PORT.
    match head[3] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            s.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            s.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut name).await?;
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("socks5 bad ATYP in reply: {}", other),
            ));
        }
    }
    Ok(s)
}

fn looks_like_http(first_bytes: &[u8]) -> bool {
    // Cheap sniff: must start with an ASCII HTTP method token followed by a space.
    for m in [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "CONNECT ", "TRACE ",
    ] {
        if first_bytes.starts_with(m.as_bytes()) {
            return true;
        }
    }
    false
}

/// Read an HTTP head (request line + headers) up to the first \r\n\r\n.
/// Returns (head_bytes, leftover_after_head). The leftover may contain part
/// of the request body already received.
async fn read_http_head(sock: &mut TcpStream) -> std::io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF mid-header",
                ))
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            let head = buf[..pos].to_vec();
            let leftover = buf[pos..].to_vec();
            return Ok(Some((head, leftover)));
        }
        if buf.len() > 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_request_head(head: &[u8]) -> Option<(String, String, String, Vec<(String, String)>)> {
    let s = std::str::from_utf8(head).ok()?;
    let mut lines = s.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if !is_valid_http_method(&method) {
        return None;
    }

    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some((method, target, version, headers))
}

fn is_valid_http_method(m: &str) -> bool {
    matches!(
        m,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE" | "CONNECT"
    )
}

// ---------- CONNECT handling ----------

async fn run_mitm_then_relay(
    sock: TcpStream,
    host: &str,
    port: u16,
    mitm: Arc<Mutex<MitmCertManager>>,
    fronter: &DomainFronter,
) {
    tracing::info!("MITM TLS -> {}:{}", host, port);

    let server_config = {
        let mut m = mitm.lock().await;
        match m.get_server_config(host) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("cert gen failed for {}: {}", host, e);
                return;
            }
        }
    };
    let acceptor = TlsAcceptor::from(server_config);

    let mut tls = match acceptor.accept(sock).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("TLS accept failed for {}: {}", host, e);
            return;
        }
    };

    // Keep-alive loop: read HTTP requests from the decrypted stream.
    // scheme=https because we MITM-terminated TLS.
    loop {
        match handle_mitm_request(&mut tls, host, port, fronter, "https").await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                tracing::debug!("MITM handler error for {}: {}", host, e);
                break;
            }
        }
    }
}

// ---------- Plain HTTP relay on a raw TCP stream (port 80 targets) ----------

async fn relay_http_stream_raw(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    scheme: &str,
    fronter: &DomainFronter,
) {
    loop {
        match handle_mitm_request(&mut sock, host, port, fronter, scheme).await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                tracing::debug!("http relay error for {}: {}", host, e);
                break;
            }
        }
    }
}

async fn do_sni_rewrite_tunnel_from_tcp(
    sock: TcpStream,
    host: &str,
    port: u16,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
) -> std::io::Result<()> {
    let target_ip = hosts_override(&rewrite_ctx.hosts, host)
        .map(|s| s.to_string())
        .unwrap_or_else(|| rewrite_ctx.google_ip.clone());

    tracing::info!(
        "SNI-rewrite tunnel -> {}:{} via {} (outbound SNI={})",
        host,
        port,
        target_ip,
        rewrite_ctx.front_domain
    );

    // Accept browser TLS with a cert we sign for `host`.
    let server_config = {
        let mut m = mitm.lock().await;
        match m.get_server_config(host) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("cert gen failed for {}: {}", host, e);
                return Ok(());
            }
        }
    };
    let inbound = match TlsAcceptor::from(server_config).accept(sock).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("inbound TLS accept failed for {}: {}", host, e);
            return Ok(());
        }
    };

    // Open outbound TLS to google_ip with SNI=front_domain.
    let upstream_tcp = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect((target_ip.as_str(), port)),
    )
    .await
    {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            s
        }
        Ok(Err(e)) => {
            tracing::debug!("upstream connect failed for {}: {}", host, e);
            return Ok(());
        }
        Err(_) => {
            tracing::debug!("upstream connect timeout for {}", host);
            return Ok(());
        }
    };
    let _ = upstream_tcp.set_nodelay(true);

    let server_name = match ServerName::try_from(rewrite_ctx.front_domain.clone()) {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("invalid front_domain '{}': {}", rewrite_ctx.front_domain, e);
            return Ok(());
        }
    };
    let outbound = match rewrite_ctx
        .tls_connector
        .connect(server_name, upstream_tcp)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("outbound TLS connect failed for {}: {}", host, e);
            return Ok(());
        }
    };

    // Bridge decrypted bytes between the two TLS streams.
    let (mut ir, mut iw) = tokio::io::split(inbound);
    let (mut or, mut ow) = tokio::io::split(outbound);
    let client_to_server = async { tokio::io::copy(&mut ir, &mut ow).await };
    let server_to_client = async { tokio::io::copy(&mut or, &mut iw).await };
    tokio::select! {
        _ = client_to_server => {}
        _ = server_to_client => {}
    }
    Ok(())
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn parse_host_port(target: &str) -> (String, u16) {
    if let Some((h, p)) = target.rsplit_once(':') {
        let port: u16 = p.parse().unwrap_or(443);
        (h.to_string(), port)
    } else {
        (target.to_string(), 443)
    }
}

async fn handle_mitm_request<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    fronter: &DomainFronter,
    scheme: &str,
) -> std::io::Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (head, leftover) = match read_http_head_io(stream).await? {
        Some(v) => v,
        None => return Ok(false),
    };

    let (method, path, _version, headers) = match parse_request_head(&head) {
        Some(v) => v,
        None => return Ok(false),
    };

    // Read body if content-length is set.
    let body = read_body(stream, &leftover, &headers).await?;

    let default_port = if scheme == "https" { 443 } else { 80 };
    let url = if port == default_port {
        format!("{}://{}{}", scheme, host, path)
    } else {
        format!("{}://{}:{}{}", scheme, host, port, path)
    };

    tracing::info!("relay {} {}", method, url);

    let response = fronter.relay(&method, &url, &headers, &body).await;
    stream.write_all(&response).await?;
    stream.flush().await?;

    // Keep-alive unless the client asked to close.
    let connection_close = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
    Ok(!connection_close)
}

async fn read_http_head_io<S>(stream: &mut S) -> std::io::Result<Option<(Vec<u8>, Vec<u8>)>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF mid-header",
                ))
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            let head = buf[..pos].to_vec();
            let leftover = buf[pos..].to_vec();
            return Ok(Some((head, leftover)));
        }
        if buf.len() > 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    }
}

async fn read_body<S>(
    stream: &mut S,
    leftover: &[u8],
    headers: &[(String, String)],
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let cl: Option<usize> = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok());

    let Some(cl) = cl else {
        return Ok(Vec::new());
    };
    let mut body = Vec::with_capacity(cl);
    body.extend_from_slice(&leftover[..leftover.len().min(cl)]);
    let mut tmp = [0u8; 8192];
    while body.len() < cl {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        let need = cl - body.len();
        body.extend_from_slice(&tmp[..n.min(need)]);
    }
    Ok(body)
}

// ---------- Plain HTTP proxy ----------

async fn do_plain_http(
    mut sock: TcpStream,
    head: &[u8],
    leftover: &[u8],
    fronter: Arc<DomainFronter>,
) -> std::io::Result<()> {
    let (method, target, _version, headers) = parse_request_head(head)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))?;

    let body = read_body(&mut sock, leftover, &headers).await?;

    // Browser sends `GET http://example.com/path HTTP/1.1` on plain proxy.
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.clone()
    } else {
        // Fallback: stitch Host header with path.
        let host = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        format!("http://{}{}", host, target)
    };

    tracing::info!("HTTP {} {}", method, url);
    let response = fronter.relay(&method, &url, &headers, &body).await;
    sock.write_all(&response).await?;
    sock.flush().await?;
    Ok(())
}
