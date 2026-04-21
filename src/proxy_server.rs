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
const SNI_REWRITE_SUFFIXES: &[&str] = &[
    "google.com",
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "fonts.googleapis.com",
];

fn matches_sni_rewrite(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    SNI_REWRITE_SUFFIXES
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
}

fn hosts_override<'a>(hosts: &'a std::collections::HashMap<String, String>, host: &str) -> Option<&'a str> {
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
    fronter: Arc<DomainFronter>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
}

pub struct RewriteCtx {
    pub google_ip: String,
    pub front_domain: String,
    pub hosts: std::collections::HashMap<String, String>,
    pub tls_connector: TlsConnector,
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
        });

        Ok(Self {
            host: config.listen_host.clone(),
            port: config.listen_port,
            fronter: Arc::new(fronter),
            mitm,
            rewrite_ctx,
        })
    }

    pub async fn run(self) -> Result<(), ProxyError> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await?;
        tracing::warn!(
            "Listening on {} — set your browser HTTP proxy to this address.",
            addr
        );

        // Periodic stats log (every 60s at info level).
        let stats_fronter = self.fronter.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // drop the immediate first tick
            loop {
                ticker.tick().await;
                let s = stats_fronter.snapshot_stats();
                if s.relay_calls > 0 || s.cache_hits > 0 {
                    tracing::info!("{}", s.fmt_line());
                }
            }
        });

        loop {
            let (sock, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::error!("accept error: {}", e);
                    continue;
                }
            };
            let _ = sock.set_nodelay(true);
            let fronter = self.fronter.clone();
            let mitm = self.mitm.clone();
            let rewrite_ctx = self.rewrite_ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(sock, fronter, mitm, rewrite_ctx).await {
                    tracing::debug!("client {} closed: {}", peer, e);
                }
            });
        }
    }
}

async fn handle_client(
    mut sock: TcpStream,
    fronter: Arc<DomainFronter>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
) -> std::io::Result<()> {
    // Read the first request (head only).
    let (head, leftover) = match read_http_head(&mut sock).await? {
        Some(v) => v,
        None => return Ok(()),
    };

    let (method, target, _version, _headers) = parse_request_head(&head)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(&target);
        if matches_sni_rewrite(&host) || hosts_override(&rewrite_ctx.hosts, &host).is_some() {
            do_sni_rewrite_connect(sock, &host, port, mitm, rewrite_ctx).await
        } else {
            do_connect(sock, &target, fronter, mitm).await
        }
    } else {
        do_plain_http(sock, &head, &leftover, fronter).await
    }
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
        "GET"
            | "POST"
            | "PUT"
            | "DELETE"
            | "HEAD"
            | "OPTIONS"
            | "PATCH"
            | "TRACE"
            | "CONNECT"
    )
}

// ---------- CONNECT handling ----------

async fn do_connect(
    mut sock: TcpStream,
    target: &str,
    fronter: Arc<DomainFronter>,
    mitm: Arc<Mutex<MitmCertManager>>,
) -> std::io::Result<()> {
    let (host, port) = parse_host_port(target);
    tracing::info!("CONNECT -> {}:{}", host, port);

    sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    sock.flush().await?;

    // MITM: build a server config for this domain and accept TLS.
    let server_config = {
        let mut m = mitm.lock().await;
        match m.get_server_config(&host) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("cert gen failed for {}: {}", host, e);
                return Ok(());
            }
        }
    };
    let acceptor = TlsAcceptor::from(server_config);

    let mut tls = match acceptor.accept(sock).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("TLS accept failed for {}: {}", host, e);
            return Ok(());
        }
    };

    // Keep-alive loop: read HTTP requests from the decrypted stream.
    loop {
        match handle_mitm_request(&mut tls, &host, port, &fronter).await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                tracing::debug!("MITM handler error for {}: {}", host, e);
                break;
            }
        }
    }
    Ok(())
}

async fn do_sni_rewrite_connect(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
) -> std::io::Result<()> {
    sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    sock.flush().await?;

    let target_ip = hosts_override(&rewrite_ctx.hosts, host)
        .map(|s| s.to_string())
        .unwrap_or_else(|| rewrite_ctx.google_ip.clone());

    tracing::info!(
        "SNI-rewrite tunnel -> {}:{} via {} (outbound SNI={})",
        host, port, target_ip, rewrite_ctx.front_domain
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
        Ok(Ok(s)) => s,
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

    let url = if port == 443 {
        format!("https://{}{}", host, path)
    } else {
        format!("https://{}:{}{}", host, port, path)
    };

    tracing::info!("MITM {} {}", method, url);

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
