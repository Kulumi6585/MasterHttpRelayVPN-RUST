//! SNI reachability probes.
//!
//! Given a fixed `google_ip`, test which SNI strings the path between here and
//! Google's edge actually lets through. Iran's DPI blocks specific SNI strings
//! (`mail.google.com` has been targeted at various times; `translate.google.com`
//! has been on/off; etc.) while others co-hosted on the exact same IP pass
//! through. This module exposes the probe logic used by both the `test-sni`
//! CLI subcommand and the UI's per-row **Test** / **Test all** buttons.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::config::Config;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const CONCURRENCY: usize = 8;

/// Outcome of a single SNI probe.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
}

impl ProbeResult {
    pub fn is_ok(&self) -> bool {
        self.latency_ms.is_some()
    }
}

/// Probe one (google_ip, sni) pair. Succeeds if we can complete a TLS
/// handshake with the given SNI against `google_ip:443`. Does not do an HTTP
/// request on top — handshake completion alone proves the SNI isn't blocked
/// by DPI and the IP accepts the fronting.
pub async fn probe_one(google_ip: &str, sni: &str) -> ProbeResult {
    let tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));
    probe_with(google_ip, sni, connector).await
}

/// Probe every SNI in `snis` in parallel (bounded to CONCURRENCY).
/// Results come back in the same order as the input.
pub async fn probe_all(google_ip: &str, snis: Vec<String>) -> Vec<(String, ProbeResult)> {
    let tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let mut tasks = Vec::with_capacity(snis.len());
    for sni in snis.iter() {
        let connector = connector.clone();
        let sem = sem.clone();
        let sni_clone = sni.clone();
        let ip = google_ip.to_string();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            (sni_clone.clone(), probe_with(&ip, &sni_clone, connector).await)
        }));
    }
    let mut out = Vec::with_capacity(tasks.len());
    for t in tasks {
        if let Ok(r) = t.await {
            out.push(r);
        }
    }
    // Re-sort into input order (task scheduling may shuffle).
    let mut indexed: Vec<(String, ProbeResult)> = Vec::with_capacity(out.len());
    for sni in snis {
        if let Some(pos) = out.iter().position(|(s, _)| s == &sni) {
            indexed.push(out.remove(pos));
        }
    }
    indexed
}

async fn probe_with(google_ip: &str, sni: &str, connector: TlsConnector) -> ProbeResult {
    let start = Instant::now();

    // DNS sanity check first. Google's GFE returns a valid wildcard cert for
    // ANY *.google.com SNI (including typos and gibberish), so a successful
    // TLS handshake alone doesn't prove the name actually exists. Resolving
    // catches typos and random strings before they show a misleading "ok".
    // We still only connect to the configured google_ip — the resolve is
    // purely an existence check.
    let resolve_target = format!("{}:443", sni);
    let resolved = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host(resolve_target),
    )
    .await;
    match resolved {
        Ok(Ok(mut iter)) => {
            if iter.next().is_none() {
                return ProbeResult {
                    latency_ms: None,
                    error: Some("dns: no addresses".into()),
                };
            }
        }
        Ok(Err(e)) => {
            return ProbeResult {
                latency_ms: None,
                error: Some(format!("dns: {}", truncate_reason(&e.to_string(), 32))),
            };
        }
        Err(_) => {
            return ProbeResult {
                latency_ms: None,
                error: Some("dns timeout".into()),
            };
        }
    }

    let addr: SocketAddr = match format!("{}:443", google_ip).parse() {
        Ok(a) => a,
        Err(e) => {
            return ProbeResult {
                latency_ms: None,
                error: Some(format!("bad ip: {}", e)),
            };
        }
    };

    let tcp = match tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return ProbeResult {
                latency_ms: None,
                error: Some(format!("connect: {}", e)),
            };
        }
        Err(_) => {
            return ProbeResult {
                latency_ms: None,
                error: Some("connect timeout".into()),
            };
        }
    };
    let _ = tcp.set_nodelay(true);

    let server_name = match ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(e) => {
            return ProbeResult {
                latency_ms: None,
                error: Some(format!("bad sni: {}", e)),
            };
        }
    };

    let mut tls = match tokio::time::timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp))
        .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            // DPI that blocks the SNI typically kills the handshake here.
            let emsg = e.to_string();
            let reason = if emsg.contains("reset") || emsg.contains("peer") {
                "handshake RST (SNI may be blocked)".into()
            } else {
                format!("tls: {}", emsg)
            };
            return ProbeResult {
                latency_ms: None,
                error: Some(reason),
            };
        }
        Err(_) => {
            return ProbeResult {
                latency_ms: None,
                error: Some("tls handshake timeout".into()),
            };
        }
    };

    // Handshake completed — SNI passed. Do a tiny HEAD to confirm the other
    // side actually speaks HTTP (catches weird misroutes).
    let req = b"HEAD / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    if tls.write_all(req).await.is_err() {
        return ProbeResult {
            latency_ms: None,
            error: Some("write failed".into()),
        };
    }
    let _ = tls.flush().await;

    let mut buf = [0u8; 64];
    match tokio::time::timeout(PROBE_TIMEOUT, tls.read(&mut buf)).await {
        Ok(Ok(n)) if n >= 5 && buf.starts_with(b"HTTP/") => {
            let elapsed = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
            ProbeResult {
                latency_ms: Some(elapsed),
                error: None,
            }
        }
        Ok(Ok(_)) => ProbeResult {
            latency_ms: None,
            error: Some("non-HTTP reply".into()),
        },
        Ok(Err(e)) => ProbeResult {
            latency_ms: None,
            error: Some(format!("read: {}", e)),
        },
        Err(_) => ProbeResult {
            latency_ms: None,
            error: Some("read timeout".into()),
        },
    }
}

/// `mhrv-rs test-sni` CLI entry point. Probes every SNI in the active pool
/// (either the user's `sni_hosts` list or the auto-expanded default from
/// `front_domain`) against `google_ip` and prints a sorted table.
pub async fn run(config: &Config) -> bool {
    use crate::domain_fronter::build_sni_pool_for;
    let pool = build_sni_pool_for(
        &config.front_domain,
        config.sni_hosts.as_deref().unwrap_or(&[]),
    );
    println!(
        "Probing {} SNI candidate(s) against google_ip={} (TCP+TLS, timeout={}s)...",
        pool.len(),
        config.google_ip,
        PROBE_TIMEOUT.as_secs()
    );
    println!();

    let mut results = probe_all(&config.google_ip, pool).await;
    results.sort_by_key(|(_, r)| r.latency_ms.unwrap_or(u32::MAX));

    println!("{:<36} {:>10}  {}", "SNI", "LATENCY", "STATUS");
    println!("{:-<36} {:->10}  {}", "", "", "------");
    let mut ok_count = 0usize;
    for (sni, r) in &results {
        match r.latency_ms {
            Some(ms) => {
                println!("{:<36} {:>8}ms  ok", sni, ms);
                ok_count += 1;
            }
            None => {
                let err = r.error.as_deref().unwrap_or("failed");
                println!("{:<36} {:>10}  {}", sni, "-", err);
            }
        }
    }
    println!();
    println!("Working: {} / {}", ok_count, results.len());
    ok_count > 0
}

fn truncate_reason(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Strip newlines / extra junk for clean UI display.
        let cleaned: String = s.chars().take(max).filter(|c| !c.is_control()).collect();
        cleaned
    }
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
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
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
