use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use mhrv_rs::cert_installer::install_ca;
use mhrv_rs::config::{Config, ScriptId};
use mhrv_rs::data_dir;
use mhrv_rs::domain_fronter::{DomainFronter, DEFAULT_GOOGLE_SNI_POOL};
use mhrv_rs::mitm::{MitmCertManager, CA_CERT_FILE};
use mhrv_rs::proxy_server::ProxyServer;
use mhrv_rs::{scan_ips, scan_sni, test_cmd};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const WIN_WIDTH: f32 = 520.0;
const WIN_HEIGHT: f32 = 680.0;
const LOG_MAX: usize = 200;

fn main() -> eframe::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let shared = Arc::new(Shared::default());
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<Cmd>();

    let shared_bg = shared.clone();
    std::thread::Builder::new()
        .name("mhrv-bg".into())
        .spawn(move || background_thread(shared_bg, cmd_rx))
        .expect("failed to spawn background thread");

    let form = load_form();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([WIN_WIDTH, WIN_HEIGHT])
            .with_min_inner_size([420.0, 540.0])
            .with_title(format!("mhrv-rs {}", VERSION)),
        ..Default::default()
    };

    eframe::run_native(
        "mhrv-rs",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App {
                shared,
                cmd_tx,
                form,
                last_poll: Instant::now(),
                toast: None,
            }))
        }),
    )
}

#[derive(Default)]
struct Shared {
    state: Mutex<UiState>,
}

#[derive(Default)]
struct UiState {
    running: bool,
    started_at: Option<Instant>,
    last_stats: Option<mhrv_rs::domain_fronter::StatsSnapshot>,
    last_per_site: Vec<(String, mhrv_rs::domain_fronter::HostStat)>,
    log: VecDeque<String>,
    ca_trusted: Option<bool>,
    last_test_ok: Option<bool>,
    last_test_msg: String,
    /// Per-SNI probe results, populated by Cmd::TestSni / TestAllSni.
    sni_probe: HashMap<String, SniProbeState>,
}

#[derive(Clone, Debug)]
enum SniProbeState {
    InFlight,
    Ok(u32),
    Failed(String),
}

enum Cmd {
    Start(Config),
    Stop,
    Test(Config),
    InstallCa,
    CheckCaTrusted,
    PollStats,
    /// Probe a single SNI against the given google_ip. Result is written
    /// into UiState::sni_probe keyed by the SNI string.
    TestSni {
        google_ip: String,
        sni: String,
    },
    /// Probe a batch of SNI names. Results appear in UiState::sni_probe one
    /// by one as each probe finishes.
    TestAllSni {
        google_ip: String,
        snis: Vec<String>,
    },
}

struct App {
    shared: Arc<Shared>,
    cmd_tx: Sender<Cmd>,
    form: FormState,
    last_poll: Instant,
    toast: Option<(String, Instant)>,
}

#[derive(Clone)]
struct FormState {
    script_id: String,
    auth_key: String,
    google_ip: String,
    front_domain: String,
    listen_host: String,
    listen_port: String,
    socks5_port: String,
    log_level: String,
    verify_ssl: bool,
    upstream_socks5: String,
    parallel_relay: u8,
    show_auth_key: bool,
    /// SNI rotation pool entries. Each item has a sni name + a checkbox
    /// flag indicating whether it's in the active rotation.
    sni_pool: Vec<SniRow>,
    /// Text field buffer for the "+ add custom SNI" input at the bottom of
    /// the SNI editor window.
    sni_custom_input: String,
    /// Whether the floating SNI editor window is open.
    sni_editor_open: bool,
}

#[derive(Clone, Debug)]
struct SniRow {
    name: String,
    enabled: bool,
}

fn load_form() -> FormState {
    let path = data_dir::config_path();
    let cwd = PathBuf::from("config.json");
    let existing = if path.exists() {
        Config::load(&path).ok()
    } else if cwd.exists() {
        Config::load(&cwd).ok()
    } else {
        None
    };
    if let Some(c) = existing {
        let sid = match &c.script_id {
            Some(ScriptId::One(s)) => s.clone(),
            Some(ScriptId::Many(v)) => v.join("\n"),
            None => match &c.script_ids {
                Some(ScriptId::One(s)) => s.clone(),
                Some(ScriptId::Many(v)) => v.join("\n"),
                None => String::new(),
            },
        };
        let sni_pool = sni_pool_for_form(c.sni_hosts.as_deref(), &c.front_domain);
        FormState {
            script_id: sid,
            auth_key: c.auth_key,
            google_ip: c.google_ip,
            front_domain: c.front_domain,
            listen_host: c.listen_host,
            listen_port: c.listen_port.to_string(),
            socks5_port: c.socks5_port.map(|p| p.to_string()).unwrap_or_default(),
            log_level: c.log_level,
            verify_ssl: c.verify_ssl,
            upstream_socks5: c.upstream_socks5.unwrap_or_default(),
            parallel_relay: c.parallel_relay,
            show_auth_key: false,
            sni_pool,
            sni_custom_input: String::new(),
            sni_editor_open: false,
        }
    } else {
        FormState {
            script_id: String::new(),
            auth_key: String::new(),
            google_ip: "216.239.38.120".into(),
            front_domain: "www.google.com".into(),
            listen_host: "127.0.0.1".into(),
            listen_port: "8085".into(),
            socks5_port: "8086".into(),
            log_level: "info".into(),
            verify_ssl: true,
            upstream_socks5: String::new(),
            parallel_relay: 0,
            show_auth_key: false,
            sni_pool: sni_pool_for_form(None, "www.google.com"),
            sni_custom_input: String::new(),
            sni_editor_open: false,
        }
    }
}

/// Build the initial `sni_pool` list shown in the editor.
///
/// If the user has explicit `sni_hosts` configured, we show exactly those
/// rows (all enabled). Otherwise we show the default Google pool plus any
/// missing entries, all enabled, with the user's `front_domain` first.
fn sni_pool_for_form(user: Option<&[String]>, front_domain: &str) -> Vec<SniRow> {
    let user_clean: Vec<String> = user
        .unwrap_or(&[])
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !user_clean.is_empty() {
        return user_clean
            .into_iter()
            .map(|name| SniRow {
                name,
                enabled: true,
            })
            .collect();
    }
    // Default: primary + the other Google-edge subdomains, primary first,
    // all enabled.
    let primary = front_domain.trim().to_string();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    if !primary.is_empty() {
        seen.insert(primary.clone());
        out.push(SniRow {
            name: primary,
            enabled: true,
        });
    }
    for s in DEFAULT_GOOGLE_SNI_POOL {
        if seen.insert(s.to_string()) {
            out.push(SniRow {
                name: (*s).to_string(),
                enabled: true,
            });
        }
    }
    out
}

impl FormState {
    fn to_config(&self) -> Result<Config, String> {
        if self.script_id.trim().is_empty() {
            return Err("Apps Script ID is required".into());
        }
        if self.auth_key.trim().is_empty() {
            return Err("Auth key is required".into());
        }
        let listen_port: u16 = self
            .listen_port
            .parse()
            .map_err(|_| "HTTP port must be a number".to_string())?;
        let socks5_port: Option<u16> = if self.socks5_port.trim().is_empty() {
            None
        } else {
            Some(
                self.socks5_port
                    .parse()
                    .map_err(|_| "SOCKS5 port must be a number".to_string())?,
            )
        };
        let ids: Vec<String> = self
            .script_id
            .split(|c: char| c == '\n' || c == ',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let script_id = if ids.len() == 1 {
            Some(ScriptId::One(ids[0].clone()))
        } else {
            Some(ScriptId::Many(ids))
        };
        Ok(Config {
            mode: "apps_script".into(),
            google_ip: self.google_ip.trim().to_string(),
            front_domain: self.front_domain.trim().to_string(),
            script_id,
            script_ids: None,
            auth_key: self.auth_key.clone(),
            listen_host: self.listen_host.trim().to_string(),
            listen_port,
            socks5_port,
            log_level: self.log_level.trim().to_string(),
            verify_ssl: self.verify_ssl,
            hosts: std::collections::HashMap::new(),
            enable_batching: false,
            upstream_socks5: {
                let v = self.upstream_socks5.trim();
                if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                }
            },
            parallel_relay: self.parallel_relay,
            sni_hosts: {
                let active: Vec<String> = self
                    .sni_pool
                    .iter()
                    .filter(|r| r.enabled)
                    .map(|r| r.name.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                // None = "use auto-expansion default", Some(list) = explicit.
                // If the user's pool is empty/all-off we still save as None so
                // the backend falls back to sensible defaults instead of dying
                // on an empty pool.
                if active.is_empty() {
                    None
                } else {
                    Some(active)
                }
            },
        })
    }
}

fn save_config(cfg: &Config) -> Result<PathBuf, String> {
    let path = data_dir::config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(&ConfigWire::from(cfg)).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())?;
    Ok(path)
}

#[derive(serde::Serialize)]
struct ConfigWire<'a> {
    mode: &'a str,
    google_ip: &'a str,
    front_domain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_id: Option<ScriptIdWire<'a>>,
    auth_key: &'a str,
    listen_host: &'a str,
    listen_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    socks5_port: Option<u16>,
    log_level: &'a str,
    verify_ssl: bool,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    hosts: &'a std::collections::HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_socks5: Option<&'a str>,
    #[serde(skip_serializing_if = "is_zero_u8")]
    parallel_relay: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni_hosts: Option<Vec<&'a str>>,
}

fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum ScriptIdWire<'a> {
    One(&'a str),
    Many(Vec<&'a str>),
}

impl<'a> From<&'a Config> for ConfigWire<'a> {
    fn from(c: &'a Config) -> Self {
        let script_id = c.script_id.as_ref().map(|s| match s {
            ScriptId::One(v) => ScriptIdWire::One(v.as_str()),
            ScriptId::Many(v) => ScriptIdWire::Many(v.iter().map(String::as_str).collect()),
        });
        ConfigWire {
            mode: c.mode.as_str(),
            google_ip: c.google_ip.as_str(),
            front_domain: c.front_domain.as_str(),
            script_id,
            auth_key: c.auth_key.as_str(),
            listen_host: c.listen_host.as_str(),
            listen_port: c.listen_port,
            socks5_port: c.socks5_port,
            log_level: c.log_level.as_str(),
            verify_ssl: c.verify_ssl,
            hosts: &c.hosts,
            upstream_socks5: c.upstream_socks5.as_deref(),
            parallel_relay: c.parallel_relay,
            sni_hosts: c
                .sni_hosts
                .as_ref()
                .map(|v| v.iter().map(String::as_str).collect()),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if self.last_poll.elapsed() > Duration::from_millis(700) {
            let _ = self.cmd_tx.send(Cmd::PollStats);
            self.last_poll = Instant::now();
        }
        ctx.request_repaint_after(Duration::from_millis(500));

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.style_mut().spacing.item_spacing = egui::vec2(8.0, 6.0);

            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("mhrv-rs  {}", VERSION))
                    .size(16.0));
                ui.add_space(8.0);
                let running = self.shared.state.lock().unwrap().running;
                let dot = if running { "running" } else { "stopped" };
                let color = if running { egui::Color32::from_rgb(70, 170, 100) } else { egui::Color32::from_rgb(170, 90, 90) };
                ui.label(egui::RichText::new(dot).color(color).monospace());
            });

            ui.separator();

            // Config form.
            egui::Grid::new("cfg")
                .num_columns(2)
                .spacing([10.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Apps Script ID(s)")
                        .on_hover_text(
                            "One deployment ID per line.\n\
                             With multiple IDs the proxy round-robins between them and\n\
                             automatically sidelines any ID that hits its daily quota (429)\n\
                             or other rate limits for 10 minutes before retrying it."
                        );
                    ui.add(egui::TextEdit::multiline(&mut self.form.script_id)
                        .hint_text("one deployment ID per line")
                        .desired_width(f32::INFINITY)
                        .desired_rows(3));
                    ui.end_row();

                    let id_count = self.form.script_id
                        .split(|c: char| c == '\n' || c == ',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .count();
                    ui.label("");
                    if id_count <= 1 {
                        ui.small("Tip: add more IDs (one per line) for round-robin rotation with auto-failover on quota.");
                    } else {
                        ui.small(format!("{} IDs — round-robin with auto-failover on quota.", id_count));
                    }
                    ui.end_row();

                    ui.label("Auth key");
                    ui.horizontal(|ui| {
                        let te = egui::TextEdit::singleline(&mut self.form.auth_key)
                            .password(!self.form.show_auth_key)
                            .desired_width(f32::INFINITY);
                        ui.add(te);
                    });
                    ui.end_row();

                    ui.label("Google IP");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.form.google_ip);
                        if ui.button("scan").on_hover_text(
                            "Try several known Google frontend IPs and report which are reachable (results printed to stdout/terminal)"
                        ).clicked() {
                            if let Ok(cfg) = self.form.to_config() {
                                let _ = self.cmd_tx.send(Cmd::Test(cfg.clone()));
                                self.toast = Some(("Scan started — check terminal for full results".into(), Instant::now()));
                            }
                        }
                    });
                    ui.end_row();

                    ui.label("Front domain");
                    ui.add(egui::TextEdit::singleline(&mut self.form.front_domain)
                        .desired_width(f32::INFINITY));
                    ui.end_row();

                    ui.label("Listen host");
                    ui.add(egui::TextEdit::singleline(&mut self.form.listen_host)
                        .desired_width(f32::INFINITY));
                    ui.end_row();

                    ui.label("HTTP port");
                    ui.add(egui::TextEdit::singleline(&mut self.form.listen_port).desired_width(80.0));
                    ui.end_row();

                    ui.label("SOCKS5 port");
                    ui.add(egui::TextEdit::singleline(&mut self.form.socks5_port).desired_width(80.0));
                    ui.end_row();

                    ui.label("Upstream SOCKS5")
                        .on_hover_text(
                            "Optional. host:port of an upstream SOCKS5 proxy (e.g. xray / v2ray / sing-box).\n\
                             When set, non-HTTP / raw-TCP traffic arriving on the SOCKS5 listener is\n\
                             chained through this proxy instead of connecting directly — this is what\n\
                             makes Telegram MTProto, IMAP, SSH etc. actually tunnel.\n\
                             HTTP/HTTPS traffic still routes through the Apps Script relay and the\n\
                             SNI-rewrite tunnel as before."
                        );
                    ui.add(egui::TextEdit::singleline(&mut self.form.upstream_socks5)
                        .hint_text("empty = direct; 127.0.0.1:50529 for a local xray")
                        .desired_width(f32::INFINITY));
                    ui.end_row();

                    ui.label("Parallel dispatch")
                        .on_hover_text(
                            "Fire this many Apps Script IDs in parallel per relay request and\n\
                             return the first successful response. 0/1 = off (round-robin).\n\
                             Higher values eliminate long-tail latency (slow script instance\n\
                             doesn't hold up the fast one) but spend that many times more\n\
                             daily quota. Only effective with multiple IDs configured.\n\
                             Recommend 2-3 if you have plenty of quota headroom."
                        );
                    ui.add(egui::DragValue::new(&mut self.form.parallel_relay)
                        .speed(1)
                        .range(0..=8));
                    ui.end_row();

                    ui.label("Log level");
                    egui::ComboBox::from_id_source("loglevel")
                        .selected_text(&self.form.log_level)
                        .show_ui(ui, |ui| {
                            for lvl in ["warn", "info", "debug", "trace"] {
                                ui.selectable_value(&mut self.form.log_level, lvl.into(), lvl);
                            }
                        });
                    ui.end_row();

                    ui.label("");
                    ui.checkbox(&mut self.form.verify_ssl, "Verify TLS server certificate (recommended)");
                    ui.end_row();

                    ui.label("");
                    ui.checkbox(&mut self.form.show_auth_key, "Show auth key");
                    ui.end_row();
                });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("Save config").clicked() {
                    match self.form.to_config().and_then(|c| save_config(&c)) {
                        Ok(p) => self.toast = Some((format!("Saved to {}", p.display()), Instant::now())),
                        Err(e) => self.toast = Some((format!("Save failed: {}", e), Instant::now())),
                    }
                }
                let active_sni = self.form.sni_pool.iter().filter(|r| r.enabled).count();
                let total_sni = self.form.sni_pool.len();
                let sni_btn = egui::Button::new(
                    egui::RichText::new(format!("SNI pool… ({}/{})", active_sni, total_sni))
                        .color(egui::Color32::WHITE),
                )
                .fill(egui::Color32::from_rgb(70, 120, 180))
                .min_size(egui::vec2(160.0, 0.0));
                if ui.add(sni_btn)
                    .on_hover_text(
                        "Open the SNI rotation pool editor.\n\n\
                         Edit which SNI names get rotated through for outbound TLS to the\n\
                         Google edge. Some default names may be locally blocked — use the\n\
                         Test buttons inside to find out which ones work on your network."
                    )
                    .clicked()
                {
                    self.form.sni_editor_open = true;
                }
                ui.small(format!("location: {}", data_dir::config_path().display()));
            });

            // Floating SNI editor window. Rendered here so it's inside the
            // same egui context but visually pops out with its own title bar.
            self.show_sni_editor(ctx);

            ui.separator();

            // Status + stats
            let (running, started_at, stats, ca_trusted, last_test_msg, per_site) = {
                let s = self.shared.state.lock().unwrap();
                (
                    s.running,
                    s.started_at,
                    s.last_stats,
                    s.ca_trusted,
                    s.last_test_msg.clone(),
                    s.last_per_site.clone(),
                )
            };

            ui.horizontal(|ui| {
                if running {
                    let up = started_at.map(|t| t.elapsed()).unwrap_or_default();
                    ui.label(egui::RichText::new(format!(
                        "Status: running  (uptime {})", fmt_duration(up)
                    )).strong());
                } else {
                    ui.label(egui::RichText::new("Status: stopped").strong());
                }
            });

            if let Some(s) = stats {
                egui::Grid::new("stats").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
                    ui.label("relay calls");
                    ui.label(egui::RichText::new(s.relay_calls.to_string()).monospace());
                    ui.end_row();
                    ui.label("failures");
                    ui.label(egui::RichText::new(s.relay_failures.to_string()).monospace());
                    ui.end_row();
                    ui.label("coalesced");
                    ui.label(egui::RichText::new(s.coalesced.to_string()).monospace());
                    ui.end_row();
                    ui.label("cache hits / total");
                    ui.label(egui::RichText::new(format!(
                        "{} / {}  ({:.0}%)",
                        s.cache_hits,
                        s.cache_hits + s.cache_misses,
                        s.hit_rate()
                    )).monospace());
                    ui.end_row();
                    ui.label("cache size");
                    ui.label(egui::RichText::new(format!("{} KB", s.cache_bytes / 1024)).monospace());
                    ui.end_row();
                    ui.label("bytes relayed");
                    ui.label(egui::RichText::new(fmt_bytes(s.bytes_relayed)).monospace());
                    ui.end_row();
                    ui.label("active scripts");
                    ui.label(egui::RichText::new(format!(
                        "{} / {}", s.total_scripts - s.blacklisted_scripts, s.total_scripts
                    )).monospace());
                    ui.end_row();
                });
            }

            if !per_site.is_empty() {
                ui.add_space(2.0);
                egui::CollapsingHeader::new(format!("Per-site ({} hosts)", per_site.len()))
                    .default_open(false)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(140.0)
                            .show(ui, |ui| {
                                egui::Grid::new("per_site")
                                    .num_columns(5)
                                    .spacing([8.0, 2.0])
                                    .striped(true)
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new("host").strong());
                                        ui.label(egui::RichText::new("req").strong());
                                        ui.label(egui::RichText::new("hit%").strong());
                                        ui.label(egui::RichText::new("bytes").strong());
                                        ui.label(egui::RichText::new("avg ms").strong());
                                        ui.end_row();
                                        for (host, st) in per_site.iter().take(60) {
                                            let hit_pct = if st.requests > 0 {
                                                (st.cache_hits as f64 / st.requests as f64) * 100.0
                                            } else { 0.0 };
                                            ui.label(egui::RichText::new(host).monospace());
                                            ui.label(egui::RichText::new(st.requests.to_string()).monospace());
                                            ui.label(egui::RichText::new(format!("{:.0}%", hit_pct)).monospace());
                                            ui.label(egui::RichText::new(fmt_bytes(st.bytes)).monospace());
                                            ui.label(egui::RichText::new(format!("{:.0}", st.avg_latency_ms())).monospace());
                                            ui.end_row();
                                        }
                                    });
                            });
                    });
            }

            ui.add_space(4.0);

            ui.horizontal(|ui| {
                if !running {
                    if ui.button("Start").clicked() {
                        match self.form.to_config() {
                            Ok(cfg) => {
                                let _ = self.cmd_tx.send(Cmd::Start(cfg));
                            }
                            Err(e) => {
                                self.toast = Some((format!("Cannot start: {}", e), Instant::now()));
                            }
                        }
                    }
                } else if ui.button("Stop").clicked() {
                    let _ = self.cmd_tx.send(Cmd::Stop);
                }

                if ui.button("Test").clicked() {
                    match self.form.to_config() {
                        Ok(cfg) => {
                            let _ = self.cmd_tx.send(Cmd::Test(cfg));
                        }
                        Err(e) => {
                            self.toast = Some((format!("Cannot test: {}", e), Instant::now()));
                        }
                    }
                }

                if ui.button("Install CA").clicked() {
                    let _ = self.cmd_tx.send(Cmd::InstallCa);
                }

                if ui.button("Check CA").clicked() {
                    let _ = self.cmd_tx.send(Cmd::CheckCaTrusted);
                }
            });

            if !last_test_msg.is_empty() {
                ui.small(last_test_msg);
            }
            match ca_trusted {
                Some(true) => { ui.small("CA appears trusted."); },
                Some(false) => { ui.small("CA is NOT trusted in the system store. Click 'Install CA' (may require admin)."); },
                None => {},
            }

            ui.separator();
            ui.label(egui::RichText::new("Recent log").strong());
            egui::ScrollArea::vertical()
                .max_height(180.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    let log = self.shared.state.lock().unwrap().log.clone();
                    for line in log.iter() {
                        ui.monospace(line);
                    }
                });

            // Transient toast at the bottom.
            if let Some((msg, t)) = &self.toast {
                if t.elapsed() < Duration::from_secs(5) {
                    ui.add_space(4.0);
                    ui.colored_label(egui::Color32::from_rgb(200, 170, 80), msg);
                } else {
                    self.toast = None;
                }
            }
        });
    }
}

impl App {
    /// Floating editor window for the SNI rotation pool. Opens from the
    /// **SNI pool…** button in the main form. The list is live-editable
    /// (reorder / toggle / add / remove); changes only persist when the user
    /// hits **Save config** in the main window. Probe results are cached in
    /// `UiState::sni_probe` so they survive opening and closing the editor.
    fn show_sni_editor(&mut self, ctx: &egui::Context) {
        if !self.form.sni_editor_open {
            return;
        }
        let mut keep_open = true;
        egui::Window::new("SNI rotation pool")
            .open(&mut keep_open)
            .resizable(true)
            .default_size(egui::vec2(520.0, 420.0))
            .min_width(460.0)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(
                    egui::RichText::new(
                        "Which SNI names to rotate through when opening TLS connections \
                         to your Google IP. Some names may be locally blocked (Iran has \
                         dropped mail.google.com at times, for example); use the Test \
                         buttons to check — TLS handshake + HTTP HEAD against the \
                         configured google_ip, per name.",
                    )
                    .small(),
                );
                ui.add_space(4.0);

                // Action row.
                let google_ip = self.form.google_ip.trim().to_string();
                let probe_map = self.shared.state.lock().unwrap().sni_probe.clone();
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Test all").on_hover_text(
                        "Probe every SNI in the list against the configured google_ip in parallel."
                    ).clicked() {
                        let snis: Vec<String> = self
                            .form
                            .sni_pool
                            .iter()
                            .map(|r| r.name.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if !snis.is_empty() && !google_ip.is_empty() {
                            let _ = self.cmd_tx.send(Cmd::TestAllSni {
                                google_ip: google_ip.clone(),
                                snis,
                            });
                        }
                    }
                    if ui
                        .button("Keep working only")
                        .on_hover_text("Uncheck every SNI that didn't pass the last probe.")
                        .clicked()
                    {
                        for row in &mut self.form.sni_pool {
                            let ok = matches!(probe_map.get(&row.name), Some(SniProbeState::Ok(_)));
                            row.enabled = ok;
                        }
                    }
                    if ui.button("Enable all").clicked() {
                        for row in &mut self.form.sni_pool {
                            row.enabled = true;
                        }
                    }
                    if ui.button("Clear status").clicked() {
                        self.shared.state.lock().unwrap().sni_probe.clear();
                    }
                    if ui
                        .button("Reset to defaults")
                        .on_hover_text(
                            "Replace the list with the built-in Google SNI pool. Custom entries \
                         are dropped.",
                        )
                        .clicked()
                    {
                        self.form.sni_pool = DEFAULT_GOOGLE_SNI_POOL
                            .iter()
                            .map(|s| SniRow {
                                name: (*s).to_string(),
                                enabled: true,
                            })
                            .collect();
                        self.shared.state.lock().unwrap().sni_probe.clear();
                    }
                });
                ui.separator();

                // Main list — one horizontal row per SNI, explicit widths so
                // the domain text field gets the room it needs.
                let mut to_remove: Option<usize> = None;
                let mut test_name: Option<String> = None;
                const STATUS_W: f32 = 150.0;
                const NAME_W: f32 = 230.0;
                egui::ScrollArea::vertical()
                    .max_height(280.0)
                    .show(ui, |ui| {
                        for (i, row) in self.form.sni_pool.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut row.enabled, "");
                                ui.add(
                                    egui::TextEdit::singleline(&mut row.name)
                                        .desired_width(NAME_W)
                                        .font(egui::TextStyle::Monospace),
                                );
                                let status_txt = match probe_map.get(&row.name) {
                                    Some(SniProbeState::Ok(ms)) => {
                                        egui::RichText::new(format!("ok  {} ms", ms))
                                            .color(egui::Color32::from_rgb(80, 180, 100))
                                            .monospace()
                                    }
                                    Some(SniProbeState::Failed(e)) => {
                                        let short = if e.len() > 22 { &e[..22] } else { e };
                                        egui::RichText::new(format!("fail {}", short))
                                            .color(egui::Color32::from_rgb(220, 110, 110))
                                            .monospace()
                                    }
                                    Some(SniProbeState::InFlight) => {
                                        egui::RichText::new("testing…")
                                            .color(egui::Color32::GRAY)
                                            .monospace()
                                    }
                                    None => egui::RichText::new("untested")
                                        .color(egui::Color32::GRAY)
                                        .monospace(),
                                };
                                ui.add_sized(
                                    [STATUS_W, 18.0],
                                    egui::Label::new(status_txt).truncate(),
                                );
                                if ui.small_button("Test").clicked() {
                                    test_name = Some(row.name.clone());
                                }
                                if ui
                                    .small_button("remove")
                                    .on_hover_text("Remove this row")
                                    .clicked()
                                {
                                    to_remove = Some(i);
                                }
                            });
                        }
                    });

                if let Some(name) = test_name {
                    let name = name.trim().to_string();
                    if !name.is_empty() && !google_ip.is_empty() {
                        let _ = self.cmd_tx.send(Cmd::TestSni {
                            google_ip: google_ip.clone(),
                            sni: name,
                        });
                    }
                }
                if let Some(i) = to_remove {
                    self.form.sni_pool.remove(i);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.form.sni_custom_input)
                            .hint_text("add a custom SNI (e.g. translate.google.com)")
                            .desired_width(280.0),
                    );
                    let add_clicked = ui.button("+ Add").clicked();
                    if add_clicked {
                        let new_name = self.form.sni_custom_input.trim().to_string();
                        if !new_name.is_empty()
                            && !self.form.sni_pool.iter().any(|r| r.name == new_name)
                        {
                            self.form.sni_pool.push(SniRow {
                                name: new_name.clone(),
                                enabled: true,
                            });
                            self.form.sni_custom_input.clear();
                            // Auto-probe the freshly added name so the user gets
                            // immediate feedback instead of a silent "untested"
                            // row. Needs a non-empty google_ip to have meaning.
                            if !google_ip.is_empty() {
                                let _ = self.cmd_tx.send(Cmd::TestSni {
                                    google_ip: google_ip.clone(),
                                    sni: new_name,
                                });
                            }
                        }
                    }
                });

                ui.add_space(6.0);
                ui.separator();
                ui.small(
                    "Changes take effect on the next Start of the proxy. \
                     Don't forget to press Save config in the main window to persist.",
                );
            });
        self.form.sni_editor_open = keep_open;
    }
}

fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

fn fmt_bytes(b: u64) -> String {
    const K: u64 = 1024;
    const M: u64 = K * K;
    const G: u64 = M * K;
    if b >= G {
        format!("{:.2} GB", b as f64 / G as f64)
    } else if b >= M {
        format!("{:.2} MB", b as f64 / M as f64)
    } else if b >= K {
        format!("{:.1} KB", b as f64 / K as f64)
    } else {
        format!("{} B", b)
    }
}

// ---------- Background thread: owns the tokio runtime + proxy lifecycle ----------

fn background_thread(shared: Arc<Shared>, rx: Receiver<Cmd>) {
    let rt = Runtime::new().expect("failed to create tokio runtime");

    let mut active: Option<(
        JoinHandle<()>,
        Arc<AsyncMutex<Option<Arc<DomainFronter>>>>,
        tokio::sync::oneshot::Sender<()>,
    )> = None;

    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Cmd::PollStats) => {
                if let Some((_, fronter_slot, _)) = &active {
                    let slot = fronter_slot.clone();
                    let shared = shared.clone();
                    rt.spawn(async move {
                        let f = slot.lock().await;
                        if let Some(fronter) = f.as_ref() {
                            let s = fronter.snapshot_stats();
                            let per_site = fronter.snapshot_per_site();
                            let mut st = shared.state.lock().unwrap();
                            st.last_stats = Some(s);
                            st.last_per_site = per_site;
                        }
                    });
                }
            }
            // In background_thread function, modify the Cmd::Start handler:
            Ok(Cmd::Start(cfg)) => {
                if active.is_some() {
                    push_log(&shared, "[ui] already running");
                    continue;
                }
                push_log(&shared, "[ui] starting proxy...");
                let shared2 = shared.clone();
                let fronter_slot: Arc<AsyncMutex<Option<Arc<DomainFronter>>>> =
                    Arc::new(AsyncMutex::new(None));
                let fronter_slot2 = fronter_slot.clone();

                let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

                let handle = rt.spawn(async move {
                    let base = data_dir::data_dir();
                    let mitm = match MitmCertManager::new_in(&base) {
                        Ok(m) => m,
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] MITM init failed: {}", e));
                            shared2.state.lock().unwrap().running = false;
                            return;
                        }
                    };
                    let mitm = Arc::new(AsyncMutex::new(mitm));
                    let server = match ProxyServer::new(&cfg, mitm) {
                        Ok(s) => s,
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] proxy build failed: {}", e));
                            shared2.state.lock().unwrap().running = false;
                            return;
                        }
                    };
                    *fronter_slot2.lock().await = Some(server.fronter());
                    {
                        let mut s = shared2.state.lock().unwrap();
                        s.running = true;
                        s.started_at = Some(Instant::now());
                    }
                    push_log(
                        &shared2,
                        &format!(
                            "[ui] listening HTTP {}:{} SOCKS5 {}:{}",
                            cfg.listen_host,
                            cfg.listen_port,
                            cfg.listen_host,
                            cfg.socks5_port.unwrap_or(cfg.listen_port + 1)
                        ),
                    );

                    let _ = server.run(shutdown_rx).await;

                    shared2.state.lock().unwrap().running = false;
                    push_log(&shared2, "[ui] proxy stopped");
                });

                active = Some((handle, fronter_slot, shutdown_tx));
            }

            Ok(Cmd::Stop) => {
                if let Some((handle, _, shutdown_tx)) = active.take() {
                    push_log(&shared, "[ui] stop requested");
                    let _ = shutdown_tx.send(());

                    // Give the proxy 2 seconds to shut down gracefully
                    rt.block_on(async {
                        tokio::select! {
                            _ = handle => {
                                push_log(&shared, "[ui] proxy stopped gracefully");
                            }
                            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                                push_log(&shared, "[ui] shutdown timeout, forcing abort");
                            }
                        }
                    });

                    shared.state.lock().unwrap().running = false;
                    shared.state.lock().unwrap().started_at = None;
                    shared.state.lock().unwrap().last_stats = None;
                }
            }

            Ok(Cmd::Test(cfg)) => {
                let shared2 = shared.clone();
                push_log(&shared, "[ui] running test...");
                rt.spawn(async move {
                    let ok = test_cmd::run(&cfg).await;
                    shared2.state.lock().unwrap().last_test_ok = Some(ok);
                    shared2.state.lock().unwrap().last_test_msg = if ok {
                        "Test passed — relay is working.".into()
                    } else {
                        "Test failed — see terminal for details.".into()
                    };
                    push_log(
                        &shared2,
                        &format!("[ui] test result: {}", if ok { "pass" } else { "fail" }),
                    );
                    // Also run ip scan on demand (cheap).
                    let _ = scan_ips::run(&cfg).await;
                });
            }
            Ok(Cmd::InstallCa) => {
                let shared2 = shared.clone();
                std::thread::spawn(move || {
                    push_log(&shared2, "[ui] installing CA...");
                    let base = data_dir::data_dir();
                    if let Err(e) = MitmCertManager::new_in(&base) {
                        push_log(&shared2, &format!("[ui] CA init failed: {}", e));
                        return;
                    }
                    let ca = base.join(CA_CERT_FILE);
                    match install_ca(&ca) {
                        Ok(()) => {
                            push_log(&shared2, "[ui] CA install ok");
                            shared2.state.lock().unwrap().ca_trusted = Some(true);
                        }
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] CA install failed: {}", e));
                            push_log(&shared2, "[ui] hint: run the terminal binary with sudo/admin: mhrv-rs --install-cert");
                        }
                    }
                });
            }
            Ok(Cmd::TestSni { google_ip, sni }) => {
                let shared2 = shared.clone();
                {
                    let mut st = shared2.state.lock().unwrap();
                    st.sni_probe.insert(sni.clone(), SniProbeState::InFlight);
                }
                rt.spawn(async move {
                    let result = scan_sni::probe_one(&google_ip, &sni).await;
                    let state = match result.latency_ms {
                        Some(ms) => SniProbeState::Ok(ms),
                        None => {
                            SniProbeState::Failed(result.error.unwrap_or_else(|| "failed".into()))
                        }
                    };
                    shared2.state.lock().unwrap().sni_probe.insert(sni, state);
                });
            }
            Ok(Cmd::TestAllSni { google_ip, snis }) => {
                let shared2 = shared.clone();
                {
                    let mut st = shared2.state.lock().unwrap();
                    for s in &snis {
                        st.sni_probe.insert(s.clone(), SniProbeState::InFlight);
                    }
                }
                rt.spawn(async move {
                    let results = scan_sni::probe_all(&google_ip, snis).await;
                    let mut st = shared2.state.lock().unwrap();
                    for (sni, r) in results {
                        let state = match r.latency_ms {
                            Some(ms) => SniProbeState::Ok(ms),
                            None => {
                                SniProbeState::Failed(r.error.unwrap_or_else(|| "failed".into()))
                            }
                        };
                        st.sni_probe.insert(sni, state);
                    }
                });
            }
            Ok(Cmd::CheckCaTrusted) => {
                let shared2 = shared.clone();
                std::thread::spawn(move || {
                    let base = data_dir::data_dir();
                    let ca = base.join(CA_CERT_FILE);
                    let trusted = mhrv_rs::cert_installer::is_ca_trusted(&ca);
                    shared2.state.lock().unwrap().ca_trusted = Some(trusted);
                });
            }
            Err(_) => {}
        }

        // Clean up finished task.
        if let Some((handle, _, _)) = &active {
            if handle.is_finished() {
                active = None;
                shared.state.lock().unwrap().running = false;
            }
        }
    }
}

fn push_log(shared: &Shared, msg: &str) {
    let line = format!(
        "{}  {}",
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Iso8601::DEFAULT)
            .unwrap_or_default(),
        msg
    );
    let mut s = shared.state.lock().unwrap();
    s.log.push_back(line);
    while s.log.len() > LOG_MAX {
        s.log.pop_front();
    }
}
