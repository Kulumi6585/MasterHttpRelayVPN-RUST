# MasterHttpRelayVPN-RUST

Rust port of [@masterking32's MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN). **All credit for the original idea and the Python implementation goes to [@masterking32](https://github.com/masterking32).** This is a faithful reimplementation of the `apps_script` mode, packaged as two tiny binaries (CLI + desktop UI) with no runtime dependencies.

Free DPI bypass via Google Apps Script as a remote relay, with TLS SNI concealment. Your ISP's censor sees traffic going to `www.google.com`; behind the scenes a free Google Apps Script that you deploy in your own Google account fetches the real website for you.

**[English Guide](#setup-guide)** | **[راهنمای فارسی](#راهنمای-فارسی)**

## Why this exists

The original Python project is excellent but requires Python + `pip install cryptography h2` + system deps. For users in hostile networks that install process is often itself broken (blocked PyPI, missing wheels, Windows without Python). This port is a single ~2.5 MB executable that you download and run. Nothing else.

## How it works

```
Browser / Telegram / xray
        |
        | HTTP proxy (8085)  or  SOCKS5 (8086)
        v
mhrv-rs (local)
        |
        | TLS to Google IP, SNI = www.google.com
        v                       ^
   DPI sees www.google.com      |
        |                       | Host: script.google.com (inside TLS)
        v                       |
  Google edge frontend ---------+
        |
        v
  Apps Script relay (your free Google account)
        |
        v
  Real destination
```

The censor's DPI sees `www.google.com` in the TLS SNI and lets it through. Google's frontend hosts both `www.google.com` and `script.google.com` on the same IP and routes by the HTTP `Host` header inside the encrypted stream.

For a handful of Google-owned domains (`google.com`, `youtube.com`, `fonts.googleapis.com`, …) the same tunnel is used directly instead of going through the Apps Script relay. This bypasses the per-fetch quota and fixes the "User-Agent is always `Google-Apps-Script`" problem for those domains. You can add more domains via the `hosts` map in config.

## Platforms

Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64). Prebuilt binaries on the [releases page](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases).

## What's in a release

Each archive contains two binaries and a launcher script:

| file | purpose |
|---|---|
| `mhrv-rs` / `mhrv-rs.exe` | CLI. Headless use, servers, automation. Works on all platforms; no system deps on macOS/Windows. |
| `mhrv-rs-ui` / `mhrv-rs-ui.exe` | Desktop UI (egui). Config form, Start/Stop/Test buttons, live stats, log panel. |
| `run.sh` / `run.command` / `run.bat` | Platform launcher: installs the MITM CA (needs sudo/admin) and then starts the UI. Use this on first run. |

macOS archives also ship `mhrv-rs.app` (in `*-app.zip`) — double-click to launch the UI without a terminal. You'll still need to run the CLI (`mhrv-rs --install-cert`) or `run.command` once to install the CA.

<p align="center"><img src="docs/ui-screenshot.png" alt="mhrv-rs desktop UI showing config form, live traffic stats, Start/Stop/Test buttons, and log panel" width="420"></p>

Linux UI also needs common desktop libraries available: `libxkbcommon`, `libwayland-client`, `libxcb`, `libgl`, `libx11`, `libgtk-3`. On most desktop distros these are already present; on a headless box install them via your package manager, or just use the CLI.

## Where things live

Config and the MITM CA live in the OS user-data dir:

- macOS: `~/Library/Application Support/mhrv-rs/`
- Linux: `~/.config/mhrv-rs/`
- Windows: `%APPDATA%\mhrv-rs\`

Inside that dir:

- `config.json` — your settings (written by the UI's **Save** button or hand-edited)
- `ca/ca.crt`, `ca/ca.key` — the MITM root certificate. Only you have the private key.

The CLI also falls back to `./config.json` in the current directory for backward compatibility with older setups.

## Setup Guide

### Step 1 — Deploy the Apps Script relay (one-time)

This part is unchanged from the original project. Follow @masterking32's guide or the summary below:

1. Open <https://script.google.com> while signed into your Google account.
2. **New project**, delete the default code.
3. Copy the contents of [`Code.gs` from the original repo](https://github.com/masterking32/MasterHttpRelayVPN/blob/python_testing/Code.gs) ([raw](https://raw.githubusercontent.com/masterking32/MasterHttpRelayVPN/refs/heads/python_testing/Code.gs)) into the editor.
4. Change `const AUTH_KEY = "..."` to a strong secret only you know.
5. **Deploy → New deployment → Web app**.
   - Execute as: **Me**
   - Who has access: **Anyone**
6. Copy the **Deployment ID** (the long random string in the URL).

### Step 2 — Download

Grab the archive for your platform from the [releases page](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases) and extract it.

Or build from source:

```bash
cargo build --release --features ui
# Binaries: target/release/mhrv-rs and target/release/mhrv-rs-ui
```

### Step 3 — First run: install the MITM CA

To route your browser's HTTPS traffic through the Apps Script relay, `mhrv-rs` has to terminate TLS locally on your machine, forward the request through the relay, and re-encrypt the response with a certificate your browser trusts. That requires a small **local** Certificate Authority.

**What actually happens on first run:**

- A fresh CA keypair (`ca/ca.crt` + `ca/ca.key`) is generated **on your machine**, in your user-data dir.
- The public `ca.crt` is added to your system trust store so browsers accept the per-site certificates `mhrv-rs` mints on the fly. This is the step that needs sudo / Administrator.
- The private `ca.key` **never leaves your machine**. Nothing uploads it, nothing phones home, and no remote party — including the Apps Script relay — can use it to impersonate sites to you.
- You can revoke it at any time by deleting the CA from your OS keychain (macOS: Keychain Access → System → delete `mhrv-rs`) / Windows cert store / `/etc/ca-certificates`, and removing the `ca/` folder.

The launcher does all of this for you and then starts the UI:

| platform | how |
|---|---|
| macOS | double-click `run.command` in Finder (or `./run.command` in a terminal) |
| Linux | `./run.sh` from a terminal |
| Windows | double-click `run.bat` |

It will ask for your password (sudo / UAC) **only** to trust the CA. After that the launcher also starts `mhrv-rs-ui`. On later runs you don't need the launcher — the CA is already trusted, so you can open `mhrv-rs.app` / `mhrv-rs-ui.exe` / `mhrv-rs-ui` directly.

If you prefer to do the CA step by hand:

```bash
# Linux / macOS
sudo ./mhrv-rs --install-cert

# Windows (Administrator)
mhrv-rs.exe --install-cert
```

Firefox keeps its own cert store; the installer also drops the CA into Firefox's NSS database via `certutil` (best-effort). If Firefox still complains, import `ca/ca.crt` manually via Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import.

### Step 4 — Configure in the UI

Open the UI and fill in the form:

- **Apps Script ID** — the Deployment ID from Step 1. Comma-separate multiple IDs for round-robin rotation across several deployments (higher quota, more throughput).
- **Auth key** — the same secret you set in `Code.gs`.
- **Google IP** — `216.239.38.120` is a solid default. Use the **scan** button to probe for a faster one from your network.
- **Front domain** — keep `www.google.com`.
- **HTTP port** / **SOCKS5 port** — defaults `8085` / `8086`.

Hit **Save**, then **Start**. Use **Test** any time to send one request end-to-end through the relay and report the result.

### Step 4 (alternative) — CLI only

Everything the UI does is also available in the CLI. Copy `config.example.json` to `config.json` (either next to the binary or into the user-data dir shown above), fill it in:

```json
{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "PASTE_YOUR_DEPLOYMENT_ID_HERE",
  "auth_key": "same-secret-as-in-code-gs",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_port": 8086,
  "log_level": "info",
  "verify_ssl": true
}
```

Then:

```bash
./mhrv-rs                   # serve (default)
./mhrv-rs test              # one-shot end-to-end probe
./mhrv-rs scan-ips          # rank Google frontend IPs by latency
./mhrv-rs --install-cert    # reinstall the MITM CA
./mhrv-rs --help
```

`script_id` can also be a JSON array: `["id1", "id2", "id3"]`.

### Step 5 — Point your client at the proxy

The tool listens on **two** ports. Use whichever your client supports:

**HTTP proxy** (browsers, generic HTTP clients) — `127.0.0.1:8085`

- **Firefox** — Settings → Network Settings → **Manual proxy**. HTTP host `127.0.0.1`, port `8085`, tick **Also use this proxy for HTTPS**.
- **Chrome / Edge** — use the system proxy settings, or the **Proxy SwitchyOmega** extension.
- **macOS system-wide** — System Settings → Network → Wi-Fi → Details → Proxies → enable **Web Proxy (HTTP)** and **Secure Web Proxy (HTTPS)**, both `127.0.0.1:8085`.
- **Windows system-wide** — Settings → Network & Internet → Proxy → **Manual proxy setup**, address `127.0.0.1`, port `8085`.

**SOCKS5 proxy** (Telegram, xray, app-level clients) — `127.0.0.1:8086`, no auth.

- Works for HTTP, HTTPS, **and** non-HTTP protocols (Telegram's MTProto, raw TCP). The server auto-detects each connection: HTTP/HTTPS go through the Apps Script relay, SNI-rewritable domains go through the direct Google-edge tunnel, and anything else falls through to raw TCP.

## Telegram, IMAP, SSH — pair with xray (optional)

The Apps Script relay only speaks HTTP request/response, so non-HTTP protocols (Telegram MTProto, IMAP, SSH, arbitrary raw TCP) can't travel through it. Without anything else, those flows hit the direct-TCP fallback — which means they're not actually tunneled, and an ISP that blocks Telegram will still block them.

Fix: run a local [xray](https://github.com/XTLS/Xray-core) (or v2ray / sing-box) with a VLESS/Trojan/Shadowsocks outbound that goes to a VPS of your own, and point mhrv-rs at xray's SOCKS5 inbound via the **Upstream SOCKS5** field (or the `upstream_socks5` config key). When set, raw-TCP flows coming through mhrv-rs's SOCKS5 listener get chained into xray → the real tunnel, instead of connecting directly.

```
Telegram  ┐                                                    ┌─ Apps Script ── HTTP/HTTPS
          ├─ SOCKS5 :8086 ─┤ mhrv-rs ├─ SNI rewrite ─── google.com, youtube.com, …
Browser   ┘                                                    └─ upstream SOCKS5 ─ xray ── VLESS ── your VPS   (Telegram, IMAP, SSH, raw TCP)
```

Example config fragment (both UI and JSON):

```json
{
  "upstream_socks5": "127.0.0.1:50529"
}
```

HTTP/HTTPS continues to route through the Apps Script relay (no change), and the SNI-rewrite tunnel for `google.com` / `youtube.com` / etc. keeps bypassing both — so YouTube stays as fast as before while Telegram gets a real tunnel.

## Running on OpenWRT (or any musl distro)

The `*-linux-musl-*` archives ship a fully static CLI that runs on OpenWRT, Alpine, and any libc-less Linux userland. Put the binary on the router and start it as a service:

```sh
# From a machine that can reach your router:
scp mhrv-rs root@192.168.1.1:/usr/bin/mhrv-rs
scp mhrv-rs.init root@192.168.1.1:/etc/init.d/mhrv-rs
scp config.json root@192.168.1.1:/etc/mhrv-rs/config.json

# On the router:
chmod +x /usr/bin/mhrv-rs /etc/init.d/mhrv-rs
/etc/init.d/mhrv-rs enable
/etc/init.d/mhrv-rs start
logread -e mhrv-rs -f   # tail its logs
```

LAN devices then point their HTTP proxy at the router's LAN IP (default port `8085`) or their SOCKS5 at `<router-ip>:8086`. Set `listen_host` to `0.0.0.0` in `/etc/mhrv-rs/config.json` so the router accepts LAN connections instead of localhost-only.

Memory footprint is ~15-20 MB resident — fine on anything with ≥128 MB RAM. No UI is shipped for musl (routers are headless).

## Diagnostics

- **`mhrv-rs test`** — sends one request through the relay and reports success/latency. Use this first whenever something breaks — it isolates "relay is up" from "client config is wrong".
- **`mhrv-rs scan-ips`** — parallel TLS probe of 28 known Google frontend IPs, sorted by latency. Take the winner and put it in `google_ip`. The UI has the same thing behind the **scan** button next to the Google IP field.
- **`mhrv-rs test-sni`** — parallel TLS probe of every SNI name in your rotation pool against the configured `google_ip`. Tells you which front-domain names actually pass through your ISP's DPI. The UI has the same thing in the **SNI pool…** floating window, with checkboxes, per-row **Test** buttons, and a **Keep ✓ only** button that auto-trims to what worked.
- **Periodic stats** are logged every 60 s at `info` level (relay calls, cache hit rate, bytes relayed, active vs. blacklisted scripts). The UI shows them live.

### SNI pool editor

By default `mhrv-rs` rotates through `{www, mail, drive, docs, calendar}.google.com` on outbound TLS connections to your Google IP, to avoid fingerprinting one name too heavily. Some of those may be locally blocked — e.g. `mail.google.com` has been specifically targeted in Iran at various times.

Either:

- Open the UI, click **SNI pool…**, hit **Test all**, then **Keep ✓ only** to auto-trim. Add custom names via the text field at the bottom. Save.
- Or edit `config.json` directly:

```json
{
  "sni_hosts": ["www.google.com", "drive.google.com", "docs.google.com"]
}
```

Leaving `sni_hosts` unset gives you the default auto-pool. Run `mhrv-rs test-sni` to verify what works from your network before saving.

## What's implemented vs. not

This port focuses on the **`apps_script` mode** — the only one that reliably works against a modern censor in 2026. Implemented:

- [x] Local HTTP proxy (CONNECT for HTTPS, plain forwarding for HTTP)
- [x] Local SOCKS5 proxy with smart TLS/HTTP/raw-TCP dispatch (Telegram, xray, etc.)
- [x] MITM with on-the-fly per-domain cert generation via `rcgen`
- [x] CA generation + auto-install on macOS / Linux / Windows
- [x] Firefox NSS cert install (best-effort via `certutil`)
- [x] Apps Script JSON relay, protocol-compatible with `Code.gs`
- [x] Connection pooling (45 s TTL, max 20 idle)
- [x] Gzip response decoding
- [x] Multi-script round-robin
- [x] Auto-blacklist failing scripts on 429 / quota errors (10-minute cooldown)
- [x] Response cache (50 MB, FIFO + TTL, `Cache-Control: max-age` aware, heuristics for static assets)
- [x] Request coalescing: concurrent identical GETs share one upstream fetch
- [x] SNI-rewrite tunnels (direct to Google edge, bypassing the relay) for `google.com`, `youtube.com`, `youtu.be`, `youtube-nocookie.com`, `fonts.googleapis.com`. Extra domains configurable via the `hosts` map.
- [x] Automatic redirect handling on the relay (`/exec` → `googleusercontent.com`)
- [x] Header filtering (strip connection-specific, brotli)
- [x] `test` and `scan-ips` subcommands
- [x] Script IDs masked in logs (`prefix…suffix`) so `info` logs don't leak deployment IDs
- [x] Desktop UI (egui) — cross-platform, no bundler needed
- [x] Optional upstream SOCKS5 chaining for non-HTTP traffic (Telegram MTProto, IMAP, SSH…) so raw-TCP flows can be tunneled through xray / v2ray / sing-box instead of connecting directly. HTTP/HTTPS keeps going through the Apps Script relay.
- [x] Connection pool pre-warm on startup (first request skips the TLS handshake to Google edge).
- [x] Per-connection SNI rotation across a pool of Google subdomains (`www/mail/drive/docs/calendar.google.com`), so outbound connection counts aren't concentrated on one SNI.
- [x] Optional parallel script-ID dispatch (`parallel_relay`): fan out a relay request to N script instances concurrently, return first success, kill p95 latency at the cost of N× quota.
- [x] Per-site stats drill-down in the UI (requests, cache hit %, bytes, avg latency per host) for live debugging.
- [x] Editable SNI rotation pool (UI window + `sni_hosts` config field) with per-name reachability probes (`mhrv-rs test-sni` CLI or **Test** / **Test all** / **Keep working only** buttons). DNS + TLS-handshake based, catches both DPI-blocked names and typos.
- [x] OpenWRT / Alpine / musl builds — static binaries, procd init script included.

Intentionally **not** implemented (rationale included so future contributors don't spend cycles on them):

- **HTTP/2 multiplexing** — the `h2` crate state machine (stream IDs, flow control, GOAWAY) has too many subtle hang cases; coalescing + 20-connection pool already gets most of the benefit for this workload.
- **Request batching (`q:[...]` mode)** — our connection pool + tokio async already parallelizes well; batching adds ~200 lines of state management with unclear incremental gain.
- **Range-based parallel download** — edge cases (non-Range servers, chunked mid-stream, content-encoding) are real; YouTube-style video already bypasses Apps Script via SNI-rewrite tunnel.
- **Other modes** (`domain_fronting`, `google_fronting`, `custom_domain`) — Cloudflare killed generic domain fronting in 2024; Cloud Run needs a paid plan. Skip unless specifically requested.

## Known limitations

These are inherent to the Apps Script + domain-fronting approach, not bugs in this client. The original Python version has the same issues.

- **User-Agent is fixed to `Google-Apps-Script`** for anything going through the relay. `UrlFetchApp.fetch()` does not allow overriding it. Consequence: sites that detect bots (e.g., Google search, some CAPTCHA flows) serve degraded / no-JS fallback pages to relayed requests. Workaround: add the affected domain to the `hosts` map so it's routed through the SNI-rewrite tunnel with your real browser's UA instead. `google.com`, `youtube.com`, `fonts.googleapis.com` are already there by default.
- **Video playback is slow and quota-limited** for anything that goes through the relay. YouTube HTML loads through the tunnel (fast), but chunks from `googlevideo.com` go through Apps Script. Each Apps Script consumer account has a ~2 M `UrlFetchApp` calls/day quota and a 50 MB body limit per fetch. Fine for text browsing, painful for 1080p. Rotate multiple `script_id`s for more headroom, or use a real VPN for video.
- **Brotli is stripped** from forwarded `Accept-Encoding` headers. Apps Script can decompress gzip, but not `br`, and forwarding `br` produces garbled responses. Minor size overhead.
- **WebSockets don't work** through the relay — it's single request/response JSON. Sites that upgrade to WS fail (ChatGPT streaming, Discord voice, etc.).
- **HSTS-preloaded / hard-pinned sites** will reject the MITM cert. Most sites are fine because the CA is trusted; a handful aren't.
- **Google / YouTube 2FA and sensitive logins** may trigger "unrecognized device" warnings because requests originate from Google's Apps Script IPs, not yours. Log in once via the tunnel (`google.com` is in the rewrite list) to avoid this.

## Security posture

- The MITM root stays **on your machine only**. The `ca/ca.key` private key is generated locally and never leaves the user-data dir.
- `auth_key` between the client and the Apps Script relay is a shared secret you pick. The server-side `Code.gs` rejects requests without a matching key.
- Traffic between your machine and Google's edge is standard TLS 1.3.
- What Google can see: the destination URL and headers of each request (because Apps Script fetches on your behalf). This is the same trust model as any hosted proxy — if that's not acceptable, use a self-hosted VPN instead.

## License

MIT. See [LICENSE](LICENSE).

## Credit

Original project: <https://github.com/masterking32/MasterHttpRelayVPN> by [@masterking32](https://github.com/masterking32). The idea, the Google Apps Script protocol, the proxy architecture, and the ongoing maintenance are all his. This Rust port exists purely to make client-side distribution easier.

---

<div dir="rtl">

## راهنمای فارسی

پورت Rust پروژهٔ [MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN) از [@masterking32](https://github.com/masterking32). **تمام اعتبار ایده و پیاده‌سازی اصلی پایتون متعلق به ایشان است.** این نسخه فقط مدل `apps_script` را به‌صورت دو فایل اجرایی کوچک (CLI + رابط گرافیکی) بدون هیچ وابستگی run-time ارائه می‌دهد.

عبور رایگان از DPI با استفاده از Google Apps Script به‌عنوان رله، به‌همراه مخفی‌سازی SNI در TLS. سانسور ISP فکر می‌کند ترافیک شما به سمت `www.google.com` می‌رود؛ در پشت صحنه یک Apps Script که خودتان در اکانت گوگل خودتان دیپلوی کرده‌اید سایت اصلی را برای شما واکشی می‌کند.

### چرا این نسخه؟

نسخهٔ اصلی پایتون عالی است، اما نیاز به Python + نصب `cryptography` و `h2` و چند وابستگی سیستمی دارد. برای کاربرانی که PyPI فیلتر است یا Python ندارند این فرآیند خودش یک دردسر است. این پورت فقط یک فایل اجرایی ~۲.۵ مگابایتی است که دانلود می‌کنید و اجرا می‌کنید. تمام.

### نحوهٔ کار

مرورگر/تلگرام/xray شما با این ابزار به‌عنوان HTTP proxy یا SOCKS5 proxy صحبت می‌کند. ابزار ترافیک را از طریق TLS به یک IP گوگل می‌فرستد، اما SNI را `www.google.com` می‌گذارد. داخل TLS رمزگذاری‌شده، header به‌نام `Host: script.google.com` رد می‌شود. DPI فقط `www.google.com` را می‌بیند و اجازه عبور می‌دهد. Apps Script سایت مقصد را واکشی می‌کند و پاسخ را به شما بازمی‌گرداند.

برای چند دامنهٔ متعلق به خود گوگل (`google.com`، `youtube.com`، `fonts.googleapis.com` و …) از همین تونل مستقیم استفاده می‌شود بدون عبور از Apps Script. این کار هم مشکل سهمیهٔ Apps Script را حل می‌کند و هم مشکل «User-Agent همیشه Google-Apps-Script است» را برای این دامنه‌ها از بین می‌برد. می‌توانید دامنه‌های بیشتری را از طریق `hosts` در config اضافه کنید.

### پلتفرم‌ها

لینوکس (x86_64، aarch64)، مک‌اواس (x86_64، aarch64)، ویندوز (x86_64). فایل‌های آماده در [صفحهٔ releases](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases).

### محتوای هر release

هر آرشیو شامل دو باینری و یک اسکریپت راه‌انداز است:

- `mhrv-rs` / `mhrv-rs.exe` — نسخهٔ CLI، برای سرور و استفادهٔ headless.
- `mhrv-rs-ui` / `mhrv-rs-ui.exe` — رابط گرافیکی دسکتاپ (egui). فرم تنظیمات، دکمه‌های Start/Stop/Test، آمار زنده، لاگ.
- `run.sh` / `run.command` / `run.bat` — اسکریپت راه‌انداز مخصوص هر سیستم‌عامل: اول CA را نصب می‌کند (نیاز به sudo/Administrator) بعد UI را اجرا می‌کند. **بار اول حتماً همین را اجرا کنید.**

نسخهٔ مک آرشیو `*-app.zip` هم دارد که داخلش `mhrv-rs.app` است — با دو بار کلیک از Finder اجرا می‌شود. ولی بار اول باید CA را نصب کنید (با `mhrv-rs --install-cert` یا همان `run.command`).

### مسیر فایل‌ها

Config و ریشهٔ MITM در پوشهٔ کاربر سیستم‌عامل قرار می‌گیرند:

- مک: `~/Library/Application Support/mhrv-rs/`
- لینوکس: `~/.config/mhrv-rs/`
- ویندوز: `%APPDATA%\mhrv-rs\`

داخل این پوشه: `config.json`، `ca/ca.crt` (گواهی عمومی) و `ca/ca.key` (کلید خصوصی — فقط روی سیستم شماست و هرگز جایی ارسال نمی‌شود).

### مراحل راه‌اندازی

#### ۱. دیپلوی Apps Script (یک بار)

این بخش دقیقاً همان نسخهٔ اصلی است:

۱. به <https://script.google.com> بروید و با اکانت گوگل وارد شوید.
۲. **New project** بزنید و کد پیش‌فرض را پاک کنید.
۳. محتوای [`Code.gs`](https://github.com/masterking32/MasterHttpRelayVPN/blob/python_testing/Code.gs) ([لینک raw](https://raw.githubusercontent.com/masterking32/MasterHttpRelayVPN/refs/heads/python_testing/Code.gs)) را از ریپو اصلی کپی و Paste کنید.
۴. خط `const AUTH_KEY = "..."` را به یک رمز قوی و مختص خودتان تغییر دهید.
۵. **Deploy → New deployment → Web app**
   - Execute as: **Me**
   - Who has access: **Anyone**
۶. **Deployment ID** را کپی کنید (رشتهٔ تصادفی طولانی داخل URL).

#### ۲. دانلود

آرشیو پلتفرم خود را از [صفحهٔ releases](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases) بگیرید و extract کنید.

#### ۳. اجرای بار اول: نصب گواهی MITM

برای اینکه ترافیک HTTPS مرورگر از طریق Apps Script رد شود، `mhrv-rs` باید TLS را **روی سیستم خودتان** باز کند، درخواست را از رله بفرستد، و پاسخ را با یک گواهی که مرورگر شما trust می‌کند دوباره رمزگذاری کند. این کار یک **Certificate Authority محلی** کوچک نیاز دارد.

**چه اتفاقی در اجرای بار اول می‌افتد:**

- یک keypair تازهٔ CA (`ca/ca.crt` + `ca/ca.key`) **روی سیستم شما** در پوشهٔ user-data ساخته می‌شود.
- فایل عمومی `ca.crt` به trust store سیستم اضافه می‌شود تا مرورگر گواهی‌های per-site که `mhrv-rs` on-the-fly می‌سازد را بپذیرد. همین مرحله است که sudo / Administrator می‌خواهد.
- کلید خصوصی `ca.key` **هرگز از سیستم شما خارج نمی‌شود**. جایی آپلود نمی‌شود، با هیچ سرور راه دوری تماس گرفته نمی‌شود، و هیچ طرف دیگری — از جمله رلهٔ Apps Script — نمی‌تواند با آن خودش را جای سایت‌ها جا بزند.
- هر وقت خواستید می‌توانید حذفش کنید: keychain مک (Keychain Access → System → `mhrv-rs` را حذف کنید) / cert store ویندوز / `/etc/ca-certificates` در لینوکس، به‌علاوهٔ پاک کردن پوشهٔ `ca/`.

اسکریپت راه‌انداز همهٔ این کارها را برایتان انجام می‌دهد و بعد UI را باز می‌کند:

- **مک**: روی `run.command` دو بار کلیک کنید (یا از ترمینال `./run.command`).
- **لینوکس**: در ترمینال `./run.sh`.
- **ویندوز**: روی `run.bat` دو بار کلیک کنید.

اسکریپت **فقط** برای trust کردن CA رمز شما را می‌خواهد (sudo یا UAC). بعد از آن UI هم باز می‌شود، و در اجراهای بعدی دیگر لازم نیست از launcher استفاده کنید — مستقیماً `mhrv-rs.app` یا `mhrv-rs-ui.exe` یا `mhrv-rs-ui` را اجرا کنید.

اگر ترجیح می‌دهید مرحلهٔ CA را دستی انجام دهید:

```bash
# لینوکس/مک
sudo ./mhrv-rs --install-cert

# ویندوز (به‌عنوان Administrator)
mhrv-rs.exe --install-cert
```

Firefox cert store خودش را جدا دارد؛ installer تلاش می‌کند از طریق `certutil` گواهی را داخل NSS فایرفاکس هم بیندازد (best-effort). اگر فایرفاکس هنوز شکایت کرد، خودتان دستی `ca/ca.crt` را از Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import اضافه کنید.

#### ۴. تنظیمات در UI

فرم را پر کنید:

- **Apps Script ID** — همان Deployment ID مرحلهٔ ۱. برای استفاده از چند deployment به‌صورت round-robin، با کاما جدا کنید.
- **Auth key** — همان رمز `AUTH_KEY` داخل `Code.gs`.
- **Google IP** — پیش‌فرض `216.239.38.120` خوب است. دکمهٔ **scan** کنارش IPهای دیگر گوگل را از شبکهٔ شما تست می‌کند و سریع‌ترین را معرفی می‌کند.
- **Front domain** — همان `www.google.com` را نگه دارید.
- **HTTP port** / **SOCKS5 port** — پیش‌فرض‌ها `8085` و `8086`.

**Save** بعد **Start**. دکمهٔ **Test** در هر زمان یک درخواست کامل از طریق رله می‌فرستد و نتیجه را گزارش می‌دهد.

#### ۴ (جایگزین). فقط CLI

هر کاری که UI می‌کند از CLI هم قابل انجام است. `config.example.json` را به `config.json` کپی و مقادیر را پر کنید، بعد:

```bash
./mhrv-rs                   # اجرای proxy
./mhrv-rs test              # تست یک درخواست کامل
./mhrv-rs scan-ips          # رتبه‌بندی IPهای گوگل بر اساس تأخیر
./mhrv-rs --install-cert    # نصب مجدد CA
./mhrv-rs --help
```

#### ۵. تنظیم proxy در کلاینت

ابزار روی **دو** پورت گوش می‌دهد:

**HTTP proxy** (مرورگرها) — `127.0.0.1:8085`

- **Firefox** — Settings → Network Settings → **Manual proxy**. HTTP برابر `127.0.0.1`، port `8085`، تیک **Also use this proxy for HTTPS**.
- **Chrome / Edge** — از تنظیمات proxy سیستم یا افزونهٔ **Proxy SwitchyOmega** استفاده کنید.
- **مک (system-wide)** — System Settings → Network → Wi-Fi → Details → Proxies → **Web Proxy (HTTP)** و **Secure Web Proxy (HTTPS)** را فعال کنید، هر دو `127.0.0.1:8085`.
- **ویندوز (system-wide)** — Settings → Network & Internet → Proxy → **Manual proxy setup**، address `127.0.0.1`، port `8085`.

**SOCKS5 proxy** (تلگرام، xray، کلاینت‌های app-level) — `127.0.0.1:8086`، بدون auth.

برای HTTP و HTTPS و **هم** پروتکل‌های غیر-HTTP (MTProto تلگرام، TCP خام) کار می‌کند. ابزار به‌صورت هوشمند تشخیص می‌دهد: HTTP/HTTPS از رلهٔ Apps Script می‌رود، دامنه‌های قابل SNI-rewrite از تونل مستقیم لبهٔ گوگل، و بقیه به TCP خام می‌افتد.

### تلگرام، IMAP، SSH — با xray جفت کنید (اختیاری)

رلهٔ Apps Script فقط HTTP request/response می‌فهمد، پس پروتکل‌های غیر-HTTP (MTProto تلگرام، IMAP، SSH، TCP خام) از داخلش عبور نمی‌کنند. بدون کار اضافه این جور ترافیک به مسیر TCP مستقیم می‌افتد — یعنی واقعاً tunnel نمی‌شود و اگر ISP تلگرام را بلاک کرده باشد، همچنان بلاک است.

راه حل: یک [xray](https://github.com/XTLS/Xray-core) (یا v2ray / sing-box) با outbound VLESS/Trojan/Shadowsocks به یک VPS شخصی خودتان بالا بیاورید، و mhrv-rs را از طریق فیلد **Upstream SOCKS5** در UI (یا کلید `upstream_socks5` در config) به SOCKS5 inbound آن وصل کنید. با این کار ترافیک TCP خامی که از SOCKS5 mhrv-rs رد می‌شود، به‌جای اتصال مستقیم، از xray رد شده و به تونل واقعی می‌رسد.

```
تلگرام   ┐                                                   ┌─ Apps Script ── HTTP/HTTPS
         ├─ SOCKS5 :8086 ┤ mhrv-rs ├─ SNI rewrite ─── google.com, youtube.com, …
مرورگر   ┘                                                   └─ upstream SOCKS5 ─ xray ── VLESS ── VPS شما   (تلگرام، IMAP، SSH، TCP خام)
```

قطعه‌ای از config:

```json
{
  "upstream_socks5": "127.0.0.1:50529"
}
```

HTTP/HTTPS هیچ تغییری نمی‌کند (همچنان از Apps Script می‌رود) و تونل SNI-rewrite برای `google.com` / `youtube.com` / … هم سر جای خودش است — پس یوتوب مثل قبل سریع می‌ماند و تلگرام بالاخره یک تونل واقعی می‌گیرد.

### ویرایشگر SNI pool

به‌صورت پیش‌فرض `mhrv-rs` بین `{www, mail, drive, docs, calendar}.google.com` روی اتصال‌های TLS خروجی به IP گوگل می‌چرخد تا یک نام تنها fingerprint نشود. بعضی از این‌ها ممکن است در شبکهٔ شما بلاک باشند — مثلاً `mail.google.com` در ایران چند بار هدف گرفته شده.

یا:

- UI را باز کنید، روی **SNI pool…** کلیک کنید، **Test all** را بزنید، بعد **Keep ✓ only** برای trim خودکار. از textbox پایین می‌توانید نام‌های دلخواه اضافه کنید. Save بزنید.
- یا مستقیماً در `config.json`:

```json
{
  "sni_hosts": ["www.google.com", "drive.google.com", "docs.google.com"]
}
```

اگر `sni_hosts` را نگذارید، pool پیش‌فرض اعمال می‌شود. قبل از ذخیره، `mhrv-rs test-sni` را اجرا کنید تا ببینید چه نامی از شبکهٔ شما رد می‌شود.

### اجرا روی OpenWRT (یا هر سیستم musl)

آرشیوهای `*-linux-musl-*` یک CLI کاملاً static می‌دهند که روی OpenWRT، Alpine و هر userland لینوکسی بدون glibc اجرا می‌شود. باینری را روی روتر بگذارید و به‌عنوان سرویس راه بیندازید:

```sh
# از یک ماشین که به روترتان می‌رسد:
scp mhrv-rs root@192.168.1.1:/usr/bin/mhrv-rs
scp mhrv-rs.init root@192.168.1.1:/etc/init.d/mhrv-rs
scp config.json root@192.168.1.1:/etc/mhrv-rs/config.json

# روی خود روتر:
chmod +x /usr/bin/mhrv-rs /etc/init.d/mhrv-rs
/etc/init.d/mhrv-rs enable
/etc/init.d/mhrv-rs start
logread -e mhrv-rs -f
```

بعدش دستگاه‌های LAN، proxy HTTP خودشان را روی IP روتر پورت `8085` (یا SOCKS5 روی `8086`) بگذارند. در `/etc/mhrv-rs/config.json` مقدار `listen_host` را به `0.0.0.0` تغییر دهید تا روتر از LAN هم connection بپذیرد (نه فقط localhost).

مصرف حافظه حدود ۱۵-۲۰ مگابایت است — روی هر روتری با حداقل ۱۲۸ مگابایت RAM اجرا می‌شود. UI برای musl ساخته نمی‌شود (روترها بدون صفحه‌نمایش هستند).

### محدودیت‌های شناخته‌شده

این‌ها محدودیت‌های ذاتی روش Apps Script + SNI هستند، نه باگ در این کلاینت. نسخهٔ اصلی پایتون هم دقیقاً همین‌ها را دارد.

- **User-Agent همیشه `Google-Apps-Script` است** برای هر چیزی که از رله رد می‌شود. `UrlFetchApp.fetch()` گوگل اجازهٔ تغییر این را نمی‌دهد. نتیجه: سایت‌هایی که ربات را تشخیص می‌دهند (مثل جست‌وجوی `google.com`، بعضی CAPTCHAها) نسخهٔ سادهٔ بدون JS را نشان می‌دهند. راه‌حل: دامنهٔ موردنظر را به `hosts` در `config.json` اضافه کنید تا از تونل SNI-rewrite (با UA واقعی مرورگر) رد شود. `google.com`، `youtube.com`، `fonts.googleapis.com` از قبل در این لیست هستند.
- **پخش ویدیو کند است و سهمیه دارد** برای چیزهایی که از رله رد می‌شوند. HTML یوتوب از تونل می‌آید (سریع)، اما chunkهای ویدیو از `googlevideo.com` از طریق Apps Script می‌آیند. هر اکانت consumer گوگل روزانه ~۲ میلیون `UrlFetchApp` call و سقف ۵۰ مگابایت روی هر fetch دارد. برای مرور متنی عالی است، برای ۱۰۸۰p دردناک. چند `script_id` بگذارید، یا برای ویدیو از VPN واقعی استفاده کنید.
- **Brotli فیلتر می‌شود** از header ارسالی `Accept-Encoding`. Apps Script می‌تواند gzip باز کند اما brotli نه، و اگر `br` را رد کنیم پاسخ خراب می‌شود. gzip فعال است. سربار حجمی جزئی.
- **WebSocket کار نمی‌کند** از طریق رله (تک request/response JSON است). سایت‌هایی که به WS ارتقا می‌دهند fail می‌کنند (streaming ChatGPT، voice دیسکورد و غیره).
- **سایت‌های HSTS-preloaded / pin-شده** گواهی MITM را قبول نمی‌کنند. اکثر سایت‌ها مشکلی ندارند چون CA ما trust شده، ولی چند مورد استثنا هستند.
- **ورود دومرحله‌ای گوگل/یوتوب** ممکن است «دستگاه ناشناس» هشدار بدهد چون درخواست از IP Apps Script می‌آید نه IP شما. یک بار با تونل (`google.com` از قبل در لیست است) لاگین کنید.

### امنیت

- ریشهٔ MITM **فقط روی سیستم شما می‌ماند**. کلید خصوصی `ca/ca.key` محلی ساخته می‌شود و هرگز از user-data dir خارج نمی‌شود.
- `auth_key` بین کلاینت و Apps Script یک secret مشترک است که خودتان انتخاب می‌کنید. کد سرور (`Code.gs`) هر درخواستی را که این کلید را نداشته باشد رد می‌کند.
- ترافیک بین سیستم شما و لبهٔ گوگل TLS 1.3 استاندارد است.
- آنچه گوگل می‌بیند: URL و headerهای درخواست (چون Apps Script به‌جای شما fetch می‌کند). این دقیقاً همان trust model هر proxy میزبانی‌شده است — اگر قابل قبول نیست از VPN self-hosted استفاده کنید.

### اعتبار

پروژهٔ اصلی: <https://github.com/masterking32/MasterHttpRelayVPN> توسط [@masterking32](https://github.com/masterking32). ایده، پروتکل Apps Script، معماری proxy و نگهداری همه متعلق به ایشان است. این پورت Rust فقط برای ساده‌کردن توزیع سمت کلاینت درست شده.

</div>
