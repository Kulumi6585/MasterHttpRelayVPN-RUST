# MasterHttpRelayVPN-RUST

Rust port of [@masterking32's MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN). **All credit for the original idea and the Python implementation goes to [@masterking32](https://github.com/masterking32).** This is a faithful Rust reimplementation of the `apps_script` mode packaged as a single static binary.

Free DPI bypass via Google Apps Script as a remote relay and TLS SNI concealment. Your ISP's censor sees traffic going to `www.google.com`; behind the scenes a free Google Apps Script fetches the real website for you.

**[English Guide](#setup-guide)** | **[Persian Guide](#%D8%B1%D8%A7%D9%87%D9%86%D9%85%D8%A7%DB%8C-%D9%81%D8%A7%D8%B1%D8%B3%DB%8C)**

## Why this exists

The original Python project is excellent but requires Python + `pip install cryptography + h2` + runtime deps. For users in hostile networks, that install process is often itself broken (blocked PyPI, missing wheels, Windows without Python). This port is a single ~2.5 MB executable that you download and run. Nothing else.

## How it works

```
Browser -> mhrv-rs (local HTTP proxy) -> TLS to Google IP with SNI=www.google.com
                                                |
                                                | Host: script.google.com (inside TLS)
                                                v
                                         Apps Script relay (your free Google account)
                                                |
                                                v
                                         Real destination
```

The censor's DPI sees `www.google.com` in the TLS SNI and lets it through. Google's frontend hosts both `www.google.com` and `script.google.com` on the same IP and routes by the HTTP Host header inside the encrypted stream.

## Platforms

Linux (x86_64/aarch64), macOS (x86_64/aarch64), Windows (x86_64). Prebuilt binaries on the [releases page](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases).

## Setup Guide

### Step 1: Deploy the Apps Script relay (one-time)

This part is unchanged from the original project. Follow @masterking32's guide, or the summary below:

1. Open <https://script.google.com> with your Google account
2. **New project**, delete the default code
3. Copy the contents of [`Code.gs` from the original repo](https://github.com/masterking32/MasterHttpRelayVPN/blob/python_testing/Code.gs) ([raw link](https://raw.githubusercontent.com/masterking32/MasterHttpRelayVPN/refs/heads/python_testing/Code.gs)) into the editor
4. **Change** the line `const AUTH_KEY = "..."` to a strong secret only you know
5. **Deploy → New deployment → Web app**
   - Execute as: **Me**
   - Who has access: **Anyone**
6. Copy the **Deployment ID** (long random string in the URL).

### Step 2: Download mhrv-rs

Download the right binary from the [releases page](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases) for your platform. Or build from source:

```bash
cargo build --release
```

### Step 3: Configure

Copy `config.example.json` to `config.json` and fill in your values:

```json
{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "PASTE_YOUR_DEPLOYMENT_ID_HERE",
  "auth_key": "same-secret-as-in-code-gs",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "log_level": "info",
  "verify_ssl": true
}
```

`script_id` can also be an array of IDs for round-robin rotation across multiple deployments (higher quota, more throughput).

### Step 4: Install the MITM CA (one-time)

The tool needs to decrypt your browser's HTTPS locally so it can forward each request through the Apps Script relay. First run generates a local CA; install it as trusted:

```bash
# Linux / macOS
sudo ./mhrv-rs --install-cert

# Windows (Administrator)
mhrv-rs.exe --install-cert
```

The CA is saved at `./ca/ca.crt` — only you have the private key.

### Step 5: Run

```bash
./mhrv-rs --config config.json      # Linux/macOS
mhrv-rs.exe --config config.json    # Windows
```

### Diagnostic subcommands

- **`mhrv-rs test`** — send one request through the relay and report success/timing. Useful when setting up or debugging. Does not need the proxy to be running.
- **`mhrv-rs scan-ips`** — parallel TLS probe of known Google frontend IPs, sorted by latency. Swap the winning IP into your `google_ip` config field for best performance.

### Step 6: Point your client at the proxy

The tool listens on **two** ports:
- **HTTP proxy** on `listen_port` (default `8085`) — for browsers / any HTTP-aware client
- **SOCKS5 proxy** on `socks5_port` (default `listen_port + 1`, i.e. `8086`) — for xray / Telegram / app-level clients

**Browser (HTTP proxy):**
- **Firefox**: Settings → Network Settings → Manual proxy → HTTP `127.0.0.1:8085`, check "Also use this proxy for HTTPS"
- **Chrome/Edge**: System proxy settings, or SwitchyOmega
- **macOS system-wide**: System Settings → Network → Wi-Fi → Details → Proxies → Web + Secure Web Proxy

**xray / Telegram (SOCKS5):**
- Point the SOCKS5 setting at `127.0.0.1:8086`, no auth.
- Non-HTTP protocols (MTProto, raw TCP) fall back to plain-TCP passthrough automatically.

## What's implemented vs not

This port focuses on the **`apps_script` mode** which is the only one that reliably works in 2026. Implemented:

- [x] Local HTTP proxy (CONNECT for HTTPS, plain forwarding for HTTP)
- [x] MITM with on-the-fly per-domain cert generation via `rcgen`
- [x] CA generation + auto-install on macOS / Linux / Windows
- [x] Firefox NSS cert install (best effort via `certutil`)
- [x] Apps Script JSON relay, protocol-compatible with `Code.gs`
- [x] Connection pooling (45s TTL, max 20 idle)
- [x] Gzip response decoding
- [x] Multi-script round-robin
- [x] Auto-blacklist failing scripts on 429 / quota errors (10-minute cooldown)
- [x] Response cache (50 MB, FIFO + TTL, parses `Cache-Control: max-age`, heuristics for static assets)
- [x] Request coalescing: concurrent identical GETs share one upstream fetch
- [x] SNI-rewrite tunnels (direct-to-Google-edge bypassing the relay) for `google.com`, `youtube.com`, `youtu.be`, `youtube-nocookie.com`, `fonts.googleapis.com`. Extra domains can be added via the `hosts` map in config — see "Known limitations" below.
- [x] Automatic redirect handling on the relay (`/exec` → `googleusercontent.com`)
- [x] Header filtering (strip connection-specific + brotli)
- [x] `mhrv-rs test` subcommand — one-shot end-to-end relay probe
- [x] `mhrv-rs scan-ips` subcommand — parallel probe 28 Google frontend IPs, sorted by latency
- [x] Periodic stats log every 60 s (relay calls, cache hit rate, bytes, active scripts)
- [x] Script IDs masked in logs (prefix...suffix) so `info` logs don't leak deployment IDs

Intentionally NOT implemented (rationale included so future contributors don't spend cycles on them):

- [ ] **HTTP/2 multiplexing** — `h2` crate state machine (stream IDs, flow control, GOAWAY) has too many subtle hang cases; coalescing + 20-connection pool already gets most of the benefit for this workload
- [ ] **Request batching (`q:[...]` mode)** — our connection pool + tokio async already parallelizes well; batching adds ~200 lines of state management with unclear incremental gain over the current flow
- [ ] **Range-based parallel download** — edge cases (non-Range servers, chunked mid-stream, content-encoding) are real; YouTube-style video already bypasses Apps Script via SNI-rewrite tunnel
- [ ] **Other modes** (`domain_fronting`, `google_fronting`, `custom_domain`) — Cloudflare killed generic domain fronting in 2024; Cloud Run needs paid plan; skip unless specifically requested

## Known limitations

These are inherent to the Apps Script + domain-fronting approach, not bugs in this client. Same issues exist in the original Python version.

- **User-Agent is fixed to `Google-Apps-Script`** for any request going through the relay. Google's `UrlFetchApp.fetch()` does not allow overriding it. Consequence: sites that detect bots (e.g., `google.com` search, some CAPTCHAs) will serve degraded / no-JavaScript fallback pages to relayed requests. Workaround: add the affected domain to the `hosts` map in `config.json` so it's routed via the SNI-rewrite tunnel (real browser UA) instead of the relay. `google.com`, `youtube.com`, `fonts.googleapis.com` are already done by default.

- **Video playback is slow and quota-limited** for anything that goes through the relay. YouTube HTML loads via the tunnel (fast) but chunks from `googlevideo.com` go through Apps Script. Each Apps Script account has a ~2 million `UrlFetchApp` calls/day consumer quota and a 50 MB body limit per fetch. Fine for text browsing, painful for 1080p video. Use multiple `script_id`s in rotation for more headroom, or use a real VPN for video.

- **Brotli compression is stripped** from forwarded `Accept-Encoding` headers. Apps Script can decompress gzip but not brotli; forwarding `br` would produce garbled responses. Gzip still works. Minor size overhead for responses that would've been brotli.

- **WebSockets don't work** through Apps Script (the relay does single request/response JSON). Sites that upgrade to WS fail. This covers `chat.openai.com` streaming, Discord voice, etc.

- **HTTPS sites your browser has pinned** (HSTS preloaded list, extended validation) will reject the MITM cert. Most sites work fine because we install our CA as trusted; a few hard-pinned ones won't.

- **Google/YouTube 2FA / sensitive logins** may see "unrecognized device" warnings because the request originates from Google's Apps Script infrastructure IP, not your real IP. Log in via tunnel first (`google.com` is in the rewrite list) to avoid this.

## License

MIT. See [LICENSE](LICENSE).

## Credit

Original project: <https://github.com/masterking32/MasterHttpRelayVPN> by [@masterking32](https://github.com/masterking32). The idea, the Google Apps Script protocol, the proxy architecture, and the ongoing maintenance are all his. This Rust port exists only to make the client-side distribution easier.

---

## راهنمای فارسی

پورت Rust پروژه [MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN) از [@masterking32](https://github.com/masterking32). **تمام اعتبار ایده و نسخه اصلی Python متعلق به ایشان است.** این نسخه فقط مدل `apps_script` را به‌صورت یک فایل اجرایی مستقل (بدون نیاز به نصب Python) ارائه می‌دهد.

### چرا این نسخه؟

نسخه اصلی Python عالی است ولی نیاز به Python + نصب `cryptography` و `h2` دارد. برای کاربرانی که PyPI فیلتر شده یا Python ندارند، این فرایند خودش مشکل است. این پورت فقط یک فایل ~۲.۵ مگابایتی است که دانلود می‌کنید و اجرا می‌کنید.

### نحوه کار

مرورگر شما با این ابزار به‌عنوان HTTP proxy صحبت می‌کند. ابزار ترافیک را از طریق TLS به IP گوگل می‌فرستد ولی SNI را `www.google.com` می‌گذارد. داخل TLS رمزگذاری‌شده، HTTP request به `script.google.com` می‌رود. DPI فقط `www.google.com` را می‌بیند. Apps Script سایت مقصد را واکشی و پاسخ را برمی‌گرداند.

### مراحل راه‌اندازی

#### ۱. راه‌اندازی Apps Script (یک‌بار)

این بخش دقیقاً همان نسخه اصلی است:

1. به <https://script.google.com> بروید و با اکانت گوگل وارد شوید
2. **New project** بزنید، کد پیش‌فرض را پاک کنید
3. محتوای [`Code.gs`](https://github.com/masterking32/MasterHttpRelayVPN/blob/python_testing/Code.gs) ([لینک raw](https://raw.githubusercontent.com/masterking32/MasterHttpRelayVPN/refs/heads/python_testing/Code.gs)) را از ریپو اصلی کپی کنید و Paste کنید
4. در خط `const AUTH_KEY = "..."` رمز را به یک مقدار قوی و مخصوص خودتان تغییر دهید
5. **Deploy → New deployment → Web app**
   - Execute as: **Me**
   - Who has access: **Anyone**
6. **Deployment ID** (رشته تصادفی طولانی) را کپی کنید

#### ۲. دانلود mhrv-rs

از [صفحه releases](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases) باینری پلتفرم خود را دانلود کنید.

#### ۳. تنظیمات

فایل `config.example.json` را به `config.json` کپی کنید و مقادیر را پر کنید. `script_id` می‌تواند یک رشته یا آرایه‌ای از رشته‌ها باشد (برای چرخش بین چند deployment).

#### ۴. نصب CA (یک‌بار)

ابزار باید TLS مرورگر شما را محلی رمزگشایی کند. بار اول یک CA می‌سازد که باید trust کنید:

```bash
# لینوکس/مک
sudo ./mhrv-rs --install-cert

# ویندوز (Administrator)
mhrv-rs.exe --install-cert
```

#### ۵. اجرا

```bash
./mhrv-rs --config config.json
```

#### ۶. تنظیم proxy در مرورگر

Proxy مرورگر را روی `127.0.0.1:8085` بگذارید (هم HTTP و هم HTTPS).

### محدودیت‌های شناخته‌شده

این‌ها محدودیت‌های ذاتی روش Apps Script هستند، نه باگ در این کلاینت. نسخه اصلی Python هم همین مشکلات را دارد.

- **User-Agent همیشه `Google-Apps-Script` است** برای هر درخواستی که از رله رد می‌شود. `UrlFetchApp.fetch()` گوگل اجازه تغییر این را نمی‌دهد. نتیجه: سایت‌هایی که ربات را تشخیص می‌دهند (مثل جست‌وجوی `google.com`، بعضی CAPTCHA‌ها) نسخه ساده بدون JS را سرو می‌کنند. راه‌حل: دامنه مورد نظر را به `hosts` در `config.json` اضافه کنید تا از مسیر SNI-rewrite (با UA واقعی مرورگر) بگذرد. `google.com`، `youtube.com`، `fonts.googleapis.com` از قبل در این لیست هستند.

- **پخش ویدیو کند است و محدودیت سهمیه دارد** برای چیزهایی که از رله رد می‌شوند. صفحه HTML یوتوب از طریق تونل می‌آید (سریع)، ولی chunk‌های ویدیو از `googlevideo.com` از طریق Apps Script می‌آیند. هر اکانت Apps Script روزانه ~۲ میلیون فراخوانی و هر درخواست حداکثر ۵۰ مگابایت. برای متن مرور اوکی، برای ۱۰۸۰p دردناک. چند `script_id` بگذارید یا برای ویدیو از VPN واقعی استفاده کنید.

- **فشرده‌سازی Brotli فیلتر می‌شود**. Apps Script gzip می‌تواند باز کند ولی brotli نه.

- **WebSocket کار نمی‌کند** (رله تک‌درخواستی است). پیام‌رسان‌ها و استریم OpenAI chat روی این کار نمی‌کنند.

- **ورود دومرحله‌ای گوگل/یوتوب** ممکن است "دستگاه ناشناس" بگوید چون درخواست از IP Apps Script می‌آید نه IP شما. اول با تونل (`google.com` در لیست است) لاگین کنید.

### اعتبار

پروژه اصلی: <https://github.com/masterking32/MasterHttpRelayVPN> توسط [@masterking32](https://github.com/masterking32). تمام ایده، پروتکل Apps Script، و نگهداری متعلق به ایشان است. این پورت Rust فقط برای ساده کردن توزیع سمت کلاینت است.
