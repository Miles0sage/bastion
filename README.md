# Bastion

**Your own Cloudflare. One binary. Zero bills.**

Bastion is a self-hosted edge platform that replaces Cloudflare, Nginx, and Caddy with a single Go binary. Reverse proxy, auto-SSL, WireGuard tunnels, rate limiting, IP blocking, and a real-time dashboard — all in ~1,200 lines of Go. No Docker. No YAML. No monthly invoice.

```bash
bastion init      # creates bastion.json
bastion up        # proxy + dashboard + auto-SSL
```

That's it. Your services are live with HTTPS.

---

## Features

- [x] **Reverse proxy** with subdomain routing
- [x] **Auto-SSL** via Let's Encrypt (zero config)
- [x] **WireGuard tunnels** — expose localhost to the internet, no port forwarding
- [x] **Real-time dashboard** with dark theme UI
- [x] **Rate limiting** — 100 req/min per IP, configurable
- [x] **IP blocklist** — block/unblock from the dashboard
- [x] **SQLite request logging** — every request persisted, queryable
- [x] **Session auth** — bcrypt passwords, random session tokens, CSRF protection
- [x] **Single binary** — compiles to ~17MB, runs anywhere Go runs
- [x] **AI WAF** — IsolationForest anomaly detection, learns your traffic, blocks threats
- [ ] **OIDC/MFA** — SSO and multi-factor auth (coming)

## Architecture

```
                    Internet
                       |
               +-------+-------+
               |    Bastion    |
               |   :80 / :443 |
               +---+---+---+--+
                   |   |   |
          +--------+   |   +--------+
          |            |            |
  app.example.com  api.example.com  dash :9090
     localhost:3000   localhost:8080    (auth)
          |
    +-----+-----+
    |  WireGuard |  <-- encrypted tunnel from your laptop
    |  Tunnel    |
    +-----+-----+
          |
    localhost:3000
    (your dev machine)

    Request flow:
    1. TLS termination (auto Let's Encrypt)
    2. Rate limiter (per-IP, sliding window)
    3. IP blocklist check (SQLite)
    4. Subdomain routing
    5. Reverse proxy to upstream
    6. Request logged to SQLite
```

## Comparison

| | **Bastion** | Cloudflare | Pangolin | Caddy |
|---|---|---|---|---|
| Self-hosted | Yes | No | Yes | Yes |
| Auto-SSL | Yes | Yes | Yes | Yes |
| WireGuard tunnels | Built-in | Paid (Tunnel) | Yes | No |
| Dashboard | Built-in | Yes | Yes | No |
| Rate limiting | Built-in | Paid tier | No | Plugin |
| IP blocking | Built-in | Paid tier | No | No |
| Request logging | SQLite | Analytics ($) | No | JSON logs |
| AI WAF | **Built-in** | Enterprise | No | No |
| Config format | JSON (1 file) | Web UI | YAML | Caddyfile |
| Binary size | ~17MB | N/A | ~30MB | ~40MB |
| Monthly cost | **$0** | $0-$200+ | $0 | $0 |
| Lines of code | ~1,200 | Proprietary | ~50K | ~100K |

## Configuration

`bastion.json` — the only config file:

```json
{
  "domain": "example.com",
  "email": "you@example.com",
  "services": [
    {
      "name": "app",
      "subdomain": "app",
      "target": "http://localhost:3000"
    },
    {
      "name": "api",
      "subdomain": "api",
      "target": "http://localhost:8080",
      "health": "http://localhost:8080/healthz"
    }
  ],
  "dashboard": {
    "port": 9090,
    "password": "change-this-immediately"
  },
  "tls": {
    "enabled": true,
    "cert_dir": ".bastion-certs"
  }
}
```

| Field | Description |
|---|---|
| `domain` | Your root domain. Services are `{subdomain}.{domain}`. |
| `email` | Used for Let's Encrypt registration. |
| `services[].name` | Display name in the dashboard. |
| `services[].subdomain` | Subdomain to route. `app` = `app.example.com`. |
| `services[].target` | Upstream URL to proxy to. |
| `services[].health` | Optional health check URL. Falls back to `target`. |
| `dashboard.port` | Port for the admin dashboard. Default `9090`. |
| `dashboard.password` | Login password. Hashed with bcrypt at startup. |
| `tls.enabled` | Enable auto-SSL. Requires ports 80+443 open. |
| `tls.cert_dir` | Directory to cache Let's Encrypt certificates. |

## WireGuard Tunneling

Expose a local service to the internet through an encrypted WireGuard tunnel. No port forwarding, no ngrok, no Cloudflare Tunnel bills.

**On your server** (where Bastion runs):

Bastion's WireGuard server starts automatically on the tunnel interface.

**On your laptop/dev machine:**

```bash
# Build the client
cd tunnel && go build -o bastion-client .

# Connect — forwards your local port through the tunnel
./bastion-client -server your-server-ip:51820 -local localhost:3000
```

Traffic flow: `app.example.com` -> Bastion (TLS) -> WireGuard tunnel -> `localhost:3000` on your machine.

The tunnel uses userspace WireGuard — no kernel module required, works on macOS/Linux/Windows.

## AI WAF

Bastion's WAF uses an IsolationForest anomaly detector — the same ML technique used in production fraud detection:

1. **Learning mode**: Collects first 1,000 requests to build a traffic baseline
2. **Active mode**: Scores every request (0.0 = normal, 1.0 = anomalous), blocks above threshold (0.65)
3. **Rule engine**: Instant blocking of SQL injection, XSS, path traversal patterns (no training needed)
4. **Dashboard**: Real-time WAF events, scores, blocked threats

API endpoints:
- `GET /api/waf/status` — mode, training progress, stats
- `GET /api/waf/events` — recent WAF decisions with scores
- `POST /api/waf/retrain` — force model retraining
- `GET /api/waf/score?url=...` — test a URL against the model

The forest is trained from scratch in pure Go — no Python, no external ML libraries, no cloud APIs.

## Dashboard

The dashboard runs on `:{port}` (default 9090) and is protected by password auth with bcrypt-hashed passwords and session tokens.

What you get:
- **Stats cards** — total requests, uptime, rate-limited IPs, blocked IPs
- **Service health** — live status with latency for each upstream
- **Requests per minute** — bar chart of the last 60 minutes
- **Top IPs** — most active IPs with one-click blocking
- **Blocked IPs** — manage the blocklist
- **Request log** — last 20 requests with method, path, status, timing

Dark theme. Auto-refreshes every 5 seconds. No JavaScript framework — vanilla JS, inline CSS, zero build step.

## Security

- Passwords hashed with **bcrypt** (cost 10) — never stored in plaintext
- Sessions use **crypto/rand** tokens (256-bit), expire after 24 hours
- **CSRF protection** on login form with per-request tokens
- Cookies: `HttpOnly`, `Secure` (when TLS enabled), `SameSite=Strict`, `Path=/`
- **Rate limiting** at 100 req/min per IP with sliding window
- **IP blocklist** persisted in SQLite
- TLS 1.2+ enforced, HTTP automatically redirects to HTTPS

## Install

**From source:**

```bash
git clone https://github.com/Miles0sage/bastion.git
cd bastion
go build -o bastion .
sudo mv bastion /usr/local/bin/
```

**As a systemd service:**

```ini
[Unit]
Description=Bastion Edge Platform
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/bastion
ExecStart=/usr/local/bin/bastion up
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Requirements

- Go 1.21+ (build only)
- Ports 80 + 443 open (for auto-SSL)
- A domain with DNS A records pointing to your server
- That's it

## Contributing

1. Fork it
2. Create your branch (`git checkout -b feat/thing`)
3. Commit (`git commit -m 'feat: add thing'`)
4. Push (`git push origin feat/thing`)
5. Open a PR

Keep it simple. Bastion is intentionally small. If a feature needs a config file of its own, it probably doesn't belong here.

## License

MIT License. See [LICENSE](LICENSE).

---

Built by [Miles](https://github.com/Miles0sage). One binary to rule them all.
