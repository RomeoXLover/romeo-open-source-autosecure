# Feature Inventory — Romeo Open Source Autosecure

**Repository**: [RomeoXLover/romeo-open-source-autosecure](https://github.com/RomeoXLover/romeo-open-source-autosecure)  
**Maintainer**: Romeo  

---

## 1. Discord Bot Subsystem

- **Bot Initialization & Event Loop (`bot.py`)**:
  - Discord bot client lifecycle, dynamic cog loading, intents management.
  - Auto-reconnect, custom activity status cycling, database initialization on ready.
- **Administration & Moderation (`cogs/admin.py`)**:
  - Guild whitelisting, role permissions, emergency lockdown, debug dumps.
  - Configuration hot-reload, cache flushing.
- **Authentication & OAuth Flows (`cogs/auth.py`)**:
  - Microsoft OAuth link generation, token exchange, session persistence.
  - Device code flow and web-based redirect callbacks.
- **Autobuy & Automated Processing (`cogs/autobuy.py`)**:
  - Queue monitoring, automated balance checking, batch purchase execution.
  - Notification embeds for successful purchases and hold checks.
- **General Commands & Information (`cogs/general.py`)**:
  - Help menu, ping/latency, system uptime, version info, terms of service.
- **Account Management (`cogs/management.py`)**:
  - Account search, tag assignment, credential view, export routines.
  - Manual triggers for re-securing, alias changes, and 2FA resets.
- **Telemetry & Statistics (`cogs/stats.py`)**:
  - Real-time secured count, hit rates, financial volume, Minecraft tier distribution.

---

## 2. Interactive UI & Components

- **Buttons (`ui/buttons/`)**:
  - `account_details.py`: Interactive account inspector view.
  - `autobuy.py`: Quick purchase toggles and balance loaders.
  - `create_ticket.py`: Automated support ticket creation.
  - `embed_buttons.py`: Pagination, link triggers, and refresh buttons.
  - `extra_info.py`: Deep profile lookup and metadata drawer.
  - `link_account.py`: Account connection workflow trigger.
  - `mail_inbox.py`: Real-time mail inbox fetcher.
  - `missing_email.py`: Missing email recovery handler.
  - `submit_code.py`: One-time password submission modal trigger.
  - `totp_refresh.py`: Dynamic TOTP code regenerator.
- **Modals (`ui/modals/`)**:
  - `autobuy.py`: Configuration modal for autobuy parameters.
  - `bulk_utils.py`: Batch input processor and validator.
  - `dm.py`: Direct message dispatcher.
  - `modal_one.py`, `modal_two.py`: Multi-step credential entry modals.
  - `recovery_code.py`, `recovery_code_bulk.py`: Single and bulk recovery code inputs.
  - `recovery_secret.py`, `recovery_secret_bulk.py`: Secret key entry and validation.

---

## 3. Securing Engine & Protocols

- **Pipeline Orchestrator (`securing/secure.py`)**:
  - End-to-end securing workflow: password update, alias rotation, 2FA setup, device removal.
- **Recovery Pipeline (`securing/recovery_secure.py`)**:
  - Recovery code validation, 25-digit code application, security proof reset.
- **Account Filtering & Bans (`securing/account_filters.py`, `securing/ban_checks.py`)**:
  - Heuristic checks for locked/suspended accounts, server bans, hypixel bans.
- **Autobuy Hold & Safeguards (`securing/autobuy_hold_check.py`)**:
  - Pre-purchase security holding check, fraud mitigation.
- **Embed Generators (`securing/build_embeds.py`)**:
  - Rich Discord embed formatters for secured accounts, hit alerts, and errors.
- **Microsoft Authentication Subsystem (`securing/auth/`)**:
  - `initial_session.py`: Session bootstrapping and cookie jar initialization.
  - `account_status.py`: Live MSA status and lock detection.
  - `check_auth.py`, `check_locked.py`: Authentication integrity verification.
  - `get_msaauth.py`, `handle_redirects.py`: Redirect follow and OAuth token extraction.
  - `send_auth.py`, `polish_host.py`: Request header normalization and proxy tunneling.
- **Security Primitives (`securing/utils/security/`)**:
  - `add_authenticator.py`: App-based authenticator (TOTP) pairing.
  - `change_password.py`, `force_password.py`: Robust password resetting.
  - `change_primary_alias.py`, `delete_aliases.py`: Email alias switching and pruning.
  - `get_recovery_code.py`: 25-digit emergency recovery code extraction.
  - `leave_family.py`: Microsoft Family Safety detachment.
  - `logout_all.py`: Universal session invalidation.
  - `remove_2fa.py`, `remove_proof.py`: Legacy proof removal.
  - `remove_devices.py`, `remove_fed_cred.py`, `remove_services.py`, `remove_zyger.py`: Access hygiene.
- **Identity & Graph Lookups (`securing/utils/ogi/`)**:
  - `get_devices.py`, `get_family.py`, `get_owner_info.py`, `get_cards.py`, `get_contacts.py`, `get_subscriptions.py`.
- **Session & Token Utilities (`securing/utils/cookies/`)**:
  - `get_cookies.py`, `get_msadelegate.py`, `get_t.py`, `get_amrp.py`, `get_livedata.py`, `ensure_amc_jwt.py`, `get_amc.py`.

---

## 4. Minecraft & Gaming Integrations

- **Profile & Cosmetics (`minecraft/`)**:
  - `get_profile.py`: Minecraft UUID, username, skin geometry.
  - `get_capes.py`: Optifine, Mojang, Minecon, Badlion, Lunar cape checks.
  - `get_hypixel.py`: Hypixel API stats (rank, bedwars, skywars, level).
  - `get_donut.py`: DonutSMP stats and inventory scan.
  - `get_ssid.py`: Minecraft session token (SSID) retrieval from Xbox Live token.
  - `get_namechange.py`: Name change eligibility and past names history.
  - `get_xbl.py`: Xbox Live authentication chain (user hash, XSTS token).
  - `check_server_ban.py`: Automated server connection test via `check.js`.

---

## 5. Payments, Subscriptions & Mail

- **Crypto Gateway (`payments/crypto.py`)**:
  - Bitcoin, Ethereum, Solana, and USDT address generation and transaction confirmations.
- **Sellpass Integration (`payments/sellpass.py`)**:
  - Webhook processing for automated digital deliveries.
- **Custom Mail Server (`mail/client.py`)**:
  - IMAP/POP3/SMTP client for temporary security domains and code extraction.

---

## 6. Web Application & Dashboard (Phase 7 — Built at End)

- **FastAPI Backend (`web/`)**:
  - `app.py`: FastAPI server configuration, CORS, middleware, static asset mounting.
  - `routers/accounts.py`: Account listing, filtering, detail, deletion endpoints.
  - `routers/auth.py`: Web dashboard authentication and session management.
  - `routers/bot.py`: Live bot control, guild stats, reload triggers.
  - `routers/commands.py`: Command execution and registry.
  - `routers/emails.py`: Email domain manager and inbox fetcher.
  - `routers/secure.py`: Web-triggered securing pipelines.
  - `routers/shares.py`: Public/private shareable account links.
  - `routers/stats.py`: Aggregate metrics and historical charts.
- **Frontend SPA (`web/src/`)**:
  - TanStack Router with Vite and Tailwind CSS.
  - High-end 3D prismatic glassmorphism aesthetic with obsidian dark mode, aurora backgrounds, and iridescent gradients.
  - Real-time data tables, interactive filter drawers, search bars, and live logs.
