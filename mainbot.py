#!/usr/bin/env python3
"""Main bot entrypoint — reads token from extracted/, wires up private mail handler.

Usage:
    python mainbot.py

Expects extracted/token.json with discord bot_token + optional imap config.
The mail handler in extracted/mail/ detects OTPs and forwards to the secure flow.
Designed for PM2: starts bot + mail poller as one process, logs to logs/romeo.log.
"""
import os
import sys
import json
import asyncio
import logging
import logging.handlers
import signal

from discord.ext import commands
import discord

EXTRACTED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extracted")


def setup_romeo_log() -> logging.Logger:
    """Configure logging — file handler to logs/romeo.log + stdout."""
    os.makedirs("logs", exist_ok=True)

    rom = logging.getLogger("romeo")
    rom.setLevel(logging.INFO)
    rom.handlers.clear()

    fh = logging.FileHandler("logs/romeo.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    rom.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(logging.Formatter("%(levelname)s | %(message)s"))
    rom.addHandler(sh)

    for noisy in ("discord", "discord.http", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return rom


def load_extracted_config() -> dict:
    """Load token + mail config from extracted/token.json."""
    path = os.path.join(EXTRACTED, "token.json")
    if not os.path.exists(path):
        rom = logging.getLogger("romeo")
        rom.error("extracted/token.json not found — bot cannot start")
        print("[x] extracted/token.json missing — create it with your bot_token")
        sys.exit(1)

    with open(path, "r") as f:
        return json.load(f)


class RomeoClient(commands.Bot):
    """Discord bot — loads cogs from commands/ + extracted hooks."""

    def __init__(self, token: str, intents: discord.Intents):
        super().__init__(
            command_prefix="!",
            intents=intents,
            allowed_mentions=discord.AllowedMentions(roles=False, everyone=False, users=True),
        )
        self.romeo_token = token
        self.otp_buffer = asyncio.Queue()

    async def on_ready(self):
        rom = logging.getLogger("romeo")
        rom.info("bot ready as %s", self.user)
        print(f"[+] romeo-bot online: {self.user}")

    async def on_disconnect(self):
        rom = logging.getLogger("romeo")
        rom.warning("discord disconnected")


async def _mail_watcher(bot: RomeoClient, config: dict):
    """Background task: detect OTPs via SMTP or Cloudflare Worker, push to bot.otp_buffer."""
    from extracted.mail.handler import start_mail_handler

    async def on_otp(code: str, subject: str, hit: dict):
        await bot.otp_buffer.put({
            "code": code,
            "subject": subject,
            "type": hit.get("type", "unknown"),
            "source": hit.get("source", "unknown"),
            "ts": __import__("time").time(),
        })

    task = await start_mail_handler(config, on_otp)
    if task:
        rom.info("mail handler running")
    else:
        rom.warning("mail handler not configured")


async def main():
    global rom

    rom = setup_romeo_log()
    rom.info("boot — romeo-bot starting")

    cfg = load_extracted_config()
    token = cfg["bot_token"]
    if not token:
        rom.error("bot_token empty in extracted/token.json")
        sys.exit(1)

    intents = discord.Intents.all()
    bot = RomeoClient(token, intents)

    # Load commands
    cmds_path = os.path.join(os.path.dirname(__file__), "commands")
    for entry in sorted(os.listdir(cmds_path)):
        if entry.endswith(".py") and not entry.startswith("_"):
            mod = entry[:-3]
            try:
                bot.load_extension(f"commands.{mod}")
                rom.debug("loaded cog: %s", mod)
            except Exception as exc:
                rom.warning("cog load failed %s: %s", mod, exc)

    # Start mail watcher
    mail_task = asyncio.create_task(_mail_watcher(bot, cfg))

    # Graceful shutdown
    def _sigint():
        rom.info("SIGINT — shutting down")
        mail_task.cancel()
        asyncio.create_task(bot.close())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_event_loop().add_signal_handler(sig, _sigint)
        except NotImplementedError:
            pass

    try:
        await bot.start(token)
    except KeyboardInterrupt:
        pass
    finally:
        if not mail_task.done():
            mail_task.cancel()
        await bot.close()


rom = logging.getLogger("romeo") if __name__ == "__main__" else logging.getLogger("romeo")
rom = setup_romeo_log() if __name__ == "__main__" else rom

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        rom.info("shutting down")
        sys.exit(0)
