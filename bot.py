from discord.ext import commands
import hashlib
import logging
import discord
import asyncio
import json
import sys
import os

from views.buttons.session_link import SessionLinkView
from views.buttons.shop_panel import ShopView
from views.buttons.ticket_launcher import TicketLauncherView
from storage.solis_db import SolisDB
from inbox.postal_service import PostalServer

app_config = json.load(open("config/bot_settings.json", "r"))
runtime_settings = json.load(open("config/runtime.json", "r"))


class NexusClient(commands.Bot):
    def __init__(self):
        super().__init__(
            command_prefix="!",
            case_insensitive=True,
            intents=discord.Intents.all(),
            allowed_mentions=discord.AllowedMentions(roles=False, everyone=False, users=True)
        )
        self.logger = logging.getLogger("nexus")
        self.operators = [int(x) for x in app_config["owners"]]

        self.presence_map = {
            "online": discord.Status.online,
            "idle": discord.Status.idle,
            "dnd": discord.Status.dnd,
            "invisible": discord.Status.invisible,
        }
        self.activity_kinds = {
            "playing": discord.ActivityType.playing,
            "streaming": discord.ActivityType.streaming,
            "listening": discord.ActivityType.listening,
            "watching": discord.ActivityType.watching,
            "competing": discord.ActivityType.competing,
        }

    async def fabricate_command(self, label: str, blurb: str, reply: str):
        async def handler(ctx: discord.ApplicationContext):
            await ctx.response.send_message(reply, ephemeral=True)

        handler.__name__ = label
        fake_cmd = discord.SlashCommand(handler, name=label, description=blurb)
        self.add_application_command(fake_cmd)

    def signature_hash(self) -> str:
        payload = []
        for cmd in self.pending_application_commands:
            try:
                payload.append(cmd.to_dict())
            except Exception:
                payload.append({"name": getattr(cmd, "name", "?")})
        blob = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    async def on_ready(self):
        self.add_view(SessionLinkView())
        self.add_view(ShopView())
        self.add_view(TicketLauncherView())
        self._bootstrap_complete = True

        pres = runtime_settings["presence"]
        kind = self.activity_kinds[pres["activity_type"]]
        act = discord.Activity(type=kind, name=pres["activity_text"])

        await self.change_presence(
            status=self.presence_map[pres["status"]],
            activity=act,
        )

        gids = [g.id for g in self.guilds]
        await self.sync_commands(guild_ids=gids)
        self.logger.info(f"Commands synced to {len(gids)} guild(s)")

    @staticmethod
    def boot_logging() -> None:
        root = logging.getLogger()
        root.setLevel(logging.INFO)

        fh = logging.FileHandler("logs/nexus.log", mode="a")
        fh.setLevel(logging.INFO)
        root.addHandler(fh)

        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("%(levelname)s | %(asctime)s | %(name)s | %(message)s"))

        nexus_log = logging.getLogger("nexus")
        nexus_log.addHandler(ch)
        nexus_log.propagate = False

        for noisy in ("discord", "discord.http", "discord.gateway", "httpx", "mail.log", "mail.server"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    async def load_extensions(self, path="./commands") -> None:
        active = runtime_settings["enabled_commands"]

        for entry in os.listdir(path):
            if entry.endswith(".py"):
                module = entry[:-3]
                if active["real"][module]:
                    self.load_extension(
                        f"{path[2:].replace('/', '.')}.{module}"
                    )
                    self.logger.info(f"Loaded: {module}")
            elif not (
                entry in ["__pycache__", "utils", "buttons", "modals"]
                or entry.endswith(("pyc", "txt"))
            ):
                await self.load_extensions(f"{path}/{entry}")

        for cmd in active["fake"].keys():
            await self.fabricate_command(
                label=active["fake"][cmd]["title"],
                blurb=active["fake"][cmd]["description"],
                reply=active["fake"][cmd]["response"],
            )

        with SolisDB() as db:
            db.initialize_tables()

asyncio.set_event_loop(asyncio.new_event_loop())
nexus = NexusClient()

async def main():
    async with nexus:
        nexus.remove_command("help")
        nexus.boot_logging()
        PostalServer.start()

        await nexus.load_extensions()
        await nexus.start(app_config["tokens"]["bot_token"])

asyncio.run(main())
