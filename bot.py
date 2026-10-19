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
from storage.romeo_db import RomeoDB
from inbox.postal_service import PostalServer

app_config = json.load(open("config/config.json", "r"))
runtime_settings = json.load(open("config/bot.json", "r"))


class RomeoClient(commands.Bot):
    def __init__(self):
        super().__init__(
            command_prefix="!",
            case_insensitive=True,
            intents=discord.Intents.all(),
            allowed_mentions=discord.AllowedMentions(roles=False, everyone=False, users=True)
        )
        self.logger = logging.getLogger("romeo")
        self.operators = [int(x) for x in app_config["owners"]]

        self.status_map = {
            "online": discord.Status.online,
            "idle": discord.Status.idle,
            "dnd": discord.Status.dnd,
            "invisible": discord.Status.invisible,
        }

        self.activity_types = {
            "playing": discord.ActivityType.playing,
            "streaming": discord.ActivityType.streaming,
            "listening": discord.ActivityType.listening,
            "watching": discord.ActivityType.watching,
            "competing": discord.ActivityType.competing,
        }

    async def create_fake_command(self, name: str, description: str, response: str):
        async def handler(ctx: discord.ApplicationContext):
            await ctx.response.send_message(response, ephemeral=True)

        handler.__name__ = name
        fake_cmd = discord.SlashCommand(handler, name=name, description=description)
        self.add_application_command(fake_cmd)

    def compute_signature(self) -> str:
        entries = []
        for cmd in self.pending_application_commands:
            try:
                entries.append(cmd.to_dict())
            except Exception:
                entries.append({"name": getattr(cmd, "name", "?")})

        raw = json.dumps(entries, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    async def on_ready(self):
        self.add_view(SessionLinkView())
        self.add_view(ShopView())
        self.add_view(TicketLauncherView())
        self._ready = True

        pres = runtime_settings["presence"]
        kind = self.activity_types[pres["activity_type"]]
        act = discord.Activity(type=kind, name=pres["activity_text"])

        await self.change_presence(
            status=self.status_map[pres["status"]],
            activity=act,
        )

        guild_ids = [g.id for g in self.guilds]
        await self.sync_commands(guild_ids=guild_ids)
        self.logger.info(f"Commands synced to {len(guild_ids)} guild(s)")

    @staticmethod
    def setup_logging() -> None:
        root = logging.getLogger()
        root.setLevel(logging.INFO)

        fh = logging.FileHandler("logs/romeo.log", mode="a")
        fh.setLevel(logging.INFO)
        root.addHandler(fh)

        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("%(levelname)s | %(asctime)s | %(name)s | %(message)s"))

        bot_log = logging.getLogger("romeo")
        bot_log.addHandler(ch)
        bot_log.propagate = False

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
            print(cmd)
            await self.create_fake_command(
                name=active["fake"][cmd]["title"],
                description=active["fake"][cmd]["description"],
                response=active["fake"][cmd]["response"],
            )

        with RomeoDB() as db:
            db.setup_tables()

asyncio.set_event_loop(asyncio.new_event_loop())
romeo = RomeoClient()

async def main():
    async with romeo:
        romeo.remove_command("help")
        romeo.setup_logging()
        PostalServer.start()

        await romeo.load_extensions()
        await romeo.start(app_config["tokens"]["bot_token"])

asyncio.run(main())
