"""Owner-only command to remove autobuy credits (balance may go negative)."""

from datetime import datetime
import json
import logging

from discord.ext import commands
import discord

from database.database import DBConnection

bot_config = json.load(open("config/bot.json", "r"))
name = bot_config["enabled_commands"]["aliases"]["removecredit"]
logger = logging.getLogger("bot")


class RemoveCredit(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @discord.slash_command(
        name=name,
        description="(Owner) Remove autobuy credits from a user (can go negative)",
    )
    async def removecredit(
        self,
        ctx: discord.ApplicationContext,
        user: discord.Option(discord.Member, "User to remove credits from"),
        amount: discord.Option(
            float,
            "USD amount to remove",
            min_value=0.01,
            max_value=100000,
        ),
        note: discord.Option(
            str,
            "Optional note (stored with the debit)",
            required=False,
            max_length=180,
        ) = None,
    ):
        if ctx.author.id not in self.bot.admins:
            await ctx.respond(
                "You do not have permission to use this command.",
                ephemeral=True,
            )
            return

        amount = round(float(amount), 2)
        if amount <= 0:
            await ctx.respond("Amount must be greater than 0.", ephemeral=True)
            return

        await ctx.defer(ephemeral=True)

        try:
            with DBConnection() as db:
                before = db.autobuy_balances(user.id)
                debit_id = db.autobuy_remove_manual_credit(
                    user.id,
                    amount,
                    note=note,
                    removed_by=ctx.author.id,
                )
                bals = db.autobuy_balances(user.id)
        except Exception as exc:
            logger.exception("removecredit failed for %s amount=%s", user.id, amount)
            await ctx.followup.send(
                f"Failed to remove credits.\n```{exc}```",
                ephemeral=True,
            )
            return

        embed = discord.Embed(
            title="Credits removed",
            description=(
                f"Removed **${amount:.2f}** from {user.mention} "
                f"(`{user.id}`).\n"
                f"**Debit ID:** `{debit_id}`\n"
                f"**Note:** {note or '—'}\n\n"
                f"**Before:** Available **${before['available_usd']:.2f}**\n"
                f"**After**\n"
                f"Available: **${bals['available_usd']:.2f}**\n"
                f"Pending: **${bals['pending_usd']:.2f}**"
            ),
            color=0xED4245,
            timestamp=datetime.utcnow(),
        )
        embed.set_footer(text=f"Removed by {ctx.author} ({ctx.author.id})")
        await ctx.followup.send(embed=embed, ephemeral=True)

        try:
            dm = discord.Embed(
                title="Autobuy credits removed",
                description=(
                    f"An owner removed **${amount:.2f}** from your withdrawable balance.\n"
                    + (f"**Note:** {note}\n" if note else "")
                    + f"\nAvailable now: **${bals['available_usd']:.2f}**"
                ),
                color=0xED4245,
            )
            await user.send(embed=dm)
        except Exception:
            logger.info("Could not DM credit debit recipient %s", user.id)


def setup(bot: commands.Bot) -> None:
    bot.add_cog(RemoveCredit(bot))
