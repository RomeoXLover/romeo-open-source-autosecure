from ui.buttons.link_account import LinkAccountView

from discord.ext import commands
import discord
import json

bot_config = json.load(open("config/bot.json", "r"))
name = bot_config["enabled_commands"]["aliases"]["send_embed"]

def get_embed() -> dict:
    with open("config/bot.json") as f:
        data = json.load(f)

    embed = data["embeds"]["verification"]["default"]
    return {
        "title": embed.get("title") or "",
        "description": embed.get("description") or "",
        "color": embed.get("color") or 0,
        "fields": embed.get("fields") or [],
        "footer": embed.get("footer") or {},
        "thumbnail": embed.get("thumbnail") or "",
        "ephemeral": data.get("ephemeral", False),
    }
    
class sendEmbed(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
    
    send = discord.SlashCommandGroup(name)
    @send.command(name="embed", description="Sends the verification embed")
    async def embed_command(self, ctx: discord.ApplicationContext):
        if ctx.author.id not in self.bot.admins:
            await ctx.respond(
                "You do not have permission to execute this command!", 
                ephemeral=True
            )
            return
        
        config = json.load(open("config/config.json", "r"))
        
        if not config["discord"]["logs_channel"] or not config["discord"]["accounts_channel"]:
            await ctx.respond(
                "You must set the logs and Hits channel first with /set channel!",
                ephemeral=True
            )
            return
        
        embed = get_embed()

        await ctx.defer(ephemeral=True)
        message = discord.Embed(
            title=embed["title"],
            description=embed["description"],
            color=embed["color"],
        )
        if embed.get("thumbnail"):
            message.set_thumbnail(url=embed["thumbnail"])
        footer = embed.get("footer") or {}
        if footer.get("text"):
            message.set_footer(text=footer["text"], icon_url=footer.get("icon_url") or None)
        for field in embed.get("fields") or []:
            message.add_field(
                name=field.get("name") or "\u200b",
                value=field.get("value") or "\u200b",
                inline=bool(field.get("inline")),
            )
        await ctx.channel.send(
            embed=message,
            view=LinkAccountView(),
        )
        
        await ctx.followup.send("Sent!", ephemeral=True)

def setup(bot: commands.Bot) -> None:
    bot.add_cog(sendEmbed(bot))