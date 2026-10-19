import discord

GUILD_ID = 1542515767126401075
VERIFIED_ROLE_ID = 1542521194081947779
STAFF_ROLE_IDS = (
    1542519008224608347,  # Admin
    1542519012892745823,  # Moderator
    1542519017909002343,  # Helper
)
TICKETS_CATEGORY_NAME = "TICKETS"


def _is_verified(member: discord.Member) -> bool:
    return any(role.id == VERIFIED_ROLE_ID for role in getattr(member, "roles", []))


def _deny_embed() -> discord.Embed:
    return discord.Embed(
        description="You have to verify in order to do this!",
        color=0xE74C3C,
    )


class CreateTicketButton(discord.ui.Button):
    def __init__(self):
        super().__init__(
            label="Create Ticket",
            emoji="🎫",
            style=discord.ButtonStyle.primary,
            custom_id="insomnia:create_ticket",
        )

    async def callback(self, interaction: discord.Interaction):
        guild = interaction.guild
        member = interaction.user
        if guild is None or guild.id != GUILD_ID or not isinstance(member, discord.Member):
            await interaction.response.send_message(embed=_deny_embed(), ephemeral=True)
            return

        if not _is_verified(member):
            await interaction.response.send_message(embed=_deny_embed(), ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)
        try:
            channel = await _open_ticket(guild, member)
        except Exception as err:
            await interaction.followup.send(
                f"Could not open a ticket: {err}",
                ephemeral=True,
            )
            return

        await interaction.followup.send(
            f"Ticket opened: {channel.mention}",
            ephemeral=True,
        )


async def _tickets_category(guild: discord.Guild) -> discord.CategoryChannel:
    for ch in guild.categories:
        if ch.name.upper() == TICKETS_CATEGORY_NAME:
            return ch

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
    }
    verified = guild.get_role(VERIFIED_ROLE_ID)
    if verified:
        overwrites[verified] = discord.PermissionOverwrite(view_channel=False)
    for role_id in STAFF_ROLE_IDS:
        role = guild.get_role(role_id)
        if role:
            overwrites[role] = discord.PermissionOverwrite(
                view_channel=True,
                send_messages=True,
                read_message_history=True,
                manage_messages=True,
            )
    return await guild.create_category(TICKETS_CATEGORY_NAME, overwrites=overwrites)


async def _open_ticket(guild: discord.Guild, member: discord.Member) -> discord.TextChannel:
    category = await _tickets_category(guild)
    marker = f"user:{member.id}"
    for ch in category.text_channels:
        if (ch.topic or "") == marker:
            return ch

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        member: discord.PermissionOverwrite(
            view_channel=True,
            send_messages=True,
            read_message_history=True,
            attach_files=True,
            embed_links=True,
        ),
    }
    for role_id in STAFF_ROLE_IDS:
        role = guild.get_role(role_id)
        if role:
            overwrites[role] = discord.PermissionOverwrite(
                view_channel=True,
                send_messages=True,
                read_message_history=True,
                manage_messages=True,
                attach_files=True,
            )

    name = f"ticket-{member.name}".lower()[:90]
    channel = await guild.create_text_channel(
        name,
        category=category,
        topic=marker,
        overwrites=overwrites,
        reason=f"ticket for {member}",
    )
    staff_mentions = " ".join(f"<@&{rid}>" for rid in STAFF_ROLE_IDS if guild.get_role(rid))
    await channel.send(
        content=f"{member.mention} {staff_mentions}".strip(),
        embed=discord.Embed(
            title="Ticket",
            description="Tell us your IGN, Java or Bedrock, and what you need help with. Staff will be here shortly.",
            color=0x5865F2,
        ).set_footer(text="Insomnia · SMP & PvP"),
    )
    return channel


class CreateTicketView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        self.add_item(CreateTicketButton())
