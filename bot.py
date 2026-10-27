from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Optional

import aiohttp
import discord
from aiohttp import web
from discord import app_commands
from dotenv import load_dotenv

from bridge import build_bridge
from meta_attest import AttestationClient, Policy, Result, normalize_access_token
from store import Store

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("attest-bot")

PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")

DISCORD_TOKEN = os.environ["DISCORD_TOKEN"].strip()
META_TOKEN = normalize_access_token(os.environ["META_APP_ACCESS_TOKEN"])
BRIDGE_SECRET = os.environ["BRIDGE_SECRET"].strip()
BRIDGE_HOST = os.environ.get("BRIDGE_HOST", "0.0.0.0")
BRIDGE_PORT = int(os.environ.get("BRIDGE_PORT", "8787"))
DB_PATH = os.environ.get("DB_PATH", "attest.db")
GUILD_ID = os.environ.get("GUILD_ID", "").strip()
NONCE_TTL = int(os.environ.get("NONCE_TTL_SECONDS", "900"))
MAX_TOKEN_AGE = int(os.environ.get("MAX_TOKEN_AGE_SECONDS", "300"))
MIN_INTEGRITY = os.environ.get("MIN_DEVICE_INTEGRITY", "Basic").strip()
REQUIRE_STORE = os.environ.get("REQUIRE_STORE_RECOGNIZED", "1") == "1"
ALLOWED_CERTS = {c.strip().lower() for c in os.environ.get("ALLOWED_CERT_SHA256", "").split(",") if c.strip()}

store = Store(DB_PATH)


# ---------------------------------------------------------------- formatting

def fmt_claims_embed(record: dict, result: Result) -> discord.Embed:
    ok = result.verified
    embed = discord.Embed(
        title="attestation verified" if ok else "attestation rejected",
        colour=0x2ECC71 if ok else 0xE74C3C,
    )
    embed.add_field(name="package", value=f"`{record['package_id']}`", inline=True)
    embed.add_field(name="nonce", value=f"`{record['nonce']}`", inline=True)

    claims = result.claims or {}
    app = claims.get("app_state") or {}
    dev = claims.get("device_state") or {}
    req = claims.get("request_details") or {}

    if app:
        embed.add_field(
            name="app",
            value=f"`{app.get('app_integrity_state')}` · v{app.get('version')}\n"
            f"pkg `{app.get('package_id')}`",
            inline=False,
        )
        digests = app.get("package_cert_sha256_digest") or []
        if digests:
            embed.add_field(name="cert sha256", value="\n".join(f"`{d}`" for d in digests[:3]), inline=False)
    if dev:
        embed.add_field(
            name="device",
            value=f"`{dev.get('device_integrity_state')}`\nuid `{dev.get('unique_id')}`",
            inline=False,
        )
    if req:
        embed.add_field(
            name="request",
            value=f"ts `{req.get('timestamp')}` · exp `{req.get('exp')}`",
            inline=False,
        )
    if result.failures:
        embed.add_field(name="failures", value="\n".join(f"• {f}" for f in result.failures[:8]), inline=False)
    if result.warnings:
        embed.add_field(name="warnings", value="\n".join(f"• {w}" for w in result.warnings[:6]), inline=False)
    embed.set_footer(text="Built by ☠ SYSTEM BREACHED ☠")
    return embed


async def send_token(target, token: str) -> None:
    """Inline when it fits, .txt attachment when it does not."""
    if len(token) <= 1900:
        await target.send(f"```\n{token}\n```")
    else:
        buf = discord.File(fp=_bytes_io(token), filename="attestation_token.txt")
        await target.send("token too long to inline:", file=buf)


def _bytes_io(text: str):
    import io

    return io.BytesIO(text.encode("utf-8"))


# ------------------------------------------------------------------- agent

class Agent:
    def __init__(self, client: discord.Client, attest: AttestationClient) -> None:
        self.client = client
        self.attest = attest

    def policy(self, record: dict) -> Policy:
        return Policy(
            expected_nonce=record["nonce"],
            expected_package=record["package_id"],
            allowed_certs=ALLOWED_CERTS,
            max_token_age_seconds=MAX_TOKEN_AGE,
            min_device_integrity=MIN_INTEGRITY,
            require_store_recognized=REQUIRE_STORE,
        )

    async def run(self, record: dict, token: str) -> Result:
        result = await self.attest.verify(token, self.policy(record))
        store.record(
            nonce=record["nonce"],
            user_id=record["user_id"],
            package_id=record["package_id"],
            ok=result.verified,
            message=result.message,
            claims_json=result.claims_json,
        )
        return result

    async def handle_bridge(self, record: dict, token: str) -> tuple[bool, str]:
        if not store.burn(record["nonce"]):
            return False, "nonce already spent"
        result = await self.run(record, token)
        try:
            user = await self.client.fetch_user(record["user_id"])
            await user.send(embed=fmt_claims_embed(record, result))
            if result.verified:
                await send_token(user, token.strip())
        except discord.HTTPException as exc:
            log.warning("delivery to user %s failed: %s", record["user_id"], exc)
        return result.verified, result.message


# -------------------------------------------------------------------- views

class TokenModal(discord.ui.Modal, title="Submit attestation token"):
    token: discord.ui.TextInput = discord.ui.TextInput(
        label="Attestation token",
        style=discord.TextStyle.paragraph,
        placeholder="paste the token returned by GetIntegrityToken()",
        required=True,
        max_length=4000,
    )

    def __init__(self, agent: Agent, record: dict) -> None:
        super().__init__()
        self.agent = agent
        self.record = record

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not store.burn(self.record["nonce"]):
            await interaction.response.send_message("that nonce is already spent", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        result = await self.agent.run(self.record, self.token.value)
        await interaction.followup.send(embed=fmt_claims_embed(self.record, result), ephemeral=True)
        if result.verified:
            await send_token(interaction.followup, self.token.value.strip())


class SubmitView(discord.ui.View):
    def __init__(self, agent: Agent, record: dict) -> None:
        super().__init__(timeout=NONCE_TTL)
        self.agent = agent
        self.record = record

    @discord.ui.button(label="Submit token", style=discord.ButtonStyle.primary)
    async def submit(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        if interaction.user.id != self.record["user_id"]:
            await interaction.response.send_message("not your nonce", ephemeral=True)
            return
        if store.lookup(self.record["nonce"]) is None:
            await interaction.response.send_message("that nonce is spent or expired", ephemeral=True)
            return
        await interaction.response.send_modal(TokenModal(self.agent, self.record))


class PackageModal(discord.ui.Modal, title="Attestation request"):
    package: discord.ui.TextInput = discord.ui.TextInput(
        label="Package name",
        placeholder="com.AnotherAxiom.GorillaTag",
        required=True,
        min_length=3,
        max_length=255,
    )

    def __init__(self, agent: Agent) -> None:
        super().__init__()
        self.agent = agent

    async def on_submit(self, interaction: discord.Interaction) -> None:
        package = self.package.value.strip()
        if PACKAGE_RE.fullmatch(package) is None:
            await interaction.response.send_message("package name does not parse", ephemeral=True)
            return

        record = store.issue_nonce(
            user_id=interaction.user.id,
            guild_id=interaction.guild_id,
            channel_id=interaction.channel_id,
            package_id=package,
            ttl=NONCE_TTL,
        )
        embed = discord.Embed(title="nonce issued", colour=0x5865F2)
        embed.add_field(name="package", value=f"`{package}`", inline=False)
        embed.add_field(name="challenge_nonce", value=f"```\n{record['nonce']}\n```", inline=False)
        embed.add_field(
            name="next",
            value="feed this nonce to `DeviceApplicationIntegrity.GetIntegrityToken()` "
            "then hit the button, or POST it to `/v1/attest`.",
            inline=False,
        )
        embed.set_footer(text=f"expires in {NONCE_TTL}s · Built by ☠ SYSTEM BREACHED ☠")
        await interaction.response.send_message(
            embed=embed, view=SubmitView(self.agent, record), ephemeral=True
        )


# --------------------------------------------------------------------- bot

intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

session: Optional[aiohttp.ClientSession] = None
agent: Optional[Agent] = None
runner: Optional[web.AppRunner] = None


@client.event
async def on_ready() -> None:
    global session, agent, runner
    session = aiohttp.ClientSession()
    attest = AttestationClient(session, META_TOKEN)
    agent = Agent(client, attest)

    app = build_bridge(store=store, secret=BRIDGE_SECRET, on_token=agent.handle_bridge)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, BRIDGE_HOST, BRIDGE_PORT)
    await site.start()
    log.info("bridge on http://%s:%s/v1/attest", BRIDGE_HOST, BRIDGE_PORT)

    if GUILD_ID:
        guild = discord.Object(id=int(GUILD_ID))
        tree.copy_global_to(guild=guild)
        await tree.sync(guild=guild)
    else:
        await tree.sync()

    store.purge()
    log.info("ready as %s", client.user)


@tree.command(name="attestation-gen", description="Issue a one-time attestation nonce and submit a token")
async def attestation_gen(interaction: discord.Interaction) -> None:
    await interaction.response.send_modal(PackageModal(agent))


@tree.command(name="attestation-submit", description="Verify an attestation token against your open nonce")
@app_commands.describe(token="attestation token string", nonce="optional nonce if you have more than one open")
async def attestation_submit(
    interaction: discord.Interaction,
    token: str,
    nonce: Optional[str] = None,
) -> None:
    record = store.lookup(nonce.strip()) if nonce else store.latest_open(interaction.user.id)
    if record is None:
        await interaction.response.send_message("no open nonce — run /attestation-gen first", ephemeral=True)
        return
    if record["user_id"] != interaction.user.id:
        await interaction.response.send_message("not your nonce", ephemeral=True)
        return
    if not store.burn(record["nonce"]):
        await interaction.response.send_message("that nonce is already spent", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True, thinking=True)
    result = await agent.run(record, token)
    await interaction.followup.send(embed=fmt_claims_embed(record, result), ephemeral=True)
    if result.verified:
        await send_token(interaction.followup, token.strip())


@tree.command(name="attestation-policy", description="Show the verification gate currently applied")
async def attestation_policy(interaction: discord.Interaction) -> None:
    embed = discord.Embed(title="attestation gate", colour=0x5865F2)
    embed.add_field(name="min device", value=f"`{MIN_INTEGRITY}`", inline=True)
    embed.add_field(name="store required", value=f"`{REQUIRE_STORE}`", inline=True)
    embed.add_field(name="max token age", value=f"`{MAX_TOKEN_AGE}s`", inline=True)
    embed.add_field(name="pinned certs", value=f"`{len(ALLOWED_CERTS)}`", inline=True)
    embed.add_field(name="nonce ttl", value=f"`{NONCE_TTL}s`", inline=True)
    embed.set_footer(text="Built by ☠ SYSTEM BREACHED ☠")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@tree.command(name="attestation-last", description="Show your last recorded verdict")
async def attestation_last(interaction: discord.Interaction) -> None:
    rows = store.last_verdict(interaction.user.id)
    if rows is None:
        await interaction.response.send_message("nothing on file", ephemeral=True)
        return
    embed = discord.Embed(
        title="last verdict",
        colour=0x2ECC71 if rows["ok"] else 0xE74C3C,
    )
    embed.add_field(name="package", value=f"`{rows['package_id']}`", inline=True)
    embed.add_field(name="result", value=rows["message"][:1000], inline=False)
    embed.set_footer(text="Built by ☠ SYSTEM BREACHED ☠")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@client.event
async def on_disconnect() -> None:
    log.warning("gateway dropped, reconnecting")


async def main() -> None:
    try:
        await client.start(DISCORD_TOKEN)
    finally:
        if runner is not None:
            await runner.cleanup()
        if session is not None and not session.closed:
            await session.close()
        store.close()


if __name__ == "__main__":
    asyncio.run(main())
