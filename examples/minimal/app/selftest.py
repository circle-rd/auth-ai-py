import asyncio
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Final

from auth_ai import AiClient, AuthAiError, AuthClient, GrantManager, UserAi, format_euros
from auth_ai.server import BearerVerifier, MachineApi
from auth_ai.web import Session

from .payloads import ChatAnswer, EmbeddingAnswer, parse_answer

POLL_INTERVAL_SECONDS: Final = 2.0
POLL_TIMEOUT_SECONDS: Final = 20.0
CHAT_MODEL_PATTERN: Final = re.compile(r"lagarde", re.IGNORECASE)
EMBED_MODEL_PATTERN: Final = re.compile(r"pplx-embed", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class SelfTestContext:
    auth: AuthClient
    grants: GrantManager
    ai: AiClient
    machine: MachineApi
    public_url: str
    gateway_url: str
    session: Session


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: object = None
    error: dict[str, object] | None = None

    def to_json(self) -> dict[str, object]:
        """The detailed report, for the server log."""
        body: dict[str, object] = {"name": self.name, "ok": self.ok}
        if self.ok:
            body["detail"] = self.detail
        if self.error is not None:
            body["error"] = self.error
        return body

    def to_public_json(self) -> dict[str, object]:
        """What the browser gets: the error code only."""
        body = self.to_json()
        if self.error is not None:
            code = self.error.get("code")
            body["error"] = {} if code is None else {"code": code}
        return body


@dataclass(slots=True)
class _State:
    ctx: SelfTestContext
    user: UserAi
    usage_session_id: str
    models: list[str] = field(default_factory=list)

    @property
    def user_id(self) -> str:
        return self.ctx.session.user_id


type _Check = Callable[[_State], Awaitable[object]]


def _describe_error(err: Exception) -> dict[str, object]:
    if isinstance(err, AuthAiError):
        return err.to_json()
    return {"message": str(err)}


async def _check(name: str, run: _Check, state: _State) -> CheckResult:
    try:
        return CheckResult(name, ok=True, detail=await run(state))
    except Exception as err:  # noqa: BLE001 - a failing check is a result, not a crash
        return CheckResult(name, ok=False, error=_describe_error(err))


async def _settle[T](
    read: Callable[[], Awaitable[T]],
    done: Callable[[T], bool],
    timeout_seconds: float = POLL_TIMEOUT_SECONDS,
) -> T:
    """Billing is asynchronous: poll until `done` holds or the time is up."""
    deadline = time.monotonic() + timeout_seconds
    value = await read()
    while not done(value) and time.monotonic() < deadline:
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        value = await read()
    return value


def _summarise(answer: object) -> dict[str, object]:
    parsed = parse_answer(ChatAnswer, answer)
    choice = parsed.choices[0] if parsed.choices else None
    message = choice.message if choice else None
    content = (message.content if message else None) or ""
    return {
        "reply": content[:80],
        "replyLength": len(content),
        "hasReasoning": bool(message and message.reasoning_content),
        "finishReason": choice.finish_reason if choice else None,
        "usage": parsed.usage,
    }


# ── Checks ──


async def _session_claims(state: _State) -> object:
    session = state.ctx.session
    claims = session.claims
    return {
        "sub": session.user_id,
        "hasProviderSession": session.session_id is not None,
        "roles": claims.roles,
        "permissions": claims.permissions,
        "features": claims.features,
        "plan": claims.plan,
        "orgId": claims.org_id,
    }


async def _refresh_returns_id_token(state: _State) -> object:
    tokens = await state.ctx.grants.refresh_tokens(state.user_id)
    claims = await state.ctx.auth.verify_id_token(tokens.id_token) if tokens.id_token else None
    return {
        "idTokenReturned": tokens.id_token is not None,
        "rotated": tokens.refresh_token is not None,
        "scope": tokens.scope,
        "rolesInRenewedClaims": claims.roles if claims else None,
        "planInRenewedClaims": claims.plan if claims else None,
        "featuresInRenewedClaims": claims.features if claims else None,
    }


async def _tokens_per_audience(state: _State) -> object:
    ctx = state.ctx
    out: dict[str, object] = {}
    for resource in (ctx.auth.config.issuer, ctx.gateway_url, ctx.public_url):
        token = await ctx.grants.get_access_token(state.user_id, resource=resource)
        claims = await ctx.auth.verify_jwt(token.access_token, audience=resource)
        out[resource] = {
            "aud": claims.get("aud"),
            "azp": claims.get("azp"),
            "scope": claims.get("scope"),
            "lifetimeSeconds": token.expires_at - int(time.time()),
        }
    return out


async def _bearer_own_resource(state: _State) -> object:
    ctx = state.ctx
    token = await ctx.grants.get_access_token(state.user_id, resource=ctx.public_url)
    verified = await BearerVerifier(ctx.auth, audience=ctx.public_url).verify(token.access_token)
    return {
        "userId": verified.user_id,
        "clientId": verified.client_id,
        "scopes": list(verified.scopes),
    }


async def _introspection(state: _State) -> object:
    ctx = state.ctx
    token = await ctx.grants.get_access_token(state.user_id, resource=ctx.auth.config.issuer)
    result = await ctx.auth.introspect(token.access_token, "access_token")
    return {"active": result.active, "scope": result.scope}


async def _wallet(state: _State) -> object:
    wallet = state.user.wallet
    account = await wallet.get_account()
    stats = await wallet.get_stats(days=7)
    page = await wallet.list_transactions(limit=3)
    topup = await wallet.get_topup_options()
    return {
        "balanceEuros": format_euros(account.balance, 6),
        "isUnlimited": account.is_unlimited,
        "canSpend": account.can_spend,
        "spent7d": format_euros(stats.total, 6),
        "calls7d": stats.calls,
        "lastTransactions": [f"{t.type}:{t.delta}" for t in page.items],
        "topupEnabled": topup.enabled,
        "topupUrl": wallet.topup_url(),
    }


async def _gateway_models(state: _State) -> object:
    state.models[:] = [model.id for model in await state.user.gateway.list_models()]
    return state.models


async def _gateway_agents(state: _State) -> object:
    return [agent.agent_name for agent in await state.user.gateway.list_agents()]


async def _gateway_mcp_servers(state: _State) -> object:
    gateway = state.user.gateway
    return {
        "servers": [
            server.server_name or server.alias or server.server_id
            for server in await gateway.list_mcp_servers()
        ],
        "mcpUrl": gateway.mcp_url(),
    }


async def _chat_free_model(state: _State) -> object:
    chat_model = next((m for m in state.models if CHAT_MODEL_PATTERN.search(m)), None)
    if chat_model is None:
        raise LookupError("no model matching /lagarde/ in the plan")
    answer = await state.user.gateway.post_json(
        "/v1/chat/completions",
        {
            "model": chat_model,
            "max_tokens": 512,
            "messages": [{"role": "user", "content": "Reply with the single word: pong"}],
            "metadata": {"session_id": state.usage_session_id},
        },
    )
    return {"model": chat_model, **_summarise(answer)}


async def _embedding_billed_model(state: _State) -> object:
    embed_model = next((m for m in state.models if EMBED_MODEL_PATTERN.search(m)), None)
    if embed_model is None:
        raise LookupError("no model matching /pplx-embed/ in the plan")
    user = state.user
    before = await user.wallet.get_account()
    answer = await user.gateway.post_json(
        "/v1/embeddings",
        {
            "model": embed_model,
            "input": "auth-ai self-test",
            "metadata": {"session_id": state.usage_session_id},
        },
    )
    embeddings = parse_answer(EmbeddingAnswer, answer)
    after = await _settle(
        user.wallet.get_account, lambda account: account.balance != before.balance
    )
    return {
        "model": embed_model,
        "dimensions": len(embeddings.data[0].embedding) if embeddings.data else None,
        "balanceBefore": format_euros(before.balance, 6),
        "balanceAfter": format_euros(after.balance, 6),
        "debitedMicroEuros": str(before.balance - after.balance),
    }


async def _wallet_session_usage(state: _State) -> object:
    wallet = state.user.wallet
    usage = await _settle(
        lambda: wallet.get_session_usage(state.usage_session_id), lambda value: value.calls > 0
    )
    return {
        "calls": usage.calls,
        "totalMicroEuros": str(usage.total),
        "models": [f"{m.model}:{m.total_tokens}tok" for m in usage.by_model],
    }


async def _machine_token(state: _State) -> object:
    tokens = await state.ctx.auth.client_credentials(scope="m2m")
    return {"issued": True, "scope": tokens.scope}


async def _billing_subscription(state: _State) -> object:
    billing = state.ctx.machine.billing
    subscription = await billing.get_subscription(state.user_id)
    return {
        "subscription": subscription.to_json() if subscription else None,
        "usage": (await billing.get_usage(state.user_id)).to_json(),
        "invoices": len((await billing.list_invoices(state.user_id, limit=1)).items),
    }


async def _consumption(state: _State) -> object:
    consumption = state.ctx.machine.consumption
    reported = await consumption.report(
        state.user_id, "selftest.calls", 1, idempotency_key=state.usage_session_id
    )
    stored = await consumption.get_aggregate(state.user_id, "selftest.calls")
    return {
        "reported": {"metered": reported.metered, "aggregate": reported.aggregate.to_json()},
        "storedTotal": stored.total,
    }


async def _consumption_metered_feature(state: _State) -> object:
    machine = state.ctx.machine
    before = (await machine.billing.get_usage(state.user_id)).features
    if not before:
        raise LookupError("the plan prices no metered feature")
    feature = before[0]
    reported = await machine.consumption.report(
        state.user_id,
        feature.feature_key,
        1,
        idempotency_key=f"{state.usage_session_id}-metered",
    )
    after = next(
        (
            item
            for item in (await machine.billing.get_usage(state.user_id)).features
            if item.feature_key == feature.feature_key
        ),
        None,
    )
    return {
        "featureKey": feature.feature_key,
        "metered": reported.metered,
        "usedBefore": feature.used,
        "usedAfter": after.used if after else None,
        "limit": feature.usage_limit,
    }


# Order matters: the model listing feeds the chat and embedding checks.
_CHECKS: Final[tuple[tuple[str, _Check], ...]] = (
    ("session-claims", _session_claims),
    ("refresh-returns-id-token", _refresh_returns_id_token),
    ("tokens-per-audience", _tokens_per_audience),
    ("bearer-own-resource", _bearer_own_resource),
    ("introspection", _introspection),
    ("wallet", _wallet),
    ("gateway-models", _gateway_models),
    ("gateway-agents", _gateway_agents),
    ("gateway-mcp-servers", _gateway_mcp_servers),
    ("chat-free-model", _chat_free_model),
    ("embedding-billed-model", _embedding_billed_model),
    ("wallet-session-usage", _wallet_session_usage),
    ("machine-token", _machine_token),
    ("billing-subscription", _billing_subscription),
    ("consumption", _consumption),
    ("consumption-metered-feature", _consumption_metered_feature),
)


async def run_self_test(ctx: SelfTestContext) -> list[CheckResult]:
    """Exercises every SDK brick for the signed-in user; the report holds no token."""
    state = _State(
        ctx=ctx,
        user=ctx.ai.for_user(ctx.session.user_id),
        usage_session_id=f"selftest-{uuid.uuid4()}",
    )
    return [await _check(name, run, state) for name, run in _CHECKS]
