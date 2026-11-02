from pydantic import BaseModel, ConfigDict, Field, ValidationError

from auth_ai import ERR


class _GatewayPayload(BaseModel):
    # The gateway adds members across versions: read what the example needs.
    model_config = ConfigDict(extra="ignore", frozen=True)


class ChatMessage(_GatewayPayload):
    content: str | None = None
    reasoning_content: str | None = None


class ChatChoice(_GatewayPayload):
    finish_reason: str | None = None
    message: ChatMessage | None = None


class ChatAnswer(_GatewayPayload):
    choices: list[ChatChoice] = Field(default_factory=list)
    usage: dict[str, object] | None = None


class EmbeddingItem(_GatewayPayload):
    embedding: list[float] = Field(default_factory=list)


class EmbeddingAnswer(_GatewayPayload):
    data: list[EmbeddingItem] = Field(default_factory=list)


def parse_answer[M: BaseModel](model: type[M], answer: object) -> M:
    """Validates a gateway answer; an unexpected shape is GW_005."""
    try:
        return model.model_validate(answer)
    except ValidationError as err:
        raise ERR.GW_005(cause=err) from err
