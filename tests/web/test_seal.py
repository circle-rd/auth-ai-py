from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest
from joserfc import jwe
from joserfc.jwk import OctKey
from pydantic import BaseModel, TypeAdapter

from auth_ai import AuthAiError
from auth_ai.web.seal import derive_seal_key, seal, unseal

SECRET = "0123456789abcdef0123456789abcdef"
ALGORITHMS = ["dir", "A256GCM"]


class Payload(BaseModel):
    state: str
    n: int


SCHEMA = TypeAdapter(Payload)
VALUE = {"state": "s", "n": 1}


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def raw_key(secret: str) -> bytes:
    return hashlib.sha256(f"auth-ai:seal:{secret}".encode()).digest()


def unseal_code(key: OctKey, token: str) -> str:
    with pytest.raises(AuthAiError) as raised:
        unseal(key, token, SCHEMA)
    return raised.value.code


class TestSeal:
    def test_round_trips_a_value(self) -> None:
        key = derive_seal_key(SECRET)
        token = seal(key, VALUE, 60)
        assert "state" not in token
        assert unseal(key, token, SCHEMA) == Payload(state="s", n=1)

    def test_derives_a_stable_256_bit_key(self) -> None:
        key = derive_seal_key(SECRET)
        assert key.raw_value == raw_key(SECRET)
        assert len(key.raw_value) == 32
        assert derive_seal_key(SECRET).raw_value == key.raw_value
        assert derive_seal_key(f"{SECRET}x").raw_value != key.raw_value

    def test_refuses_a_short_secret_without_echoing_it(self) -> None:
        with pytest.raises(AuthAiError) as raised:
            derive_seal_key("hunter2")
        assert raised.value.code == "CFG_001"
        assert "hunter2" not in raised.value.message

    def test_rejects_a_token_sealed_with_another_key(self) -> None:
        token = seal(derive_seal_key(SECRET), VALUE, 60)
        assert unseal_code(derive_seal_key("another-secret-another-secret-12"), token) == "SES_002"

    def test_rejects_a_tampered_token(self) -> None:
        key = derive_seal_key(SECRET)
        header, encrypted_key, iv, ciphertext, tag = seal(key, VALUE, 60).split(".")
        flipped = ("B" if ciphertext[0] == "A" else "A") + ciphertext[1:]
        tampered = ".".join((header, encrypted_key, iv, flipped, tag))
        assert unseal_code(key, tampered) == "SES_002"
        assert unseal_code(key, "not-a-token") == "SES_002"
        assert unseal_code(key, "") == "SES_002"

    def test_rejects_an_expired_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        key = derive_seal_key(SECRET)
        token = seal(key, VALUE, 60)
        assert unseal(key, token, SCHEMA).n == 1
        now = time.time()
        monkeypatch.setattr(time, "time", lambda: now + 61)
        assert unseal_code(key, token) == "SES_002"

    def test_rejects_a_payload_that_does_not_match_the_schema(self) -> None:
        key = derive_seal_key(SECRET)
        assert unseal_code(key, seal(key, {"state": 1}, 60)) == "SES_002"
        assert unseal_code(key, seal(key, "not an object", 60)) == "SES_002"

    def test_rejects_a_token_sealed_with_another_algorithm(self) -> None:
        key = derive_seal_key(SECRET)
        foreign_key = OctKey.import_key(raw_key(SECRET)[:16])
        now = int(time.time())
        payload = json.dumps({"data": VALUE, "iat": now, "exp": now + 60}).encode()
        foreign = jwe.encrypt_compact(
            {"alg": "dir", "enc": "A128GCM"}, payload, foreign_key, algorithms=["dir", "A128GCM"]
        )
        assert unseal_code(key, foreign) == "SES_002"

    def test_rejects_a_token_without_expiry(self) -> None:
        key = derive_seal_key(SECRET)
        payload = json.dumps({"data": VALUE}).encode()
        token = jwe.encrypt_compact(
            {"alg": "dir", "enc": "A256GCM"}, payload, key, algorithms=ALGORITHMS
        )
        assert unseal_code(key, token) == "SES_002"


class TestInteroperability:
    """The cookies are shared with the TypeScript SDK: format and key are the contract."""

    def test_the_token_is_a_compact_dir_a256gcm_jwe(self) -> None:
        token = seal(derive_seal_key(SECRET), VALUE, 60)
        segments = token.split(".")
        assert len(segments) == 5
        assert segments[1] == ""
        assert json.loads(b64url_decode(segments[0])) == {"alg": "dir", "enc": "A256GCM"}

    def test_the_key_is_the_sha256_of_the_prefixed_secret(self) -> None:
        token = seal(derive_seal_key(SECRET), VALUE, 60)
        independent = OctKey.import_key(raw_key(SECRET))
        decrypted = jwe.decrypt_compact(token, independent, algorithms=ALGORITHMS)
        assert decrypted.plaintext is not None
        envelope = json.loads(decrypted.plaintext)
        assert envelope["data"] == VALUE
        assert envelope["exp"] - envelope["iat"] == 60

    def test_unseals_a_token_built_the_way_the_typescript_sdk_does(self) -> None:
        now = int(time.time())
        payload = json.dumps({"data": VALUE, "iat": now, "exp": now + 60}).encode()
        token = jwe.encrypt_compact(
            {"alg": "dir", "enc": "A256GCM"},
            payload,
            OctKey.import_key(raw_key(SECRET)),
            algorithms=ALGORITHMS,
        )
        assert unseal(derive_seal_key(SECRET), token, SCHEMA) == Payload(state="s", n=1)
