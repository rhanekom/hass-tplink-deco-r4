"""
TP-Link Deco R4 web-interface protocol client (spike).

A self-contained async implementation of the login/session protocol described in
`doc/specification.md`, used by `deco_probe.py` to validate that specification
against real hardware. This is throwaway-grade by design: once the protocol is
proven here, the logic gets ported into
`custom_components/tplink_deco_r4/api.py` with tests and full linting.

Nothing here imports Home Assistant. Only `aiohttp` (for transport) and the
standard library are used; the crypto is implemented directly because the
firmware's RSA usage is non-standard (raw PKCS#1 v1.5 blocks over a 512-bit key,
hex encoded, concatenated in 53-byte chunks) and hand-rolling it is clearer than
bending a library into the same shape.

Safety: every call this module makes is a read (`operation: read` / `get`) plus
the login and logout handshakes. It never issues a write, reboot or factory
operation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import ssl
from dataclasses import dataclass, field
from typing import Any, Self

import aiohttp
from yarl import URL

# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class DecoError(Exception):
    """Base class for protocol failures."""


class DecoConnectionError(DecoError):
    """Transport-level failure: DNS, refused, timeout, TLS."""


class DecoAuthError(DecoError):
    """The router rejected the credentials.

    `retryable` is False when retrying would burn a login attempt and risk
    locking the account. Callers must honour it.
    """

    def __init__(self, message: str, code: object = None, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class DecoSessionExpiredError(DecoError):
    """The session is no longer valid; a fresh login is required."""


class DecoApiError(DecoError):
    """The JSON API returned a non-zero error_code."""

    def __init__(self, message: str, code: object = None):
        super().__init__(message)
        self.code = code


# Login failure codes from `?code=7&asyn=0`, per
# modules/login/localLogin/controllers.js.
# The tuple is (human message, safe to retry automatically).
LOGIN_ERRORS: dict[int, tuple[str, bool]] = {
    0: ("router login sessions are full", True),
    1: ("account is locked out", False),
    2: ("login timed out", True),
    3: ("wrong password", False),
    5: ("wrong password", False),
    6: ("wrong password", False),
}

# error_code values from the JSON API, per frame.js successJudge().
API_SESSION_ERRORS: frozenset[object] = frozenset({"timeout", -5001})
API_AUTH_ERRORS: frozenset[object] = frozenset({-5002, -5003})


# --------------------------------------------------------------------------- #
# Crypto primitives (ports of js/libs/encrypt.js + js/libs/tpEncrypt.js)
# --------------------------------------------------------------------------- #

_PAD_BYTE = 187  # 0xBB, the padding operand in $.su.encrypt


def su_encrypt(text: str, key: str, dictionary: str) -> str:
    """Port of `$.su.encrypt`: a dictionary-indexed XOR, not a cipher.

    Used only to derive the session id from the server salt and the password
    hash. Both operands are 32 characters on this firmware, so the result is 32
    characters drawn from `dictionary`.
    """
    out: list[str] = []
    len_t, len_k, len_d = len(text), len(key), len(dictionary)
    for i in range(max(len_t, len_k)):
        s = n = _PAD_BYTE
        if len_t <= i:
            n = ord(key[i])
        elif len_k <= i:
            s = ord(text[i])
        else:
            s, n = ord(text[i]), ord(key[i])
        out.append(dictionary[(s ^ n) % len_d])
    return "".join(out)


def md5_hex(value: str) -> str:
    """Lowercase hex MD5. Weak by modern standards; the firmware requires it."""
    return hashlib.md5(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RsaPublicKey:
    """The router's RSA public key, as delivered by `?code=16&asyn=0` / `get`."""

    modulus_hex: str
    exponent_hex: str

    @property
    def n(self) -> int:
        return int(self.modulus_hex, 16)

    @property
    def e(self) -> int:
        return int(self.exponent_hex, 16)

    @property
    def size_bytes(self) -> int:
        """Modulus length in bytes. 64 (512-bit) on the reference firmware."""
        return (self.n.bit_length() + 7) // 8

    @property
    def max_block(self) -> int:
        """Longest plaintext a single PKCS#1 v1.5 block can carry."""
        return self.size_bytes - 11


def rsa_encrypt_hex(plaintext: str, key: RsaPublicKey) -> str:
    """RSA-encrypt `plaintext`, chunked, returning concatenated hex blocks.

    Mirrors `$.su.RSAencrypt` plus `encryptor.getSignature`: PKCS#1 v1.5 type-2
    padding, one block per `max_block` bytes of input, each block rendered as
    hex left-zero-padded to the modulus length.
    """
    data = plaintext.encode("utf-8")
    chunk = key.max_block
    if chunk < 1:
        raise DecoError(f"RSA modulus too small: {key.size_bytes} bytes")
    return "".join(
        _rsa_encrypt_block(data[i : i + chunk], key) for i in range(0, len(data), chunk)
    )


def _rsa_encrypt_block(block: bytes, key: RsaPublicKey) -> str:
    size = key.size_bytes
    pad_len = size - len(block) - 3
    if pad_len < 8:
        raise DecoError("RSA block too long for modulus")
    # PKCS#1 v1.5 type 2: 0x00 0x02 <non-zero random padding> 0x00 <block>
    padding = bytes(secrets.choice(range(1, 256)) for _ in range(pad_len))
    encoded = b"\x00\x02" + padding + b"\x00" + block
    cipher = pow(int.from_bytes(encoded, "big"), key.e, key.n)
    return cipher.to_bytes(size, "big").hex()


@dataclass
class AesKey:
    """AES-128-CBC key material.

    The firmware generates key and IV as 16-character strings of ASCII decimal
    digits and uses those characters' UTF-8 bytes directly as the 16-byte key
    and IV (`tpEncrypt.js` `genKey`).
    """

    key: str
    iv: str

    @classmethod
    def generate(cls) -> AesKey:
        digits = "0123456789"
        gen = lambda: "".join(secrets.choice(digits) for _ in range(16))  # noqa: E731
        return cls(key=gen(), iv=gen())

    @property
    def key_string(self) -> str:
        """The canonical `k=<key>&i=<iv>` form used for RSA upload and signing."""
        return f"k={self.key}&i={self.iv}"

    def encrypt(self, plaintext: str) -> str:
        return base64.b64encode(
            _aes_cbc(
                self._key_bytes, self._iv_bytes, _pkcs7_pad(plaintext.encode()), True
            )
        ).decode("ascii")

    def decrypt(self, b64: str) -> str:
        raw = base64.b64decode(b64, validate=False)
        if not raw or len(raw) % 16:
            raise DecoError(
                f"ciphertext is not a whole number of AES blocks ({len(raw)} bytes)"
            )
        return _pkcs7_unpad(
            _aes_cbc(self._key_bytes, self._iv_bytes, raw, False)
        ).decode("utf-8", errors="strict")

    @property
    def _key_bytes(self) -> bytes:
        return self.key.encode("ascii")

    @property
    def _iv_bytes(self) -> bytes:
        return self.iv.encode("ascii")


def _aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    # Imported lazily so the crypto dependency is only needed when actually used.
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(data) + ctx.finalize()


def _pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise DecoError("empty plaintext after AES decrypt")
    pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        raise DecoError("bad PKCS#7 padding after AES decrypt (wrong key?)")
    return data[:-pad]


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #

# OpenSSL 3.x refuses this firmware's TLS stack under its default policy, for two
# independent reasons, both confirmed live against the reference unit:
#
#   1. UNSAFE_LEGACY_RENEGOTIATION_DISABLED -- the server does not advertise the
#      RFC 5746 renegotiation extension, so OP_LEGACY_SERVER_CONNECT is required.
#   2. WRONG_SIGNATURE_TYPE -- with that fixed, the handshake still fails at
#      security level 1+ because the server signs it with an algorithm OpenSSL
#      now rejects. SECLEVEL=0 is needed. (Not a certificate problem: the cert
#      itself is a 2048-bit sha256WithRSAEncryption self-signed leaf.)
#
# The negotiated connection is TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256, so the
# transport is sound; it is OpenSSL's algorithm *policy* that has moved on, not
# the crypto that is broken.
_OP_LEGACY_SERVER_CONNECT = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x04)


def build_ssl_context(verify_ssl: bool = False) -> ssl.SSLContext:
    """Build an SSL context this firmware will actually complete a handshake with.

    `verify_ssl` still controls certificate and hostname verification. The
    algorithm-policy relaxations are applied either way, because without them no
    handshake completes at all and the flag would have nothing to verify.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.options |= _OP_LEGACY_SERVER_CONNECT
    context.set_ciphers("DEFAULT@SECLEVEL=0")
    if verify_ssl:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    else:
        # The router serves a self-signed cert for an RFC1918 address.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


# --------------------------------------------------------------------------- #
# Session-id URL encoding
# --------------------------------------------------------------------------- #

# The session id is drawn from a server-supplied 255-character dictionary. That
# dictionary excludes URI-reserved printables but NOT control bytes (0x08 has
# been observed), so the id must be percent-encoded. Two candidate schemes:
#
#   "strict"  percent-encode everything outside the unreserved set. Strictly
#             valid; relies on the router percent-decoding properly.
#   "browser" reproduce Firefox's query encoding: encode only C0 controls,
#             DEL, space and " # < > '. This is what the captures show working.
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_BROWSER_ENCODE = frozenset(" \"#<>'\x7f") | {chr(c) for c in range(0x20)}

ID_ENCODINGS = ("browser", "strict")


def encode_session_id(session_id: str, scheme: str = "browser") -> str:
    """Percent-encode a session id for use in the `id` query parameter."""
    if scheme == "strict":
        should_encode = lambda ch: ch not in _UNRESERVED  # noqa: E731
    elif scheme == "browser":
        should_encode = lambda ch: ch in _BROWSER_ENCODE  # noqa: E731
    else:
        raise ValueError(f"unknown id encoding scheme: {scheme}")
    out: list[str] = []
    for ch in session_id:
        if should_encode(ch):
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8"))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------- #
# Wire-level records
# --------------------------------------------------------------------------- #


@dataclass
class TmpKey:
    """Key material from `?code=7&asyn=1` (the 401 response)."""

    lines: list[str]

    @property
    def salt(self) -> str:
        return self.lines[3]

    @property
    def dictionary(self) -> str:
        return self.lines[4]


@dataclass
class HandshakeFacts:
    """What the handshake revealed, for the probe's report. No secrets."""

    tmp_key_status: int | None = None
    salt_len: int | None = None
    dictionary_len: int | None = None
    dictionary_distinct: int | None = None
    dictionary_has_control_bytes: bool | None = None
    dictionary_ord_range: tuple[int, int] | None = None
    rsa_modulus_bits: int | None = None
    rsa_exponent_hex: str | None = None
    seq: int | None = None
    session_id_len: int | None = None
    session_id_needs_encoding: bool | None = None
    session_id_encoding_used: str | None = None
    signature_hex_len: int | None = None
    signature_blocks: int | None = None
    plaintext_responses_until_set_key: bool | None = None


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


@dataclass
class DecoClient:
    """An authenticated session against one Deco master node."""

    host: str
    password: str
    verify_ssl: bool = False
    timeout: float = 15.0
    id_encoding: str = "browser"
    trace: bool = False
    auto_relogin: bool = True

    _session: aiohttp.ClientSession | None = field(default=None, init=False, repr=False)
    _own_session: bool = field(default=False, init=False, repr=False)
    _tmp_key: TmpKey | None = field(default=None, init=False, repr=False)
    _rsa: RsaPublicKey | None = field(default=None, init=False, repr=False)
    _aes: AesKey | None = field(default=None, init=False, repr=False)
    _seq: int | None = field(default=None, init=False, repr=False)
    _session_id: str | None = field(default=None, init=False, repr=False)
    _encrypted: bool = field(default=False, init=False, repr=False)
    facts: HandshakeFacts = field(default_factory=HandshakeFacts, repr=False)
    request_count: int = field(default=0, init=False)
    relogin_count: int = field(default=0, init=False)

    # -- lifecycle ---------------------------------------------------------- #

    @property
    def base_url(self) -> str:
        host = self.host.strip()
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host.rstrip("/")

    @property
    def logged_in(self) -> bool:
        return self._session_id is not None and self._encrypted

    async def __aenter__(self) -> Self:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=build_ssl_context(self.verify_ssl)),
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            )
            self._own_session = True
        return self

    async def __aexit__(self, *exc: object) -> None:
        try:
            if self.logged_in:
                await self.logout()
        finally:
            if self._session is not None and self._own_session:
                await self._session.close()
                self._session = None

    # -- transport ---------------------------------------------------------- #

    async def _post(
        self,
        path_and_query: str,
        body: str | None = None,
        content_type: str | None = None,
        with_id: bool = False,
    ) -> tuple[int, str]:
        """POST to a raw path+query, returning (status, body text).

        The URL is assembled and percent-encoded here and handed to yarl with
        `encoded=True`, so yarl never re-normalises the session id.
        """
        if self._session is None:
            raise DecoError("client used outside its async context manager")
        url = f"{self.base_url}{path_and_query}"
        if with_id:
            if self._session_id is None:
                raise DecoError("no session id yet")
            url += f"&id={encode_session_id(self._session_id, self.id_encoding)}"

        headers = {
            "Accept": "*/*",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/",
        }
        if content_type:
            headers["Content-Type"] = content_type

        if self.trace:
            print(
                f"    -> POST {_redact_url(path_and_query, with_id)} "
                f"({len(body or '')} bytes)"
            )
        try:
            async with self._session.post(
                URL(url, encoded=True),
                data=(body or "").encode("utf-8"),
                headers=headers,
            ) as resp:
                text = await resp.text(errors="replace")
        except aiohttp.ClientSSLError as err:
            raise DecoConnectionError(
                f"TLS failure talking to the router: {err}"
            ) from err
        except (TimeoutError, aiohttp.ClientError) as err:
            raise DecoConnectionError(f"cannot reach the router: {err}") from err
        self.request_count += 1
        if self.trace:
            print(f"    <- {resp.status} ({len(text)} bytes)")
        return resp.status, text

    # -- handshake ---------------------------------------------------------- #

    async def fetch_tmp_key(self) -> TmpKey | None:
        """`?code=7&asyn=1`.

        Returns key material on 401, or None if a session is already valid.
        """
        status, text = await self._post("/?code=7&asyn=1")
        self.facts.tmp_key_status = status
        if status != 401:
            return None
        lines = text.removesuffix("\r\n").split("\r\n")
        if len(lines) < 5:
            raise DecoError(f"unexpected code=7 response shape: {len(lines)} lines")
        tmp = TmpKey(lines)
        alphabet = tmp.dictionary
        ords = [ord(c) for c in alphabet]
        self.facts.salt_len = len(tmp.salt)
        self.facts.dictionary_len = len(alphabet)
        self.facts.dictionary_distinct = len(set(alphabet))
        self.facts.dictionary_has_control_bytes = any(
            o < 0x20 or o == 0x7F for o in ords
        )
        self.facts.dictionary_ord_range = (min(ords), max(ords))
        self._tmp_key = tmp
        return tmp

    async def _enable_encryption(self) -> None:
        status, text = await self._post(
            "/?code=16&asyn=0",
            "enable",
            "application/x-www-form-urlencoded; charset=UTF-8",
        )
        _expect_ok(status, text, "enable application-layer encryption")

    async def _fetch_rsa_key(self) -> None:
        status, text = await self._post(
            "/?code=16&asyn=0",
            "get",
            "application/x-www-form-urlencoded; charset=UTF-8",
        )
        _expect_ok(status, text, "fetch RSA public key")
        lines = text.removesuffix("\r\n").split("\r\n")
        if len(lines) < 4:
            raise DecoError(
                f"unexpected key-exchange response shape: {len(lines)} lines"
            )
        # Note the ordering: setRSAKey(data[2], data[1]) -> modulus, then exponent.
        self._rsa = RsaPublicKey(modulus_hex=lines[2], exponent_hex=lines[1])
        self._seq = int(lines[3])
        self._aes = AesKey.generate()
        self.facts.rsa_modulus_bits = self._rsa.n.bit_length()
        self.facts.rsa_exponent_hex = self._rsa.exponent_hex
        self.facts.seq = self._seq

    def _derive_session_id(self) -> str:
        if self._tmp_key is None:
            raise DecoError("no tmp key; call fetch_tmp_key() first")
        session_id = su_encrypt(
            self._tmp_key.salt, md5_hex(self.password), self._tmp_key.dictionary
        )
        self.facts.session_id_len = len(session_id)
        self.facts.session_id_needs_encoding = any(
            c not in _UNRESERVED for c in session_id
        )
        self.facts.session_id_encoding_used = self.id_encoding
        return session_id

    async def _submit_password(self) -> None:
        if self._rsa is None:
            raise DecoError("no RSA key")
        body = rsa_encrypt_hex(self.password, self._rsa)
        status, text = await self._post(
            "/?code=7&asyn=0",
            body,
            "application/x-www-form-urlencoded; charset=UTF-8",
            with_id=True,
        )
        first = text.split("\r\n")[0] if text else ""
        if status == 200 and first == "00000":
            self.facts.plaintext_responses_until_set_key = True
            return
        raise _login_error(status, text)

    async def _upload_aes_key(self) -> None:
        if self._aes is None or self._rsa is None:
            raise DecoError("no AES/RSA key material")
        sealed = rsa_encrypt_hex(self._aes.key_string, self._rsa)
        status, text = await self._post(
            "/?code=16&asyn=0",
            f"set {sealed}",
            "application/x-www-form-urlencoded; charset=UTF-8",
            with_id=True,
        )
        _expect_ok(status, text, "upload AES session key")
        self._encrypted = True

    async def login(self) -> None:
        """Run the full five-step login flow from doc/specification.md section 4."""
        # Reset any dead session state so a re-login starts clean.
        self._session_id = None
        self._encrypted = False
        tmp = await self.fetch_tmp_key()
        if tmp is None:
            raise DecoError(
                "?code=7&asyn=1 did not return 401; an unexpected session state exists"
            )
        await self._enable_encryption()
        await self._fetch_rsa_key()
        self._session_id = self._derive_session_id()
        await self._submit_password()
        await self._upload_aes_key()

    async def logout(self) -> None:
        """`?code=11`. Best-effort: never raises, so it is safe in teardown."""
        try:
            await self._post("/?code=11&asyn=0", with_id=True)
        except DecoError:
            pass
        finally:
            self._session_id = None
            self._encrypted = False

    # -- JSON API ----------------------------------------------------------- #

    def _envelope(self, payload: dict[str, Any]) -> str:
        if self._aes is None or self._rsa is None or self._seq is None:
            raise DecoError("no session crypto state")
        data = self._aes.encrypt(json.dumps(payload, separators=(",", ":")))
        signed = f"{self._aes.key_string}&s={self._seq + len(data)}"
        sign = rsa_encrypt_hex(signed, self._rsa)
        self.facts.signature_hex_len = len(sign)
        self.facts.signature_blocks = len(sign) // (self._rsa.size_bytes * 2)
        return f"sign={sign}&data={data}"

    async def call(
        self,
        form_path: str,
        operation: str = "read",
        params: dict[str, Any] | None = None,
        raw_payload: dict[str, Any] | None = None,
    ) -> Any:
        """Call a `?form=` endpoint and return the decrypted `result` payload.

        `form_path` is the path plus its `form=` query, e.g.
        `/admin/device?form=device_list`.

        Sessions on this firmware die unpredictably: HTTP 403 mid-cycle has been
        observed even on a session that was working moments earlier, and a
        competing login elsewhere in the household can evict this one. When
        `auto_relogin` is set (the default) a session failure triggers one full
        re-login and one retry, which is what makes polling survivable. An
        authentication failure is never retried, because that would spend login
        attempts toward the router's lockout.
        """
        try:
            return await self._call_once(form_path, operation, params, raw_payload)
        except DecoSessionExpiredError:
            if not self.auto_relogin:
                raise
            self.relogin_count += 1
            await self.login()
            return await self._call_once(form_path, operation, params, raw_payload)

    async def _call_once(
        self,
        form_path: str,
        operation: str = "read",
        params: dict[str, Any] | None = None,
        raw_payload: dict[str, Any] | None = None,
    ) -> Any:
        payload: dict[str, Any] = raw_payload or {"operation": operation}
        if params is not None:
            payload["params"] = params

        status, text = await self._post(
            form_path, self._envelope(payload), "text/plain;charset=UTF-8", with_id=True
        )
        if status in (401, 403, 408):
            raise DecoSessionExpiredError(f"session rejected with HTTP {status}")
        if status != 200:
            raise DecoApiError(f"HTTP {status} from {form_path}")

        if self._aes is None:
            raise DecoError("no AES key")
        try:
            plaintext = self._aes.decrypt(text.strip())
        except DecoError as err:
            # frame.js treats an undecryptable body as "session gone, re-login".
            raise DecoSessionExpiredError(
                f"could not decrypt response from {form_path}: {err}"
            ) from err

        try:
            body = json.loads(plaintext)
        except json.JSONDecodeError as err:
            raise DecoError(f"response from {form_path} is not JSON: {err}") from err

        code = body.get("error_code", body.get("errorcode"))
        if not (body.get("success") is True or code == 0):
            if code in API_SESSION_ERRORS:
                raise DecoSessionExpiredError(
                    f"{form_path} reported error_code {code!r}"
                )
            if code in API_AUTH_ERRORS:
                raise DecoAuthError(
                    f"{form_path} reported auth error {code!r}",
                    code=code,
                    retryable=False,
                )
            raise DecoApiError(f"{form_path} reported error_code {code!r}", code=code)
        return body.get("data", body.get("result"))

    # -- convenience readers ------------------------------------------------ #

    async def get_mode(self) -> dict[str, Any]:
        return await self.call("/admin/device?form=mode")

    async def get_device_list(self) -> list[dict[str, Any]]:
        result = await self.call("/admin/device?form=device_list")
        return list(result.get("device_list") or [])

    async def get_client_list(
        self, device_mac: str = "default"
    ) -> list[dict[str, Any]]:
        result = await self.call(
            "/admin/client?form=client_list", params={"device_mac": device_mac}
        )
        return list(result.get("client_list") or [])

    async def get_performance(self, device_mac: str | None = None) -> dict[str, Any]:
        params = {"device_mac": device_mac} if device_mac else None
        return await self.call("/admin/network?form=performance", params=params)

    async def get_lan_ip(self, device_mac: str = "default") -> dict[str, Any]:
        return await self.call(
            "/admin/network?form=lan_ip", params={"device_mac": device_mac}
        )

    async def get_wlan(self) -> dict[str, Any]:
        return await self.call("/admin/wireless?form=wlan")

    async def get_internet(self) -> dict[str, Any]:
        return await self.call("/admin/network?form=internet")


# --------------------------------------------------------------------------- #
# Unauthenticated probes
# --------------------------------------------------------------------------- #


async def probe_unauthenticated(host: str, verify_ssl: bool = False) -> dict[str, Any]:
    """Read the two plain-JSON endpoints that need no session."""
    client = DecoClient(host=host, password="", verify_ssl=verify_ssl)
    out: dict[str, Any] = {}
    async with client:
        for name, path in (
            ("envar", "/system?form=envar"),
            ("check_factory_default", "/login?form=check_factory_default"),
        ):
            try:
                status, text = await client._post(  # noqa: SLF001 - spike probe
                    path, '{"operation":"read"}', "application/json"
                )
                out[name] = {"status": status, "body": json.loads(text)}
            except (DecoError, json.JSONDecodeError) as err:
                out[name] = {"error": str(err)}
    return out


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _expect_ok(status: int, text: str, what: str) -> None:
    first = text.split("\r\n", maxsplit=1)[0] if text else ""
    if status == 200 and first == "00000":
        return
    raise DecoError(f"failed to {what}: HTTP {status}, first line {first!r}")


def _login_error(status: int, text: str) -> DecoError:
    lines = text.split("\r\n")
    raw = lines[1] if len(lines) > 1 else ""
    try:
        code = int(raw)
    except ValueError:
        return DecoAuthError(
            f"login rejected with HTTP {status} and no parsable error code",
            retryable=False,
        )
    message, retryable = LOGIN_ERRORS.get(code, (f"unknown login error {code}", False))
    detail = ""
    if code in (3, 5) and len(lines) > 2 and lines[2].strip().isdigit():
        detail = f" ({10 - int(lines[2]):d} attempt(s) remaining before lockout)"
    return DecoAuthError(
        f"login failed: {message}{detail}", code=code, retryable=retryable
    )


def _redact_url(path_and_query: str, with_id: bool) -> str:
    return f"{path_and_query}{'&id=<redacted>' if with_id else ''}"


def b64_decode_field(value: object) -> object:
    """Decode a base64 field, returning the input unchanged if it is not base64.

    Deco payloads base64-encode client names, SSIDs and `custom_nickname`, but
    not every string field, and the firmware is not always consistent.
    """
    if not isinstance(value, str) or not value:
        return value
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except ValueError, UnicodeDecodeError:
        return value
