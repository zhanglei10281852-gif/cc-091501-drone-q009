"""安全原语与授权口径（仅用标准库）。

- API Key 以 SHA-256 散列存库，明文只在签发时返回一次；
- 敏感身份使用 ChaCha20（RFC 8439）+ HMAC-SHA256（Encrypt-then-MAC）落库，
  密钥独立存放在 data/identity.key，与可公开摘要物理分开；
- 权限按 scope 粗粒度授权，身份读取另需逐案 grant。
"""

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass

# ---- 作用域 ----------------------------------------------------------------

USER_MANAGE = "user:manage"
CASE_READ = "case:read"
CASE_WRITE = "case:write"
EVIDENCE_INTAKE = "evidence:intake"
EVIDENCE_READ = "evidence:read"
EVIDENCE_DOWNLOAD = "evidence:download"
EVIDENCE_VOID = "evidence:void"
CUSTODY_HANDLE = "custody:handle"
FACT_WRITE = "fact:write"
FINDING_WRITE = "finding:write"
DECISION_WRITE = "decision:write"
IDENTITY_GRANT = "identity:grant"
PUBLIC_WRITE = "public:write"
ARCHIVE_WRITE = "archive:write"
ARCHIVE_READ = "archive:read"
AUDIT_READ = "audit:read"

ROLE_SCOPES = {
    # 办案人员
    "officer": {
        USER_MANAGE, CASE_READ, CASE_WRITE, EVIDENCE_INTAKE, EVIDENCE_READ,
        EVIDENCE_DOWNLOAD, EVIDENCE_VOID, CUSTODY_HANDLE, FACT_WRITE,
        FINDING_WRITE, IDENTITY_GRANT, PUBLIC_WRITE,
    },
    # 审批人
    "approver": {
        CASE_READ, EVIDENCE_READ, EVIDENCE_DOWNLOAD, DECISION_WRITE,
    },
    # 档案管理员
    "archivist": {
        CASE_READ, EVIDENCE_READ, EVIDENCE_DOWNLOAD, ARCHIVE_WRITE, ARCHIVE_READ,
    },
    # 审计员（可读取全部留痕，含作废材料）
    "auditor": {
        CASE_READ, EVIDENCE_READ, EVIDENCE_DOWNLOAD, AUDIT_READ, ARCHIVE_READ,
    },
    # 外单位录入员（景区公安 / Remote ID 运营单位等）：可登记并调阅本人提交的材料，
    # 服务层以 intaker_user_id 过滤，案件级接口一律不开放
    "intaker": {EVIDENCE_INTAKE, EVIDENCE_READ, EVIDENCE_DOWNLOAD},
    # 只读公众用户：只能看到脱敏后的可公开摘要
    "viewer": set(),
}

ROLE_NAMES = {
    "officer": "办案人员",
    "approver": "审批人",
    "archivist": "档案管理员",
    "auditor": "审计员",
    "intaker": "单位录入员",
    "viewer": "只读用户",
}


# ---- API Key ----------------------------------------------------------------

def generate_key() -> str:
    return "dk_" + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ---- 身份信息封存：ChaCha20 + HMAC -----------------------------------------

def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _rotl32(x: int, n: int) -> int:
    return _u32((x << n) | (x >> (32 - n)))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = _u32(state[a] + state[b]); state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = _u32(state[c] + state[d]); state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = _u32(state[a] + state[b]); state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = _u32(state[c] + state[d]); state[b] = _rotl32(state[b] ^ state[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
    ]
    state += [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    state += [counter]
    state += [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]
    working = list(state)
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return b"".join(_u32(working[i] + state[i]).to_bytes(4, "little") for i in range(16))


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    out = bytearray()
    for block_index in range(0, len(data), 64):
        keystream = _chacha20_block(key, counter + block_index // 64, nonce)
        chunk = data[block_index:block_index + 64]
        out.extend(a ^ b for a, b in zip(chunk, keystream[: len(chunk)]))
    return bytes(out)


def _hkdf(master: bytes, info: bytes, length: int = 32) -> bytes:
    # RFC 5869：salt 为空时 PRK = HMAC(0x00 长度=散列长度, IKM)
    prk = hmac.new(b"\x00" * hashlib.sha256().digest_size, master, hashlib.sha256).digest()
    okm = b""
    previous = b""
    i = 1
    while len(okm) < length:
        previous = hmac.new(prk, previous + info + bytes([i]), hashlib.sha256).digest()
        okm += previous
        i += 1
    return okm[:length]


@dataclass
class IdentityCipher:
    master_key: bytes

    @classmethod
    def load(cls, key_path) -> "IdentityCipher":
        key_path = str(key_path)
        if os.path.exists(key_path):
            with open(key_path, "rb") as handle:
                key = handle.read()
            if len(key) != 32:
                raise ValueError("identity.key 长度必须为 32 字节")
        else:
            key = secrets.token_bytes(32)
            with open(key_path, "wb") as handle:
                handle.write(key)
            os.chmod(key_path, 0o600)
        return cls(key)

    def _keys(self) -> tuple[bytes, bytes]:
        return _hkdf(self.master_key, b"identity/v1/enc"), _hkdf(self.master_key, b"identity/v1/mac")

    def seal(self, plaintext: bytes) -> bytes:
        enc_key, mac_key = self._keys()
        nonce = secrets.token_bytes(12)
        ciphertext = chacha20_xor(enc_key, nonce, plaintext)
        body = b"V1" + nonce + ciphertext
        tag = hmac.new(mac_key, body, hashlib.sha256).digest()
        return body + tag

    def open(self, blob: bytes) -> bytes:
        enc_key, mac_key = self._keys()
        if len(blob) < 2 + 12 + 32 or blob[:2] != b"V1":
            raise ValueError("身份封存数据格式非法")
        body, tag = blob[:-32], blob[-32:]
        if not hmac.compare_digest(hmac.new(mac_key, body, hashlib.sha256).digest(), tag):
            raise ValueError("身份封存数据完整性校验失败")
        nonce, ciphertext = body[2:14], body[14:]
        return chacha20_xor(enc_key, nonce, ciphertext)
