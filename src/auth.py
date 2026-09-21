"""API Key 认证与请求上下文。"""

import sqlite3

from errors import AuthError, PermissionError
from security import ROLE_SCOPES, hash_key
import timeutil


class Actor:
    def __init__(self, row: sqlite3.Row):
        self.id = row["id"]
        self.username = row["username"]
        self.display_name = row["display_name"]
        self.role = row["role"]
        self.scopes = ROLE_SCOPES.get(row["role"], set())

    def require(self, scope: str) -> None:
        if scope not in self.scopes:
            raise PermissionError(f"角色 {self.role} 缺少权限 {scope}")

    def has(self, scope: str) -> bool:
        return scope in self.scopes


def authenticate(conn: sqlite3.Connection, key: str | None) -> Actor:
    if not key:
        raise AuthError("缺少 X-API-Key 凭据")
    row = conn.execute(
        "SELECT * FROM users WHERE key_hash = ? AND active = 1", (hash_key(key),)
    ).fetchone()
    if row is None:
        raise AuthError("凭据无效或已停用")
    return Actor(row)


def create_user(conn, username, display_name, role, created_by: str) -> tuple[int, str]:
    """签发新用户，返回 (id, 明文key)；明文 key 只在这一次响应中出现。"""
    if role not in ROLE_SCOPES:
        raise ValueError(f"未知角色: {role}")
    from security import generate_key
    plain = generate_key()
    cur = conn.execute(
        "INSERT INTO users (username, display_name, role, key_hash, created_at, created_by)"
        " VALUES (?,?,?,?,?,?)",
        (username, display_name, role, hash_key(plain), timeutil.now_iso(), created_by),
    )
    return cur.lastrowid, plain


def audit(conn, actor: Actor | None, action: str, *, object_type=None, object_id=None,
          case_id=None, detail=None, request_ip=None) -> None:
    conn.execute(
        "INSERT INTO audit_log (actor, actor_id, action, object_type, object_id, case_id,"
        " detail, occurred_at, request_ip) VALUES (?,?,?,?,?,?,?,?,?)",
        (
            actor.display_name if actor else "anonymous",
            actor.id if actor else None,
            action, object_type, object_id, case_id,
            detail, timeutil.now_iso(), request_ip,
        ),
    )
