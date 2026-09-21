"""敏感身份信息：加密封存 + 逐案逐人授权，与可公开摘要完全分开。"""

import json
import sqlite3

import timeutil
from auth import audit
from errors import ConflictError, NotFoundError, PermissionError, UnprocessableError
from security import IdentityCipher
from svc_common import get_case, require_writable_case, row_dict


def seal_identity(conn, actor, cipher: IdentityCipher, case_id: int, *,
                  label: str, data: dict) -> dict:
    require_writable_case(get_case(conn, case_id))
    if not isinstance(data, dict) or not data:
        raise UnprocessableError("身份数据必须是非空对象")
    if not label:
        raise UnprocessableError("label 不能为空")
    ts = timeutil.now_iso()
    blob = cipher.seal(json.dumps(data, ensure_ascii=False).encode("utf-8"))
    cur = conn.execute(
        "INSERT INTO identity_vault (label,ciphertext,created_at,created_by)"
        " VALUES (?,?,?,?)",
        (label, blob, ts, actor.display_name),
    )
    identity_id = cur.lastrowid
    conn.execute(
        "INSERT INTO case_identities (case_id,identity_id,linked_by,linked_at)"
        " VALUES (?,?,?,?)",
        (case_id, identity_id, actor.display_name, ts),
    )
    audit(conn, actor, "identity.seal", object_type="identity", object_id=identity_id,
          case_id=case_id, detail=f"label={label}")
    return {"identity_id": identity_id, "case_id": case_id, "label": label,
            "created_at": ts}


def list_case_identities(conn, actor, case_id: int) -> list[dict]:
    get_case(conn, case_id)
    rows = conn.execute(
        "SELECT v.id, v.label, v.created_at, v.created_by, ci.case_id"
        " FROM identity_vault v JOIN case_identities ci ON ci.identity_id=v.id"
        " WHERE ci.case_id=? ORDER BY v.id", (case_id,)
    ).fetchall()
    result = []
    for r in rows:
        item = row_dict(r)
        item["accessible"] = _active_grant_exists(conn, case_id, r["id"], actor.id)
        result.append(item)
    return result


def _active_grant_exists(conn, case_id, identity_id, user_id) -> bool:
    return conn.execute(
        "SELECT 1 FROM case_identity_grants WHERE case_id=? AND identity_id=? AND user_id=?"
        " AND revoked_at IS NULL",
        (case_id, identity_id, user_id),
    ).fetchone() is not None


def grant(conn, actor, case_id: int, identity_id: int, *, user_id: int) -> dict:
    require_writable_case(get_case(conn, case_id))
    if not conn.execute("SELECT 1 FROM case_identities WHERE case_id=? AND identity_id=?",
                        (case_id, identity_id)).fetchone():
        raise NotFoundError("该身份不属于此案件")
    user = conn.execute("SELECT id FROM users WHERE id=? AND active=1",
                        (user_id,)).fetchone()
    if user is None:
        raise NotFoundError("被授权人不存在或已停用")
    ts = timeutil.now_iso()
    existing = conn.execute(
        "SELECT id, revoked_at FROM case_identity_grants"
        " WHERE case_id=? AND identity_id=? AND user_id=?",
        (case_id, identity_id, user_id),
    ).fetchone()
    if existing is not None:
        if existing["revoked_at"] is None:
            raise ConflictError("授权仍有效，无需重复授予")
        # 授权历史保留：撤销后重新授予写新行
    cur = conn.execute(
        "INSERT INTO case_identity_grants (case_id,identity_id,user_id,granted_by,"
        "granted_at) VALUES (?,?,?,?,?)",
        (case_id, identity_id, user_id, actor.display_name, ts),
    )
    audit(conn, actor, "identity.grant", object_type="identity", object_id=identity_id,
          case_id=case_id, detail=f"granted_to_user={user_id}")
    return {"grant_id": cur.lastrowid, "identity_id": identity_id,
            "user_id": user_id, "granted_at": ts}


def revoke_grant(conn, actor, case_id: int, identity_id: int, *, user_id: int) -> dict:
    require_writable_case(get_case(conn, case_id))
    ts = timeutil.now_iso()
    cur = conn.execute(
        "UPDATE case_identity_grants SET revoked_at=? WHERE case_id=? AND identity_id=?"
        " AND user_id=? AND revoked_at IS NULL",
        (ts, case_id, identity_id, user_id),
    )
    if cur.rowcount == 0:
        raise NotFoundError("没有找到有效的授权记录")
    audit(conn, actor, "identity.grant_revoke", object_type="identity",
          object_id=identity_id, case_id=case_id, detail=f"user={user_id}")
    return {"identity_id": identity_id, "user_id": user_id, "revoked_at": ts}


def reveal(conn, actor, cipher: IdentityCipher, case_id: int, identity_id: int) -> dict:
    get_case(conn, case_id)
    if not _active_grant_exists(conn, case_id, identity_id, actor.id):
        audit(conn, actor, "identity.reveal_denied", object_type="identity",
              object_id=identity_id, case_id=case_id)
        raise PermissionError("未取得该敏感身份在本案的逐案授权")
    row = conn.execute("SELECT * FROM identity_vault WHERE id=?",
                       (identity_id,)).fetchone()
    if row is None:
        raise NotFoundError("身份记录不存在")
    data = json.loads(cipher.open(row["ciphertext"]).decode("utf-8"))
    audit(conn, actor, "identity.reveal", object_type="identity", object_id=identity_id,
          case_id=case_id)
    return {"identity_id": identity_id, "label": row["label"], "data": data,
            "created_by": row["created_by"], "created_at": row["created_at"]}
