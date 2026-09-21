"""证据服务。

入库即固定：摘要、来源、采集时间（来源口径，仅格式归一）、接收时间（服务器时钟）、
保管起始人。原件内容寻址只追加。查看/下载写审计与保管链。
"""

import json
import sqlite3

import timeutil
from auth import audit
from errors import ConflictError, NotFoundError, PermissionError, UnprocessableError
from svc_common import (active_link, can_access_evidence, ensure_evidence_access,
                        evidence_payload, get_case, require_writable_case, row_dict)
from storage import BlobStore

KINDS = {"video", "remote_id", "record", "other"}


# ---- 入库 -------------------------------------------------------------------

def intake_evidence(conn, actor, store: BlobStore, stream, *, case_id: int, kind: str,
                    source_unit: str, collected_at: str, media_type: str,
                    source_reference=None, note=None) -> dict:
    if kind not in KINDS:
        raise UnprocessableError(f"kind 必须是 {sorted(KINDS)} 之一")
    case = get_case(conn, case_id)
    require_writable_case(case)
    collected = timeutil.normalize(collected_at, "collected_at")
    registered = timeutil.now_iso()
    # 接收时间：流到达服务的服务器时钟；不接受客户端指定，防止口径被统一改写
    received = registered
    digest, size, existed = store.put_stream(stream)

    cur = conn.execute(
        "INSERT INTO evidence (intake_case_id,kind,source_unit,source_reference,"
        "collected_at,received_at,registered_at,media_type,size_bytes,digest_alg,"
        "digest,blob_path,registered_by,intaker_user_id)"
        " VALUES (?,?,?,?,?,?,?,?,?, 'sha256',?,?,?,?)",
        (case_id, kind, source_unit, source_reference, collected, received, registered,
         media_type, size, digest, f"blobs/{digest[:2]}/{digest[2:4]}/{digest}",
         actor.display_name, actor.id if actor.role == "intaker" else None),
    )
    evidence_id = cur.lastrowid
    conn.execute(
        "INSERT INTO evidence_links (evidence_id,case_id,linked_by,linked_by_id,linked_at)"
        " VALUES (?,?,?,?,?)",
        (evidence_id, case_id, actor.display_name, actor.id, registered),
    )
    conn.execute(
        "INSERT INTO custody_events (evidence_id,action,actor,actor_id,from_holder,"
        "to_holder,note,occurred_at) VALUES (?, 'intake',?,?,NULL,?,?,?)",
        (evidence_id, actor.display_name, actor.id, source_unit, note, registered),
    )
    audit(conn, actor, "evidence.intake", object_type="evidence", object_id=evidence_id,
          case_id=case_id, detail=json.dumps(
              {"digest": digest, "size": size, "dedup_hit": existed,
               "collected_at": collected}, ensure_ascii=False))
    return evidence_payload(conn, _must_get(conn, evidence_id))


def _must_get(conn, evidence_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"证据 {evidence_id} 不存在")
    return row


def get_evidence(conn, actor, evidence_id: int, *, for_download=False, request_ip=None) -> dict:
    row = _must_get(conn, evidence_id)
    ensure_evidence_access(actor, row)
    action = "evidence.download" if for_download else "evidence.view"
    audit(conn, actor, action, object_type="evidence", object_id=evidence_id,
          case_id=row["intake_case_id"], request_ip=request_ip)
    if for_download:
        conn.execute(
            "INSERT INTO custody_events (evidence_id,action,actor,actor_id,note,"
            "occurred_at) SELECT ?, 'download',?,?,?,?",
            (evidence_id, actor.display_name, actor.id, "下载调阅", timeutil.now_iso()),
        )
    else:
        conn.execute(
            "INSERT INTO custody_events (evidence_id,action,actor,actor_id,note,occurred_at)"
            " VALUES (?, 'inspect',?,?,?,?)",
            (evidence_id, actor.display_name, actor.id, "在线查看", timeutil.now_iso()),
        )
    return evidence_payload(conn, row)


def open_blob(conn, actor, store: BlobStore, evidence_id: int, request_ip=None):
    row = _must_get(conn, evidence_id)
    ensure_evidence_access(actor, row)
    # 已作废原件不对普通调阅开放，审计员可凭 audit:read 调阅核验
    if row["status"] == "voided" and not actor.has("audit:read"):
        raise ConflictError("证据已作废，不能下载；如需核验请由审计角色调阅")
    get_evidence(conn, actor, evidence_id, for_download=True, request_ip=request_ip)
    return row, store.open_read(row["digest"])


def list_case_evidence(conn, actor, case_id: int) -> list[dict]:
    get_case(conn, case_id)
    rows = conn.execute(
        "SELECT e.* FROM evidence e JOIN evidence_links l ON l.evidence_id=e.id"
        " WHERE l.case_id=? AND NOT EXISTS (SELECT 1 FROM link_revocations r"
        " WHERE r.target_type='evidence_link' AND r.target_id=l.id) ORDER BY e.id",
        (case_id,),
    ).fetchall()
    out = []
    for row in rows:
        if can_access_evidence(actor, row):
            out.append(evidence_payload(conn, row))
    return out


# ---- 错误关联撤销 / 重新关联 -------------------------------------------------

def revoke_link(conn, actor, evidence_id: int, *, reason: str) -> dict:
    row = _must_get(conn, evidence_id)
    link = active_link(conn, evidence_id)
    if link is None:
        raise ConflictError("该证据当前没有有效关联")
    case = get_case(conn, link["case_id"])
    require_writable_case(case)
    ts = timeutil.now_iso()
    cur = conn.execute(
        "INSERT INTO link_revocations (case_id,target_type,target_id,reason,revoked_by,"
        "revoked_by_id,revoked_at) VALUES (?, 'evidence_link',?,?,?,?,?)",
        (link["case_id"], link["id"], reason, actor.display_name, actor.id, ts),
    )
    conn.execute(
        "INSERT INTO custody_events (evidence_id,action,actor,actor_id,from_holder,to_holder,"
        "note,occurred_at) VALUES (?, 'transfer',?,?,?,?,?,?)",
        (evidence_id, actor.display_name, actor.id, case["case_no"], None,
         f"撤销与案件关联：{reason}", ts),
    )
    audit(conn, actor, "evidence.link_revoke", object_type="evidence_link",
          object_id=link["id"], case_id=link["case_id"], detail=reason)
    return {"revocation_id": cur.lastrowid, "evidence_id": evidence_id,
            "from_case_id": link["case_id"], "revoked_at": ts}


def relink(conn, actor, evidence_id: int, *, to_case_id: int, note=None) -> dict:
    row = _must_get(conn, evidence_id)
    ensure_evidence_access(actor, row)
    if active_link(conn, evidence_id) is not None:
        raise ConflictError("证据仍有有效关联，请先撤销原关联")
    target = get_case(conn, to_case_id)
    require_writable_case(target)
    ts = timeutil.now_iso()
    cur = conn.execute(
        "INSERT INTO evidence_links (evidence_id,case_id,linked_by,linked_by_id,linked_at)"
        " VALUES (?,?,?,?,?)",
        (evidence_id, to_case_id, actor.display_name, actor.id, ts),
    )
    conn.execute(
        "INSERT INTO custody_events (evidence_id,action,actor,actor_id,from_holder,to_holder,"
        "note,occurred_at) VALUES (?, 'transfer',?,?,NULL,?,?,?)",
        (evidence_id, actor.display_name, actor.id, target["case_no"], note, ts),
    )
    audit(conn, actor, "evidence.relink", object_type="evidence_link",
          object_id=cur.lastrowid, case_id=to_case_id, detail=note)
    return {"link_id": cur.lastrowid, "evidence_id": evidence_id,
            "case_id": to_case_id, "linked_at": ts}


# ---- 作废（追加标记，不删原件） ----------------------------------------------

def void_evidence(conn, actor, evidence_id: int, *, reason: str) -> dict:
    row = _must_get(conn, evidence_id)
    ensure_evidence_access(actor, row)
    link = active_link(conn, evidence_id)
    if link is not None:
        require_writable_case(get_case(conn, link["case_id"]))
    if row["status"] == "voided":
        raise ConflictError("证据已处于作废状态")
    ts = timeutil.now_iso()
    conn.execute(
        "INSERT INTO void_marks (evidence_id,reason,marked_by,marked_at) VALUES (?,?,?,?)",
        (evidence_id, reason, actor.display_name, ts),
    )
    # 触发器只放行 sealed->voided 且其他列原样
    conn.execute("UPDATE evidence SET status='voided' WHERE id=?", (evidence_id,))
    conn.execute(
        "INSERT INTO custody_events (evidence_id,action,actor,actor_id,note,occurred_at)"
        " VALUES (?, 'void',?,?,?,?)",
        (evidence_id, actor.display_name, actor.id, reason, ts),
    )
    audit(conn, actor, "evidence.void", object_type="evidence", object_id=evidence_id,
          case_id=link["case_id"] if link else row["intake_case_id"], detail=reason)
    return evidence_payload(conn, _must_get(conn, evidence_id))


# ---- 保管交接：发起转交（持久化待签收）与签收 -------------------------------

def transfer(conn, actor, evidence_id: int, *, to_user_id: int, note=None) -> dict:
    row = _must_get(conn, evidence_id)
    ensure_evidence_access(actor, row)
    link = active_link(conn, evidence_id)
    if link is None:
        raise ConflictError("证据未关联到案件，不能发起交接")
    require_writable_case(get_case(conn, link["case_id"]))
    to_user = conn.execute("SELECT * FROM users WHERE id=? AND active=1",
                           (to_user_id,)).fetchone()
    if to_user is None:
        raise NotFoundError("接收人不存在或已停用")
    ts = timeutil.now_iso()
    cur = conn.execute(
        "INSERT INTO pending_transfers (evidence_id,to_user_id,from_holder,note,"
        "created_at,created_by,status) VALUES (?,?,?,?,?,?,'pending')",
        (evidence_id, to_user_id, actor.display_name, note, ts, actor.display_name),
    )
    conn.execute(
        "INSERT INTO custody_events (evidence_id,action,actor,actor_id,to_holder,note,"
        "occurred_at) VALUES (?, 'transfer',?,?,?,?,?)",
        (evidence_id, actor.display_name, actor.id, to_user["display_name"],
         f"发起交接待签收：{note or ''}", ts),
    )
    audit(conn, actor, "custody.transfer_create", object_type="pending_transfer",
          object_id=cur.lastrowid, case_id=link["case_id"],
          detail=f"to={to_user['display_name']}")
    return {"transfer_id": cur.lastrowid, "evidence_id": evidence_id,
            "to_user_id": to_user_id, "status": "pending", "created_at": ts}


def sign_transfer(conn, actor, transfer_id: int) -> dict:
    t = conn.execute("SELECT * FROM pending_transfers WHERE id=?",
                     (transfer_id,)).fetchone()
    if t is None:
        raise NotFoundError("交接单不存在")
    if t["to_user_id"] != actor.id:
        raise PermissionError("只有指定接收人本人可以签收")
    if t["status"] != "pending":
        raise ConflictError(f"交接单状态为 {t['status']}，不能签收")
    ts = timeutil.now_iso()
    conn.execute(
        "UPDATE pending_transfers SET status='signed', signed_at=? WHERE id=?",
        (ts, transfer_id),
    )
    conn.execute(
        "INSERT INTO custody_events (evidence_id,action,actor,actor_id,from_holder,"
        "to_holder,note,occurred_at) VALUES (?, 'receive_sign',?,?,?,?, '签收接收',?)",
        (t["evidence_id"], actor.display_name, actor.id, t["created_by"],
         actor.display_name, ts),
    )
    audit(conn, actor, "custody.sign", object_type="pending_transfer",
          object_id=transfer_id, detail=None)
    return {"transfer_id": transfer_id, "status": "signed", "signed_at": ts}


def pending_for_user(conn, actor) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM pending_transfers WHERE to_user_id=? AND status='pending'"
        " ORDER BY id", (actor.id,)
    ).fetchall()
    return [row_dict(r) for r in rows]


def custody_chain(conn, actor, evidence_id: int) -> list[dict]:
    row = _must_get(conn, evidence_id)
    ensure_evidence_access(actor, row)
    audit(conn, actor, "custody.chain_view", object_type="evidence",
          object_id=evidence_id)
    rows = conn.execute(
        "SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id", (evidence_id,)
    ).fetchall()
    return [row_dict(r) for r in rows]


# ---- 可公开摘要：独立授权、追加版本 ------------------------------------------

def add_public_summary(conn, actor, evidence_id: int, *, content: str) -> dict:
    row = _must_get(conn, evidence_id)
    ensure_evidence_access(actor, row)
    link = active_link(conn, evidence_id)
    if link is not None:
        require_writable_case(get_case(conn, link["case_id"]))
    if not content or not content.strip():
        raise UnprocessableError("摘要内容不能为空")
    last = conn.execute(
        "SELECT COALESCE(MAX(version),0) AS v FROM public_summaries WHERE evidence_id=?",
        (evidence_id,),
    ).fetchone()["v"]
    ts = timeutil.now_iso()
    conn.execute(
        "INSERT INTO public_summaries (evidence_id,version,content,created_by,"
        "created_by_id,created_at) VALUES (?,?,?,?,?,?)",
        (evidence_id, last + 1, content, actor.display_name, actor.id, ts),
    )
    audit(conn, actor, "public_summary.add", object_type="evidence",
          object_id=evidence_id, detail=f"v{last+1}")
    return {"evidence_id": evidence_id, "version": last + 1, "content": content,
            "created_by": actor.display_name, "created_at": ts}


def public_summary_view(conn, evidence_id: int) -> dict:
    """无需 identity 授权即可查看的脱敏视图；不返回原件任何字节。"""
    row = conn.execute(
        "SELECT ps.version, ps.content, ps.created_by, ps.created_at,"
        " e.kind, e.source_unit, e.collected_at, e.received_at, e.status, e.digest"
        " FROM public_summaries ps JOIN evidence e ON e.id=ps.evidence_id"
        " WHERE ps.evidence_id=? ORDER BY ps.version DESC LIMIT 1",
        (evidence_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("该证据尚无公开摘要")
    return row_dict(row)
