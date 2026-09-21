"""案件服务：立案、期限、状态、待签收交接与结案归档。"""

import json
import sqlite3
from datetime import timedelta

import timeutil
from errors import ConflictError, NotFoundError
from svc_common import get_case, row_dict


def create_case(conn, actor, *, case_no, title, location=None, incident_at=None,
                deadline_days=30) -> dict:
    if conn.execute("SELECT 1 FROM cases WHERE case_no=?", (case_no,)).fetchone():
        raise ConflictError(f"案号 {case_no} 已存在")
    incident = timeutil.normalize(incident_at, "incident_at") if incident_at else None
    deadline = timeutil.format_dt(
        timeutil.now().replace(microsecond=0) + timedelta(days=int(deadline_days))
    )
    cur = conn.execute(
        "INSERT INTO cases (case_no,title,status,location,incident_at,reported_by,"
        "deadline,created_at,created_by) VALUES (?,?, 'open',?,?,?,?,?,?)",
        (case_no, title, location, incident, actor.display_name,
         deadline, timeutil.now_iso(), actor.display_name),
    )
    return get_case_view(conn, cur.lastrowid)


def list_cases(conn, actor, *, status=None) -> list[dict]:
    # 单位录入员不看案件列表（其权限以证据为限）
    rows = conn.execute(
        "SELECT * FROM cases" + (" WHERE status=?" if status else "") + " ORDER BY id DESC",
        ([status] if status else []),
    ).fetchall()
    return [row_dict(r) for r in rows]


def _pending_transfers(conn, case_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT pt.id, pt.evidence_id, pt.to_user_id, u.display_name AS to_user,"
        " pt.from_holder, pt.note, pt.created_at, pt.created_by, pt.status, pt.signed_at"
        " FROM pending_transfers pt JOIN users u ON u.id=pt.to_user_id"
        " JOIN evidence_links l ON l.evidence_id=pt.evidence_id"
        " WHERE l.case_id=? AND pt.status='pending'"
        " AND NOT EXISTS (SELECT 1 FROM link_revocations r"
        " WHERE r.target_type='evidence_link' AND r.target_id=l.id)"
        " ORDER BY pt.id",
        (case_id,),
    ).fetchall()
    return [row_dict(r) for r in rows]


def get_case_view(conn, case_id: int) -> dict:
    case = row_dict(get_case(conn, case_id))
    case["deadline_status"] = {
        "deadline": case["deadline"],
        "overdue": timeutil.is_overdue(case["deadline"]),
        "days_left": timeutil.days_left(case["deadline"]),
        "server_time": timeutil.now_iso(),
    }
    case["pending_transfers"] = _pending_transfers(conn, case_id)
    return case


def set_status(conn, case_id: int, status: str) -> None:
    conn.execute("UPDATE cases SET status=? WHERE id=?", (status, case_id))


def archive_case(conn, actor, case_id: int) -> dict:
    case = get_case(conn, case_id)
    if case["status"] == "archived":
        raise ConflictError("案件已归档")
    # 结案归档前必须已有生效的处罚决定（事实认定/告知/补证均不足以结案）
    decided = conn.execute(
        "SELECT 1 FROM decisions WHERE case_id=? AND kind='penalty_decision'"
        " AND superseded=0", (case_id,)
    ).fetchone()
    if not decided:
        raise ConflictError("尚未作出生效的处罚决定，不能结案归档")
    open_pending = conn.execute(
        "SELECT COUNT(*) AS c FROM pending_transfers pt"
        " JOIN evidence_links l ON l.evidence_id=pt.evidence_id"
        " WHERE l.case_id=? AND pt.status='pending'",
        (case_id,),
    ).fetchone()["c"]
    if open_pending:
        raise ConflictError("仍有待签收交接，不能结案归档")

    # 归档清单：固定案件全部证据摘要、决定与事实版本，生成整体指纹
    manifest = _build_manifest(conn, case_id)
    archive_ref = f"ARCH-{case['case_no']}-{timeutil.now().strftime('%Y%m%d%H%M%S')}"
    conn.execute(
        "UPDATE cases SET status='archived', archived_at=?, archive_ref=?,"
        " archive_manifest=? WHERE id=?",
        (timeutil.now_iso(), archive_ref, json.dumps(manifest, ensure_ascii=False), case_id),
    )
    result = row_dict(get_case(conn, case_id))
    result["manifest"] = manifest
    return result


def _build_manifest(conn, case_id: int) -> dict:
    links = conn.execute(
        "SELECT l.evidence_id AS eid FROM evidence_links l WHERE l.case_id=?"
        " AND NOT EXISTS (SELECT 1 FROM link_revocations r"
        " WHERE r.target_type='evidence_link' AND r.target_id=l.id)",
        (case_id,),
    ).fetchall()
    evidences = []
    for link in links:
        row = conn.execute(
            "SELECT id, kind, source_unit, collected_at, received_at, registered_at,"
            " digest_alg, digest, size_bytes, status FROM evidence WHERE id=?",
            (link["eid"],),
        ).fetchone()
        evidences.append(row_dict(row))

    decisions = [row_dict(r) for r in conn.execute(
        "SELECT id, kind, seq, rule_id, fact_version, made_at, superseded"
        " FROM decisions WHERE case_id=? ORDER BY seq", (case_id,)
    ).fetchall()]
    facts = [row_dict(r) for r in conn.execute(
        "SELECT version, based_on, author, created_at FROM fact_versions"
        " WHERE case_id=? ORDER BY version", (case_id,)
    ).fetchall()]

    canonical = json.dumps(
        {"evidences": evidences, "decisions": decisions, "facts": facts},
        ensure_ascii=False, sort_keys=True,
    )
    import hashlib
    return {
        "case_id": case_id,
        "generated_at": timeutil.now_iso(),
        "evidence_count": len(evidences),
        "items": {"evidences": evidences, "decisions": decisions, "facts": facts},
        "manifest_digest": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def verify_archive(conn, case_id: int) -> dict:
    case = get_case(conn, case_id)
    if not case["archive_manifest"]:
        raise ConflictError("案件未归档")
    stored = json.loads(case["archive_manifest"])
    current = _build_manifest(conn, case_id)
    return {
        "archive_ref": case["archive_ref"],
        "stored_digest": stored["manifest_digest"],
        "current_digest": current["manifest_digest"],
        "intact": stored["manifest_digest"] == current["manifest_digest"],
    }
