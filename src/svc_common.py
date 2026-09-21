"""服务层公共辅助。"""

import sqlite3

from errors import ConflictError, NotFoundError, PermissionError


def row_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def get_case(conn: sqlite3.Connection, case_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"案件 {case_id} 不存在")
    return row


def require_writable_case(case: sqlite3.Row) -> None:
    if case["status"] == "archived":
        raise ConflictError(f"案件 {case['case_no']} 已归档封存，不得再变更")


def active_link(conn: sqlite3.Connection, evidence_id: int,
                case_id: int | None = None) -> sqlite3.Row | None:
    """返回证据当前有效的关联（无撤销记录）。"""
    sql = (
        "SELECT l.* FROM evidence_links l WHERE l.evidence_id = ?"
        " AND NOT EXISTS (SELECT 1 FROM link_revocations r"
        " WHERE r.target_type='evidence_link' AND r.target_id=l.id)"
    )
    params: list = [evidence_id]
    if case_id is not None:
        sql += " AND l.case_id = ?"
        params.append(case_id)
    return conn.execute(sql, params).fetchone()


def next_seq(conn: sqlite3.Connection, case_id: int) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(seq),0)+1 AS s FROM decisions WHERE case_id=?", (case_id,)
    ).fetchone()
    return int(row["s"])


def can_access_evidence(actor, evidence: sqlite3.Row) -> bool:
    """单位录入员只能访问本人提交的材料；其他角色按 scope 与案件关联控制。"""
    if actor.role == "intaker":
        return evidence["intaker_user_id"] == actor.id
    return True


def ensure_evidence_access(actor, evidence: sqlite3.Row) -> None:
    if not can_access_evidence(actor, evidence):
        raise PermissionError("录入单位只能访问本单位用户本人登记的材料")


def evidence_payload(conn, row: sqlite3.Row) -> dict:
    data = row_dict(row)
    mark = conn.execute(
        "SELECT reason, marked_by, marked_at FROM void_marks WHERE evidence_id=?"
        " ORDER BY id DESC LIMIT 1", (row["id"],)
    ).fetchone()
    data["void_mark"] = row_dict(mark)
    link = active_link(conn, row["id"])
    data["active_case_id"] = link["case_id"] if link else None
    latest_summary = conn.execute(
        "SELECT version, content, created_by, created_at FROM public_summaries"
        " WHERE evidence_id=? ORDER BY version DESC LIMIT 1", (row["id"],)
    ).fetchone()
    data["public_summary"] = row_dict(latest_summary)
    return data
