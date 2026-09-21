"""认定结论与程序决定：作出时固定引用，结论可沿引用图完整溯源。

程序不倒置原则：
- 决定作出时把规则 id、事实版本号、证据 id 集合写死在 decision_refs；
  此后规则更新、事实再改版、证据补交或撤销关联，都不改写历史决定。
- 补交材料只出现在其登记之后的新决定引用里；溯源时把“决定之后才出现的材料”
  单独列出并标注 never_basis=true。
- 错误结论只能置 superseded 并留撤销记录，不能删除。
"""

import json
import sqlite3

import timeutil
from auth import audit
from errors import ConflictError, NotFoundError, UnprocessableError
from svc_cases import set_status
from svc_common import active_link, get_case, require_writable_case, row_dict
from svc_rules import get_rule, rule_applicable_at
import svc_facts

DECISION_KINDS = {"finding", "supplement_notice", "penalty_notice",
                  "penalty_decision", "closure"}


def _add_ref(conn, decision_id, ref_type, ref_id, note=None):
    conn.execute(
        "INSERT INTO decision_refs (decision_id,ref_type,ref_id,note,created_at)"
        " VALUES (?,?,?,?,?)",
        (decision_id, ref_type, ref_id, note, timeutil.now_iso()),
    )


def _refs(conn, decision_id: int, ref_type: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM decision_refs WHERE decision_id=? AND ref_type=? ORDER BY id",
        (decision_id, ref_type),
    ).fetchall()


def create_decision(conn, actor, case_id: int, body: dict) -> dict:
    kind = body.get("kind")
    if kind not in DECISION_KINDS:
        raise UnprocessableError(f"kind 必须是 {sorted(DECISION_KINDS)} 之一")
    case = get_case(conn, case_id)
    require_writable_case(case)

    title = (body.get("title") or "").strip()
    content = body.get("content")
    if not title:
        raise UnprocessableError("title 不能为空")
    if not isinstance(content, str) or not content.strip():
        raise UnprocessableError("content 不能为空")

    # 程序前置条件优先校验（缺前序决定属于冲突 409，而不是请求格式问题）
    _check_procedure(conn, case_id, kind)

    ts = timeutil.now_iso()

    # 事实版本：默认固定为当前最新；显式指定时必须属于本案
    fact_version = body.get("fact_version")
    if fact_version is None:
        fact_version = svc_facts.current_version(conn, case_id)
    fact_version = int(fact_version)
    if fact_version <= 0:
        raise UnprocessableError("作出决定前必须先有事实清单版本")
    fv = conn.execute(
        "SELECT 1 FROM fact_versions WHERE case_id=? AND version=?",
        (case_id, fact_version),
    ).fetchone()
    if fv is None:
        raise UnprocessableError(f"事实版本 v{fact_version} 不属于本案")

    # 规则：存在性 + 对事发时点是否适用
    rule_id = body.get("rule_id")
    if rule_id is not None:
        rule_id = int(rule_id)
        rule = get_rule(rule_id, conn)
        if case["incident_at"]:
            if not rule_applicable_at(conn, rule_id, case["incident_at"]):
                raise UnprocessableError(
                    f"规则 {rule['rule_code']} 在事发时间 {case['incident_at']} 尚未生效，"
                    "不能作为认定依据")
        # 若规则已被新版本取代但事发时适用，仍允许，溯源会提示当前已有新版

    # 证据引用：决定作出时必须有效关联本案且未作废
    evidence_ids = body.get("evidence_ids") or []
    if not isinstance(evidence_ids, list) or not all(isinstance(x, int) for x in evidence_ids):
        raise UnprocessableError("evidence_ids 必须是整数数组")
    resolved = []
    for eid in dict.fromkeys(evidence_ids):  # 去重保序
        ev = conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
        if ev is None:
            raise UnprocessableError(f"证据 {eid} 不存在")
        link = active_link(conn, eid, case_id)
        if link is None:
            raise UnprocessableError(f"证据 {eid} 当前未有效关联到本案，不能引用")
        if ev["status"] == "voided":
            raise UnprocessableError(f"证据 {eid} 已作废，不能作为认定依据")
        resolved.append(ev)

    prior_ids = body.get("prior_decision_ids") or []
    if not isinstance(prior_ids, list):
        raise UnprocessableError("prior_decision_ids 必须是数组")
    for pid in prior_ids:
        prior = conn.execute("SELECT * FROM decisions WHERE id=? AND case_id=?",
                             (int(pid), case_id)).fetchone()
        if prior is None:
            raise UnprocessableError(f"前序决定 {pid} 不存在或不属于本案")
        if prior["superseded"]:
            raise UnprocessableError(f"前序决定 {pid} 已被撤销，不能作为程序依据")

    seq = int(conn.execute(
        "SELECT COALESCE(MAX(seq),0)+1 AS s FROM decisions WHERE case_id=?", (case_id,)
    ).fetchone()["s"])
    cur = conn.execute(
        "INSERT INTO decisions (case_id,kind,title,content,rule_id,fact_version,seq,"
        "made_by,made_by_id,made_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (case_id, kind, title, content, rule_id, fact_version, seq,
         actor.display_name, actor.id, ts),
    )
    decision_id = cur.lastrowid
    _add_ref(conn, decision_id, "fact_version", fact_version)
    if rule_id is not None:
        _add_ref(conn, decision_id, "rule", rule_id)
    for ev in resolved:
        _add_ref(conn, decision_id, "evidence", ev["id"])
    for pid in prior_ids:
        _add_ref(conn, decision_id, "prior_decision", int(pid))

    # 程序状态联动
    if kind == "supplement_notice":
        conn.execute(
            "INSERT INTO supplements (case_id,decision_id,reason,requested_by,"
            "requested_at,due_at) VALUES (?,?,?,?,?,?)",
            (case_id, decision_id, body.get("supplement_reason") or title,
             actor.display_name, ts,
             timeutil.format_dt(timeutil.parse_iso(ts) + _supplement_window(body))),
        )
        set_status(conn, case_id, "supplementing")
    elif kind == "penalty_decision":
        set_status(conn, case_id, "decided")

    audit(conn, actor, f"decision.create.{kind}", object_type="decision",
          object_id=decision_id, case_id=case_id,
          detail=json.dumps({"rule_id": rule_id, "fact_version": fact_version,
                             "evidence": evidence_ids, "prior": prior_ids},
                            ensure_ascii=False))
    return get_decision(conn, decision_id)


def _supplement_window(body) :
    from datetime import timedelta
    return timedelta(days=int(body.get("supplement_due_days", 7)))


def _check_procedure(conn, case_id, kind):
    def exists(kind_name, include_superseded=False):
        sql = "SELECT 1 FROM decisions WHERE case_id=? AND kind=?"
        if not include_superseded:
            sql += " AND superseded=0"
        return conn.execute(sql, (case_id, kind_name)).fetchone() is not None

    if kind == "finding":
        return
    if kind == "penalty_notice" and not exists("finding"):
        raise ConflictError("缺少有效的事实认定结论，不能发出处罚事先告知")
    if kind == "penalty_decision":
        if not exists("penalty_notice"):
            raise ConflictError("缺少处罚事先告知，不能作出处罚决定")
        if not exists("finding"):
            raise ConflictError("缺少有效的事实认定结论")
    if kind == "closure" and not exists("penalty_decision"):
        raise ConflictError("缺少处罚决定，不能结案")


def get_decision(conn, decision_id: int) -> dict:
    row = conn.execute("SELECT * FROM decisions WHERE id=?",
                       (decision_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"决定 {decision_id} 不存在")
    data = row_dict(row)
    data["refs"] = {
        "evidence": [r["ref_id"] for r in _refs(conn, decision_id, "evidence")],
        "fact_version": [r["ref_id"] for r in _refs(conn, decision_id, "fact_version")],
        "rule": [r["ref_id"] for r in _refs(conn, decision_id, "rule")],
        "prior_decision": [r["ref_id"] for r in _refs(conn, decision_id, "prior_decision")],
        "identity": [r["ref_id"] for r in _refs(conn, decision_id, "identity")],
    }
    return data


def list_case_decisions(conn, case_id: int, *, include_superseded=True) -> list[dict]:
    get_case(conn, case_id)
    sql = "SELECT * FROM decisions WHERE case_id=?"
    if not include_superseded:
        sql += " AND superseded=0"
    sql += " ORDER BY seq"
    return [row_dict(r) for r in conn.execute(sql, (case_id,)).fetchall()]


def supersede_decision(conn, actor, decision_id: int, *, reason: str) -> dict:
    """撤销错误结论：原记录保留并标记，留撤销原因与经办人。"""
    row = conn.execute("SELECT * FROM decisions WHERE id=?",
                       (decision_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"决定 {decision_id} 不存在")
    if row["superseded"]:
        raise ConflictError("该决定已被撤销")
    case = get_case(conn, row["case_id"])
    require_writable_case(case)

    # 有后续有效决定以其为程序依据时，必须先撤销后续决定，防止链条悬空
    dependents = conn.execute(
        "SELECT d.id, d.kind FROM decisions d JOIN decision_refs r"
        " ON r.decision_id=d.id WHERE r.ref_type='prior_decision' AND r.ref_id=?"
        " AND d.superseded=0 ORDER BY d.id",
        (decision_id,),
    ).fetchall()
    if dependents:
        raise ConflictError(
            "该决定仍被后续有效决定引用，须先撤销后续决定："
            + ", ".join(f"#{d['id']}({d['kind']})" for d in dependents),
            code="decision_has_dependents",
        )

    ts = timeutil.now_iso()
    conn.execute(
        "UPDATE decisions SET superseded=1, superseded_reason=?, superseded_at=?"
        " WHERE id=?",
        (reason, ts, decision_id),
    )
    cur = conn.execute(
        "INSERT INTO link_revocations (case_id,target_type,target_id,reason,revoked_by,"
        "revoked_by_id,revoked_at) VALUES (?, 'decision',?,?,?,?,?)",
        (row["case_id"], decision_id, reason, actor.display_name, actor.id, ts),
    )
    audit(conn, actor, "decision.supersede", object_type="decision",
          object_id=decision_id, case_id=row["case_id"], detail=reason)
    return {"decision_id": decision_id, "superseded": 1, "reason": reason,
            "revoked_at": ts, "revocation_id": cur.lastrowid}


# ---- 溯源 --------------------------------------------------------------------

def trace(conn, decision_id: int) -> dict:
    """从一条认定结论出发，还原当时适用的规则、事实版本、完整证据链、
    经办人、程序前序与变更记录；并单列决定之后才出现、不能作为其依据的材料。"""
    root = conn.execute("SELECT * FROM decisions WHERE id=?",
                        (decision_id,)).fetchone()
    if root is None:
        raise NotFoundError(f"决定 {decision_id} 不存在")

    visited: set[int] = set()
    prior_chain: list[dict] = []

    def walk(did: int):
        if did in visited:
            return
        visited.add(did)
        for r in _refs(conn, did, "prior_decision"):
            pr = conn.execute("SELECT * FROM decisions WHERE id=?",
                              (r["ref_id"],)).fetchone()
            prior_chain.append(_decision_brief(pr))
            walk(r["ref_id"])

    walk(decision_id)

    # 规则（作出时固定指针）
    rule_view = None
    if root["rule_id"] is not None:
        rule = get_rule(root["rule_id"], conn)
        rule_view = row_dict(rule)
        case = get_case(conn, root["case_id"])
        rule_view["applicable_at_incident"] = (
            rule_applicable_at(conn, rule["id"], case["incident_at"])
            if case["incident_at"] else None
        )
        rule_view["has_newer_version"] = rule["effective_to"] is not None
        rule_view["note"] = (
            "该规则在结论作出后已有新版本，但历史结论仍指向当时适用版本"
            if rule["effective_to"] else "当前仍为有效版本"
        )

    # 事实版本快照
    fact_view = None
    if root["fact_version"]:
        fv = conn.execute(
            "SELECT * FROM fact_versions WHERE case_id=? AND version=?",
            (root["case_id"], root["fact_version"]),
        ).fetchone()
        if fv is not None:
            fact_view = row_dict(fv)
            fact_view["content"] = json.loads(fact_view["content"])
            fact_view["is_current"] = (
                svc_facts.current_version(conn, root["case_id"]) == fv["version"]
            )

    # 证据链：固定引用集合 + 每件的保管链与当前状态（事后变化只作标注）
    evidence_chain = []
    for r in _refs(conn, decision_id, "evidence"):
        ev = conn.execute("SELECT * FROM evidence WHERE id=?",
                          (r["ref_id"],)).fetchone()
        item = row_dict(ev)
        item["custody_chain"] = [
            row_dict(c) for c in conn.execute(
                "SELECT id,action,actor,from_holder,to_holder,note,occurred_at"
                " FROM custody_events WHERE evidence_id=? ORDER BY id",
                (ev["id"],),
            ).fetchall()
        ]
        revocation = conn.execute(
            "SELECT * FROM link_revocations WHERE target_type='evidence_link'"
            " AND target_id IN (SELECT id FROM evidence_links WHERE evidence_id=?)"
            " ORDER BY id DESC LIMIT 1",
            (ev["id"],),
        ).fetchone()
        item["later_voided"] = ev["status"] == "voided"
        item["later_link_revoked"] = row_dict(revocation)
        evidence_chain.append(item)

    # 经办人：决定经办人 + 事实版本作者 + 证据入库/各环节保管经办人
    handlers = [{"role": "decision_maker", "name": root["made_by"],
                 "at": root["made_at"]}]
    if fact_view is not None:
        handlers.append({"role": "fact_author", "version": fact_view["version"],
                         "name": fact_view["author"], "at": fact_view["created_at"]})
    for item in evidence_chain:
        for c in item["custody_chain"]:
            handlers.append({"role": f"custody:{c['action']}",
                             "evidence_id": item["id"], "name": c["actor"],
                             "at": c["occurred_at"], "note": c["note"]})

    # 变更记录：本决定撤销信息 + 所引证据/事实/规则的事后变化
    changes = []
    if root["superseded"]:
        changes.append({"type": "decision_superseded",
                        "reason": root["superseded_reason"],
                        "at": root["superseded_at"]})
    if fact_view is not None and not fact_view["is_current"]:
        changes.append({"type": "fact_advanced_after_decision",
                        "used_version": fact_view["version"],
                        "current_version": svc_facts.current_version(
                            conn, root["case_id"])})
    for item in evidence_chain:
        if item["later_voided"]:
            changes.append({"type": "evidence_voided_after_decision",
                            "evidence_id": item["id"]})
        if item["later_link_revoked"]:
            changes.append({"type": "evidence_link_revoked_after_decision",
                            "evidence_id": item["id"],
                            "reason": item["later_link_revoked"]["reason"],
                            "at": item["later_link_revoked"]["revoked_at"]})

    # 补交材料：决定作出之后才接收到本案的证据，标注从未成为本决定依据。
    # 以 intake_case_id 限定，避免跨案重新关联的材料误入本案溯源。
    later_materials = [
        row_dict(e) for e in conn.execute(
            "SELECT id,kind,source_unit,received_at,status FROM evidence"
            " WHERE intake_case_id=? AND received_at > ? ORDER BY received_at",
            (root["case_id"], root["made_at"]),
        ).fetchall()
    ]
    for m in later_materials:
        m["never_basis"] = True
        m["note"] = "决定作出后才接收，不能倒置为该决定的依据"

    supplements = [
        row_dict(s) for s in conn.execute(
            "SELECT * FROM supplements WHERE case_id=? ORDER BY id",
            (root["case_id"],),
        ).fetchall()
    ]

    return {
        "decision": _decision_brief(root),
        "rule_at_time": rule_view,
        "fact_version_at_time": fact_view,
        "evidence_chain": evidence_chain,
        "prior_decisions": prior_chain,
        "handlers": handlers,
        "change_history": changes,
        "supplements": supplements,
        "later_materials_not_basis": later_materials,
    }


def _decision_brief(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"], "case_id": row["case_id"], "kind": row["kind"],
        "title": row["title"], "seq": row["seq"],
        "made_by": row["made_by"], "made_at": row["made_at"],
        "rule_id": row["rule_id"], "fact_version": row["fact_version"],
        "superseded": bool(row["superseded"]),
        "superseded_reason": row["superseded_reason"],
        "superseded_at": row["superseded_at"],
    }
