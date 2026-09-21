"""领域服务：案件、证据 WORM、保管交接、事实版本、认定结论、程序决定。

核心不变量：
1. 证据原文内容寻址、只追加；状态变化只以 custody 事件表达（sealed/transfer/receive/recall/void）。
2. 案件时间轴只追加（create/link/supplement/unlink/procedure/close），历史永不被改写。
3. 认定结论固定 rule_version / fact_version / evidence_ids 与经办人；事后补证只影响后续判断。
4. 程序决定落快照（当时事实版本 + 当时在链证据），补证不能倒置已作出的决定。
"""

import base64
import binascii
import json
import uuid

from times import now_ts, parse_ts, to_iso

INVESTIGATOR = "investigator"
AUDITOR = "auditor"
PUBLIC_VIEWER = "public_viewer"

SEALED, VOID = "sealed", "void"


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str = ""):
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message or code


def parse_time(value) -> int:
    """HTTP 边界统一把时间口径错误转成 400。"""
    try:
        return parse_ts(value)
    except ValueError as exc:
        raise ApiError(400, exc.args[0] if exc.args else "time_invalid") from exc


# ---------------- 认证与授权 ----------------

def load_actor(store, actor_id: str | None):
    if not actor_id:
        raise ApiError(401, "actor_required", "请求头 X-Actor-Id 必填")
    row = store.query_one("SELECT * FROM actors WHERE actor_id=?", (actor_id,))
    if not row:
        raise ApiError(401, "actor_unknown", "经办人未登记")
    row["roles"] = json.loads(row["roles"])
    return row


def require_role(actor, role: str):
    if role not in actor["roles"]:
        raise ApiError(403, "forbidden", f"需要 {role} 权限")


def register_actor(store, body: dict):
    actor_id = str(body.get("actor_id") or f"actor-{uuid.uuid4().hex[:12]}")
    name = body.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ApiError(400, "name_required")
    roles = body.get("roles", [])
    valid = {INVESTIGATOR, AUDITOR, PUBLIC_VIEWER}
    if not isinstance(roles, list) or any(r not in valid for r in roles):
        raise ApiError(400, "roles_invalid")
    if store.query_one("SELECT 1 FROM actors WHERE actor_id=?", (actor_id,)):
        raise ApiError(409, "actor_exists")
    store.execute(
        "INSERT INTO actors(actor_id,name,org,roles) VALUES (?,?,?,?)",
        (actor_id, name.strip(), str(body.get("org", "")), json.dumps(roles)),
    )
    store.audit(actor_id, "register", "actor", actor_id, {"roles": roles})
    return get_actor(store, actor_id)


def get_actor(store, actor_id: str):
    row = store.query_one("SELECT * FROM actors WHERE actor_id=?", (actor_id,))
    if not row:
        raise ApiError(404, "not_found")
    row["roles"] = json.loads(row["roles"])
    return row


def list_actors(store):
    rows = store.query("SELECT actor_id,name,org,roles FROM actors ORDER BY actor_id")
    for r in rows:
        r["roles"] = json.loads(r.pop("roles"))
    return rows


# ---------------- 禁飞规则（版本化、只追加） ----------------

def create_rule(store, actor, body: dict):
    require_role(actor, INVESTIGATOR)
    rule_id = body.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ApiError(400, "rule_id_required")
    title = body.get("title")
    content = body.get("content")
    if not isinstance(title, str) or not title.strip():
        raise ApiError(400, "title_required")
    if not isinstance(content, str) or not content.strip():
        raise ApiError(400, "content_required")
    scope = body.get("scope", {})
    if not isinstance(scope, dict):
        raise ApiError(400, "scope_invalid")
    effective_from = parse_time(body.get("effective_from"))
    versions = store.query(
        "SELECT version,effective_from,effective_to FROM rules WHERE rule_id=?"
        " ORDER BY version", (rule_id,))
    version = int(body["version"]) if body.get("version") is not None else len(versions) + 1
    if any(v["version"] == version for v in versions):
        raise ApiError(409, "rule_version_exists")
    if version != len(versions) + 1:
        raise ApiError(400, "rule_version_gap", "规则版本必须连续递增")
    if versions and effective_from < versions[-1]["effective_from"]:
        raise ApiError(409, "rule_effective_order", "新版本生效时间不得早于旧版本")
    ts = now_ts()
    store.execute(
        "INSERT INTO rules(rule_id,version,title,content,scope,effective_from,"
        "effective_to,supersedes,created_ts) VALUES (?,?,?,?,?,?,?,?,?)",
        (rule_id, version, title.strip(), content, json.dumps(scope, ensure_ascii=False),
         effective_from, None, str(body.get("supersedes", "")), ts),
    )
    # 新版本生效之时，旧现行版本自动截止（旧版本内容本身保持不变）
    if versions and versions[-1]["effective_to"] is None:
        store.execute(
            "UPDATE rules SET effective_to=? WHERE rule_id=? AND version=?",
            (effective_from, rule_id, versions[-1]["version"]),
        )
    store.audit(actor["actor_id"], "create", "rule", rule_id, {"version": version})
    return get_rule(store, rule_id, version)


def _rule_out(row: dict) -> dict:
    row["scope"] = json.loads(row["scope"])
    row["effective_from_iso"] = to_iso(row.pop("effective_from"))
    row["effective_to_iso"] = to_iso(row.pop("effective_to"))
    row["created_iso"] = to_iso(row.pop("created_ts"))
    return row


def get_rule(store, rule_id: str, version: int | None = None, at_ts: int | None = None):
    if version is not None:
        row = store.query_one(
            "SELECT * FROM rules WHERE rule_id=? AND version=?", (rule_id, version))
    elif at_ts is not None:
        row = store.query_one(
            "SELECT * FROM rules WHERE rule_id=? AND effective_from<=?"
            " AND (effective_to IS NULL OR effective_to>?) ORDER BY version DESC",
            (rule_id, at_ts, at_ts))
    else:
        row = store.query_one(
            "SELECT * FROM rules WHERE rule_id=? ORDER BY version DESC", (rule_id,))
    if not row:
        raise ApiError(404, "rule_not_found")
    return _rule_out(dict(row))


def list_rules(store, actor):
    if not (INVESTIGATOR in actor["roles"] or AUDITOR in actor["roles"]):
        raise ApiError(403, "forbidden")
    rows = store.query("SELECT * FROM rules ORDER BY rule_id, version")
    latest = {}
    for r in rows:
        latest[r["rule_id"]] = r
    return [_rule_out(dict(r)) for r in latest.values()]


# ---------------- 证据：入库固定 + WORM 状态机 ----------------

def ingest_evidence(store, actor, body: dict):
    require_role(actor, INVESTIGATOR)
    kind = body.get("kind")
    if kind not in {"video", "remote_id", "transcript", "other"}:
        raise ApiError(400, "kind_invalid")
    source_org = body.get("source_org")
    if not isinstance(source_org, str) or not source_org.strip():
        raise ApiError(400, "source_org_required")
    collected_ts = parse_time(body.get("collected_at"))  # 来源单位口径，必填
    received_ts = parse_time(body["received_at"]) if body.get("received_at") else now_ts()
    if received_ts < collected_ts:
        raise ApiError(400, "time_order", "接收时间不得早于采集时间")
    if not isinstance(body.get("content"), str):
        raise ApiError(400, "content_required", "原文须以 base64 字符串提供")
    try:
        raw = base64.b64decode(body["content"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ApiError(400, "content_base64_invalid") from exc
    public_summary = body.get("public_summary")
    if not isinstance(public_summary, str) or not public_summary.strip():
        raise ApiError(400, "public_summary_required")
    sensitive = str(body.get("sensitive_identity", ""))
    custodian = body.get("custodian") or actor["actor_id"]
    if not get_actor(store, custodian):
        raise ApiError(400, "custodian_unknown")

    evidence_id = str(body.get("evidence_id") or f"evi-{uuid.uuid4().hex[:12]}")
    if store.query_one("SELECT 1 FROM evidences WHERE evidence_id=?", (evidence_id,)):
        raise ApiError(409, "evidence_exists")
    digest, size, ref = store.put_blob(raw)
    ts = now_ts()
    store.execute(
        "INSERT INTO evidences(evidence_id,kind,sha256,size,source_org,collected_ts,"
        "received_ts,stored_ts,status,storage_ref,public_summary,sensitive_identity)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (evidence_id, kind, digest, size, source_org.strip(), collected_ts,
         received_ts, ts, SEALED, ref, public_summary.strip(), sensitive),
    )
    store.execute(
        "INSERT INTO evidence_custody(evidence_id,action,from_actor,to_actor,actor,note,ts)"
        " VALUES (?,?,?,?,?,?,?)",
        (evidence_id, "ingest", "", custodian, actor["actor_id"], "入库封存", ts),
    )
    store.audit(actor["actor_id"], "ingest", "evidence", evidence_id,
                {"sha256": digest, "size": size, "source_org": source_org})
    return get_evidence_meta(store, evidence_id, actor)


def _evidence_out(row: dict, actor) -> dict:
    out = {
        "evidence_id": row["evidence_id"],
        "kind": row["kind"],
        "sha256": row["sha256"],
        "size": row["size"],
        "source_org": row["source_org"],
        "collected_at": to_iso(row["collected_ts"]),
        "received_at": to_iso(row["received_ts"]),
        "stored_at": to_iso(row["stored_ts"]),
        "status": row["status"],
        "public_summary": row["public_summary"],
    }
    # 敏感身份单独授权：公开角色只见公开摘要
    if AUDITOR in actor["roles"] or INVESTIGATOR in actor["roles"]:
        out["sensitive_identity"] = row["sensitive_identity"]
    return out


def _get_evidence_row(store, evidence_id: str) -> dict:
    row = store.query_one("SELECT * FROM evidences WHERE evidence_id=?", (evidence_id,))
    if not row:
        raise ApiError(404, "evidence_not_found")
    return row


def get_evidence_meta(store, evidence_id: str, actor, *, log_view=True) -> dict:
    row = _get_evidence_row(store, evidence_id)
    if PUBLIC_VIEWER in actor["roles"] and AUDITOR not in actor["roles"] \
            and INVESTIGATOR not in actor["roles"]:
        out = {"evidence_id": row["evidence_id"], "kind": row["kind"],
               "status": row["status"], "public_summary": row["public_summary"]}
    else:
        out = _evidence_out(row, actor)
    out["custody"] = _custody_rows(store, evidence_id)
    if log_view:
        store.audit(actor["actor_id"], "view", "evidence", evidence_id)
    return out


def download_evidence(store, evidence_id: str, actor) -> tuple[dict, bytes]:
    # 下载原文需要办案/审计权限，公开角色不可下载
    if not (INVESTIGATOR in actor["roles"] or AUDITOR in actor["roles"]):
        raise ApiError(403, "forbidden", "下载原文需要 investigator/auditor 权限")
    row = _get_evidence_row(store, evidence_id)
    if row["status"] == VOID:
        raise ApiError(410, "evidence_void", "已作废材料不得下载，原文哈希仍保留备查")
    pending = pending_transfer(store, evidence_id)
    if pending:
        raise ApiError(409, "custody_in_transit", "材料交接签收完成前不得下载")
    data = store.get_blob(row["storage_ref"])
    store.audit(actor["actor_id"], "download", "evidence", evidence_id,
                {"sha256": row["sha256"], "size": row["size"]})
    return _evidence_out(row, actor), data


def list_evidences(store, actor, case_id: str | None = None):
    if PUBLIC_VIEWER in actor["roles"] and len(actor["roles"]) == 1:
        rows = store.query("SELECT * FROM evidences WHERE status=? ORDER BY stored_ts", (SEALED,))
        store.audit(actor["actor_id"], "view", "evidence_list", case_id or "all")
        return [{"evidence_id": r["evidence_id"], "kind": r["kind"],
                 "status": r["status"], "public_summary": r["public_summary"]} for r in rows]
    if case_id:
        rows = store.query(
            "SELECT e.* FROM evidences e JOIN case_events ce ON ce.case_id=?"
            "  AND ce.type IN ('link','supplement') "
            "  AND json_extract(ce.payload,'$.evidence_id')=e.evidence_id "
            "WHERE NOT EXISTS (SELECT 1 FROM case_events u WHERE u.case_id=? AND u.type='unlink'"
            "  AND json_extract(u.payload,'$.evidence_id')=e.evidence_id AND u.seq>ce.seq)"
            "ORDER BY e.stored_ts", (case_id, case_id))
    else:
        rows = store.query("SELECT * FROM evidences ORDER BY stored_ts")
    store.audit(actor["actor_id"], "view", "evidence_list", case_id or "all")
    return [_evidence_out(dict(r), actor) for r in rows]


# ---------------- 保管链：交接/签收/召回/作废（全部追加事件） ----------------

def custody_chain(store, evidence_id: str, actor):
    _get_evidence_row(store, evidence_id)
    store.audit(actor["actor_id"], "view", "custody", evidence_id)
    return _custody_rows(store, evidence_id)


def _custody_rows(store, evidence_id: str):
    rows = store.query(
        "SELECT seq,action,from_actor,to_actor,actor,note,ts FROM evidence_custody"
        " WHERE evidence_id=? ORDER BY seq", (evidence_id,))
    for r in rows:
        r["at"] = to_iso(r.pop("ts"))
    return rows


def custody_overview(store, evidence_id: str) -> dict:
    rows = store.query(
        "SELECT action,from_actor,to_actor FROM evidence_custody WHERE evidence_id=?"
        " ORDER BY seq DESC LIMIT 1", (evidence_id,))
    pending = pending_transfer(store, evidence_id)
    if pending:
        return {"state": "in_transit", "holder": pending["from_actor"],
                "pending_to": pending["to_actor"]}
    if rows:
        last = rows[0]
        if last["action"] == "void":
            return {"state": "void", "holder": last["to_actor"] or last["actor"]}
        return {"state": "held", "holder": last["to_actor"] or last["actor"]}
    return {"state": "unknown"}


def pending_transfer(store, evidence_id: str):
    rows = store.query(
        "SELECT seq,action,from_actor,to_actor,note,ts FROM evidence_custody"
        " WHERE evidence_id=? ORDER BY seq DESC LIMIT 1", (evidence_id,))
    if rows and rows[0]["action"] == "transfer":
        r = rows[0]
        return {"evidence_id": evidence_id, "seq": r["seq"], "from_actor": r["from_actor"],
                "to_actor": r["to_actor"], "note": r["note"], "at": to_iso(r["ts"])}
    return None


def transfer_evidence(store, actor, evidence_id: str, body: dict):
    require_role(actor, INVESTIGATOR)
    row = _get_evidence_row(store, evidence_id)
    if row["status"] == VOID:
        raise ApiError(410, "evidence_void")
    if pending_transfer(store, evidence_id):
        raise ApiError(409, "custody_already_pending", "已有待签收交接")
    to_actor = body.get("to_actor")
    if not to_actor or not get_actor(store, to_actor):
        raise ApiError(400, "to_actor_unknown")
    overview = custody_overview(store, evidence_id)
    holder = overview["holder"]
    if actor["actor_id"] != holder:
        raise ApiError(403, "not_custodian", "只有当前保管人可以移交")
    ts = now_ts()
    store.execute(
        "INSERT INTO evidence_custody(evidence_id,action,from_actor,to_actor,actor,note,ts)"
        " VALUES (?,?,?,?,?,?,?)",
        (evidence_id, "transfer", holder, to_actor, actor["actor_id"],
         str(body.get("note", "")), ts),
    )
    store.audit(actor["actor_id"], "transfer", "custody", evidence_id,
                {"from": holder, "to": to_actor})
    return custody_overview(store, evidence_id)


def receive_evidence(store, actor, evidence_id: str, body: dict):
    require_role(actor, INVESTIGATOR)
    row = _get_evidence_row(store, evidence_id)
    if row["status"] == VOID:
        raise ApiError(410, "evidence_void")
    pending = pending_transfer(store, evidence_id)
    if not pending:
        raise ApiError(409, "no_pending_transfer")
    if actor["actor_id"] != pending["to_actor"]:
        raise ApiError(403, "not_recipient", "只有指定接收人可以签收")
    ts = now_ts()
    store.execute(
        "INSERT INTO evidence_custody(evidence_id,action,from_actor,to_actor,actor,note,ts)"
        " VALUES (?,?,?,?,?,?,?)",
        (evidence_id, "receive", pending["from_actor"], actor["actor_id"],
         actor["actor_id"], str(body.get("note", "签收")), ts),
    )
    store.audit(actor["actor_id"], "receive", "custody", evidence_id,
                {"from": pending["from_actor"]})
    return custody_overview(store, evidence_id)


def recall_transfer(store, actor, evidence_id: str, body: dict):
    require_role(actor, INVESTIGATOR)
    pending = pending_transfer(store, evidence_id)
    if not pending:
        raise ApiError(409, "no_pending_transfer")
    if actor["actor_id"] != pending["from_actor"]:
        raise ApiError(403, "not_sender", "只有移交人可以召回")
    ts = now_ts()
    store.execute(
        "INSERT INTO evidence_custody(evidence_id,action,from_actor,to_actor,actor,note,ts)"
        " VALUES (?,?,?,?,?,?,?)",
        (evidence_id, "recall", actor["actor_id"], actor["actor_id"],
         actor["actor_id"], str(body.get("note", "召回")), ts),
    )
    store.audit(actor["actor_id"], "recall", "custody", evidence_id)
    return custody_overview(store, evidence_id)


def void_evidence(store, actor, evidence_id: str, body: dict):
    require_role(actor, INVESTIGATOR)
    row = _get_evidence_row(store, evidence_id)
    if row["status"] == VOID:
        raise ApiError(409, "already_void")
    if pending_transfer(store, evidence_id):
        raise ApiError(409, "custody_in_transit", "待签收交接完成前不得作废")
    note = body.get("note")
    if not isinstance(note, str) or not note.strip():
        raise ApiError(400, "void_reason_required")
    overview = custody_overview(store, evidence_id)
    ts = now_ts()
    store.execute("UPDATE evidences SET status=? WHERE evidence_id=?", (VOID, evidence_id))
    store.execute(
        "INSERT INTO evidence_custody(evidence_id,action,from_actor,to_actor,actor,note,ts)"
        " VALUES (?,?,?,?,?,?,?)",
        (evidence_id, "void", "", overview.get("holder", ""), actor["actor_id"],
         note.strip(), ts),
    )
    store.audit(actor["actor_id"], "void", "evidence", evidence_id, {"reason": note})
    return get_evidence_meta(store, evidence_id, actor, log_view=False)

def list_pending_transfers(store, actor):
    if not (INVESTIGATOR in actor["roles"] or AUDITOR in actor["roles"]):
        raise ApiError(403, "forbidden")
    ids = [r["evidence_id"] for r in store.query(
        "SELECT DISTINCT evidence_id FROM evidence_custody")]
    pending = [p for p in (pending_transfer(store, eid) for eid in ids) if p]
    store.audit(actor["actor_id"], "view", "pending_transfers", "all")
    return pending


# ---------------- 案件与时间轴 ----------------

def create_case(store, actor, body: dict):
    require_role(actor, INVESTIGATOR)
    case_id = str(body.get("case_id") or f"case-{uuid.uuid4().hex[:12]}")
    title = body.get("title")
    if not isinstance(title, str) or not title.strip():
        raise ApiError(400, "title_required")
    if store.query_one("SELECT 1 FROM cases WHERE case_id=?", (case_id,)):
        raise ApiError(409, "case_exists")
    deadline = parse_time(body.get("deadline"))  # 办案期限，落库持久
    ts = now_ts()
    store.execute(
        "INSERT INTO cases(case_id,title,status,created_ts,deadline_ts) VALUES (?,?,?,?,?)",
        (case_id, title.strip(), "open", ts, deadline),
    )
    store.execute(
        "INSERT INTO case_events(case_id,type,actor_id,ts,payload) VALUES (?,?,?,?,?)",
        (case_id, "create", actor["actor_id"], ts,
         json.dumps({"title": title.strip()}, ensure_ascii=False)),
    )
    store.audit(actor["actor_id"], "create", "case", case_id, {"deadline": to_iso(deadline)})
    return get_case(store, case_id, actor)


def _get_case_row(store, case_id: str) -> dict:
    row = store.query_one("SELECT * FROM cases WHERE case_id=?", (case_id,))
    if not row:
        raise ApiError(404, "case_not_found")
    return row


def _require_open(store, case_id: str):
    row = _get_case_row(store, case_id)
    if row["status"] != "open":
        raise ApiError(409, "case_closed", "已结案归档，不得再变更")
    return row


def _event_out(row: dict) -> dict:
    out = {"seq": row["seq"], "type": row["type"], "actor_id": row["actor_id"],
           "at": to_iso(row["ts"]), "payload": json.loads(row.get("payload") or "{}")}
    return out


def active_evidence_ids(store, case_id: str, as_of_ts: int | None = None) -> list[str]:
    """重建某时点在链证据：按 seq 回放 link/supplement 与 unlink（支持 as-of 历史快照）。"""
    if as_of_ts is None:
        events = store.query(
            "SELECT seq,type,payload FROM case_events WHERE case_id=?"
            " AND type IN ('link','supplement','unlink') ORDER BY seq", (case_id,))
    else:
        events = store.query(
            "SELECT seq,type,payload FROM case_events WHERE case_id=?"
            " AND type IN ('link','supplement','unlink') AND ts<=? ORDER BY seq",
            (case_id, as_of_ts))
    active = []
    for e in events:
        eid = json.loads(e["payload"]).get("evidence_id")
        if e["type"] in ("link", "supplement"):
            if eid not in active:
                active.append(eid)
        else:
            if eid in active:
                active.remove(eid)
    return active


def link_evidence(store, actor, case_id: str, body: dict, *, supplement: bool = False):
    require_role(actor, INVESTIGATOR)
    _require_open(store, case_id)
    evidence_id = body.get("evidence_id")
    if not isinstance(evidence_id, str):
        raise ApiError(400, "evidence_id_required")
    ev = _get_evidence_row(store, evidence_id)
    if ev["status"] == VOID:
        raise ApiError(410, "evidence_void", "已作废材料不得关联案件")
    active = active_evidence_ids(store, case_id)
    if evidence_id in active:
        raise ApiError(409, "already_linked")
    ts = now_ts()
    etype = "supplement" if supplement else "link"
    payload = {"evidence_id": evidence_id, "sha256": ev["sha256"],
               "note": str(body.get("note", ""))}
    store.execute(
        "INSERT INTO case_events(case_id,type,actor_id,ts,payload) VALUES (?,?,?,?,?)",
        (case_id, etype, actor["actor_id"], ts, json.dumps(payload, ensure_ascii=False)),
    )
    store.audit(actor["actor_id"], etype, "case", case_id,
                {"evidence_id": evidence_id})
    return {"case_id": case_id, "active_evidence_ids": active_evidence_ids(store, case_id)}


def unlink_evidence(store, actor, case_id: str, evidence_id: str, body: dict):
    require_role(actor, INVESTIGATOR)
    _require_open(store, case_id)
    _get_evidence_row(store, evidence_id)
    reason = body.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ApiError(400, "reason_required", "撤销错误关联必须写明原因")
    if evidence_id not in active_evidence_ids(store, case_id):
        raise ApiError(409, "not_linked", "该证据当前不在案件关联链上")
    ts = now_ts()
    payload = {"evidence_id": evidence_id, "reason": reason.strip()}
    store.execute(
        "INSERT INTO case_events(case_id,type,actor_id,ts,payload) VALUES (?,?,?,?,?)",
        (case_id, "unlink", actor["actor_id"], ts, json.dumps(payload, ensure_ascii=False)),
    )
    store.audit(actor["actor_id"], "unlink", "case", case_id,
                {"evidence_id": evidence_id, "reason": reason})
    return {"case_id": case_id, "active_evidence_ids": active_evidence_ids(store, case_id)}


def get_case(store, case_id: str, actor):
    row = _get_case_row(store, case_id)
    facts = store.query_one(
        "SELECT version FROM fact_versions WHERE case_id=? ORDER BY version DESC LIMIT 1",
        (case_id,))
    findings = store.query(
        "SELECT finding_id,ts FROM findings WHERE case_id=? ORDER BY ts", (case_id,))
    out = {
        "case_id": row["case_id"],
        "title": row["title"],
        "status": row["status"],
        "created_at": to_iso(row["created_ts"]),
        "deadline": to_iso(row["deadline_ts"]),
        "closed_at": to_iso(row["closed_ts"]),
        "overdue": row["status"] == "open" and now_ts() > row["deadline_ts"],
        "fact_version": facts["version"] if facts else 0,
        "active_evidence_ids": active_evidence_ids(store, case_id),
        "findings": [{"finding_id": f["finding_id"], "at": to_iso(f["ts"])} for f in findings],
    }
    store.audit(actor["actor_id"], "view", "case", case_id)
    return out


def timeline(store, case_id: str, actor, as_of_ts: int | None = None):
    _get_case_row(store, case_id)
    if as_of_ts is None:
        rows = store.query(
            "SELECT seq,type,actor_id,ts,payload FROM case_events"
            " WHERE case_id=? ORDER BY seq", (case_id,))
    else:
        rows = store.query(
            "SELECT seq,type,actor_id,ts,payload FROM case_events"
            " WHERE case_id=? AND ts<=? ORDER BY seq", (case_id, as_of_ts))
    store.audit(actor["actor_id"], "view", "timeline", case_id,
                {"as_of": to_iso(as_of_ts)} if as_of_ts else {})
    return [_event_out(dict(r)) for r in rows]


def list_cases(store, actor):
    rows = store.query("SELECT * FROM cases ORDER BY created_ts")
    out = []
    for r in rows:
        out.append({
            "case_id": r["case_id"], "title": r["title"], "status": r["status"],
            "created_at": to_iso(r["created_ts"]), "deadline": to_iso(r["deadline_ts"]),
            "overdue": r["status"] == "open" and now_ts() > r["deadline_ts"],
        })
    store.audit(actor["actor_id"], "view", "case_list", "all")
    return out


# ---------------- 事实清单：乐观锁多版本 ----------------

def put_facts(store, actor, case_id: str, body: dict):
    require_role(actor, INVESTIGATOR)
    _require_open(store, case_id)
    if not isinstance(body.get("content"), (dict, list)):
        raise ApiError(400, "content_required", "事实清单 content 必须是 JSON 对象或数组")
    try:
        base_version = int(body.get("base_version", 0))
    except (TypeError, ValueError) as exc:
        raise ApiError(400, "base_version_invalid") from exc
    latest = store.query_one(
        "SELECT version,editor_id,ts FROM fact_versions WHERE case_id=?"
        " ORDER BY version DESC LIMIT 1", (case_id,))
    current = latest["version"] if latest else 0
    if base_version != current:
        # 暴露版本冲突：返回服务端当前版本与编辑人，不覆盖任何人的修改
        raise ApiError(409, "fact_version_conflict",
                       f"事实清单已由 {latest['editor_id']} 更新到 v{current}")
    version = current + 1
    ts = now_ts()
    store.execute(
        "INSERT INTO fact_versions(case_id,version,content,editor_id,base_version,ts)"
        " VALUES (?,?,?,?,?,?)",
        (case_id, version, json.dumps(body["content"], ensure_ascii=False),
         actor["actor_id"], base_version, ts),
    )
    store.audit(actor["actor_id"], "edit", "facts", case_id, {"version": version})
    return get_facts(store, case_id, version, actor, log_view=False)


def get_facts(store, case_id: str, version: int | None, actor, *, log_view=True):
    _get_case_row(store, case_id)
    if version is None:
        row = store.query_one(
            "SELECT * FROM fact_versions WHERE case_id=? ORDER BY version DESC LIMIT 1",
            (case_id,))
    else:
        row = store.query_one(
            "SELECT * FROM fact_versions WHERE case_id=? AND version=?", (case_id, version))
    if not row:
        if version in (None, 0):
            return {"case_id": case_id, "version": 0, "base_version": 0,
                    "editor_id": None, "content": None, "edited_at": None}
        raise ApiError(404, "fact_version_not_found")
    out = {"case_id": case_id, "version": row["version"],
           "base_version": row["base_version"], "editor_id": row["editor_id"],
           "edited_at": to_iso(row["ts"]), "content": json.loads(row["content"])}
    if log_view:
        store.audit(actor["actor_id"], "view", "facts", case_id, {"version": out["version"]})
    return out


# ---------------- 认定结论：固定引用 ----------------

def create_finding(store, actor, case_id: str, body: dict):
    require_role(actor, INVESTIGATOR)
    _require_open(store, case_id)
    content = body.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ApiError(400, "content_required")
    rule_id = body.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ApiError(400, "rule_id_required")
    ts = now_ts()
    # 固定当时适用的规则版本（未显式指定则取当下有效版本并固化）
    if body.get("rule_version") is not None:
        rule = get_rule(store, rule_id, int(body["rule_version"]))
    else:
        rule = get_rule(store, rule_id, at_ts=ts)
    fact_row = store.query_one(
        "SELECT version FROM fact_versions WHERE case_id=? ORDER BY version DESC LIMIT 1",
        (case_id,))
    fact_version = int(body["fact_version"]) if body.get("fact_version") is not None \
        else (fact_row["version"] if fact_row else 0)
    if fact_version > 0 and not store.query_one(
            "SELECT 1 FROM fact_versions WHERE case_id=? AND version=?",
            (case_id, fact_version)):
        raise ApiError(404, "fact_version_not_found")
    evidence_ids = body.get("evidence_ids", [])
    if not isinstance(evidence_ids, list) or not evidence_ids:
        raise ApiError(400, "evidence_ids_required", "认定结论必须引用至少一项证据")
    active = active_evidence_ids(store, case_id)
    for eid in evidence_ids:
        if eid not in active:
            raise ApiError(409, "evidence_not_linked", f"证据 {eid} 当前不在案件链上")
        ev = _get_evidence_row(store, eid)
        if ev["status"] != SEALED:
            raise ApiError(410, "evidence_void", f"证据 {eid} 已作废，不得作为认定依据")
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ApiError(400, "evidence_ids_duplicate")
    finding_id = str(body.get("finding_id") or f"fnd-{uuid.uuid4().hex[:12]}")
    if store.query_one("SELECT 1 FROM findings WHERE finding_id=?", (finding_id,)):
        raise ApiError(409, "finding_exists")
    store.execute(
        "INSERT INTO findings(finding_id,case_id,content,rule_id,rule_version,"
        "fact_version,evidence_ids,actor_id,ts) VALUES (?,?,?,?,?,?,?,?,?)",
        (finding_id, case_id, content.strip(), rule_id, rule["version"], fact_version,
         json.dumps(evidence_ids), actor["actor_id"], ts),
    )
    store.audit(actor["actor_id"], "create", "finding", finding_id,
                {"case_id": case_id, "rule_version": rule["version"],
                 "fact_version": fact_version})
    return get_finding(store, finding_id, actor)


def _finding_row(store, finding_id: str) -> dict:
    row = store.query_one("SELECT * FROM findings WHERE finding_id=?", (finding_id,))
    if not row:
        raise ApiError(404, "finding_not_found")
    return row


def get_finding(store, finding_id: str, actor):
    row = _finding_row(store, finding_id)
    out = {
        "finding_id": row["finding_id"], "case_id": row["case_id"],
        "content": row["content"], "rule_id": row["rule_id"],
        "rule_version": row["rule_version"], "fact_version": row["fact_version"],
        "evidence_ids": json.loads(row["evidence_ids"]),
        "actor_id": row["actor_id"], "at": to_iso(row["ts"]),
    }
    store.audit(actor["actor_id"], "view", "finding", finding_id)
    return out


def list_findings(store, case_id: str, actor):
    _get_case_row(store, case_id)
    rows = store.query("SELECT finding_id,ts FROM findings WHERE case_id=? ORDER BY ts",
                       (case_id,))
    store.audit(actor["actor_id"], "view", "finding_list", case_id)
    return [{"finding_id": r["finding_id"], "at": to_iso(r["ts"])} for r in rows]


def trace_finding(store, finding_id: str, actor):
    """从一条认定结论回溯：固定版本规则、事实版本、完整证据链、经办人及变更记录。"""
    row = _finding_row(store, finding_id)
    evidence_ids = json.loads(row["evidence_ids"])
    evidences = []
    for eid in evidence_ids:
        ev = store.query_one("SELECT * FROM evidences WHERE evidence_id=?", (eid,))
        evidences.append({
            "meta": _evidence_out(dict(ev), actor) if ev else None,
            "custody_chain": _custody_rows(store, eid),
            # 该证据在结论作出时点是否在链（事后撤销关联不影响结论当时的依据）
            "linked_at_finding_time": eid in active_evidence_ids(
                store, row["case_id"], as_of_ts=row["ts"]),
        })
    fact = store.query_one(
        "SELECT * FROM fact_versions WHERE case_id=? AND version=?",
        (row["case_id"], row["fact_version"]))
    actor_row = store.query_one("SELECT * FROM actors WHERE actor_id=?", (row["actor_id"],))
    change_events = store.query(
        "SELECT seq,type,actor_id,ts,payload FROM case_events WHERE case_id=? AND ts<=?"
        " ORDER BY seq", (row["case_id"], row["ts"]))
    later = store.query(
        "SELECT seq,type,actor_id,ts,payload FROM case_events WHERE case_id=? AND ts>?"
        " ORDER BY seq", (row["case_id"], row["ts"]))
    out = {
        "finding": get_finding(store, finding_id, actor),
        "rule": get_rule(store, row["rule_id"], row["rule_version"]),
        "facts": ({"version": fact["version"], "editor_id": fact["editor_id"],
                   "edited_at": to_iso(fact["ts"]), "content": json.loads(fact["content"])}
                  if fact else {"version": 0, "content": None}),
        "evidences": evidences,
        "handler": ({"actor_id": actor_row["actor_id"], "name": actor_row["name"],
                     "org": actor_row["org"], "roles": json.loads(actor_row["roles"])}
                    if actor_row else None),
        "changes_before_decision": [_event_out(dict(e)) for e in change_events],
        "changes_after_decision": [_event_out(dict(e)) for e in later],
    }
    store.audit(actor["actor_id"], "trace", "finding", finding_id)
    return out


# ---------------- 程序决定（落快照，不受事后补证倒置） ----------------

def record_decision(store, actor, case_id: str, body: dict):
    require_role(actor, INVESTIGATOR)
    _require_open(store, case_id)
    content = body.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ApiError(400, "content_required", "程序决定内容必填")
    fact_row = store.query_one(
        "SELECT version FROM fact_versions WHERE case_id=? ORDER BY version DESC LIMIT 1",
        (case_id,))
    ts = now_ts()
    # 决定作出瞬间的依据快照：事实版本 + 在链证据（含哈希），此后补证/撤链不改写本快照
    active_ids = active_evidence_ids(store, case_id)
    basis = []
    for eid in active_ids:
        ev = _get_evidence_row(store, eid)
        basis.append({"evidence_id": eid, "sha256": ev["sha256"], "status": ev["status"]})
    payload = {"content": content.strip(),
               "fact_version": fact_row["version"] if fact_row else 0,
               "evidence_basis": basis}
    store.execute(
        "INSERT INTO case_events(case_id,type,actor_id,ts,payload) VALUES (?,?,?,?,?)",
        (case_id, "procedure", actor["actor_id"], ts,
         json.dumps(payload, ensure_ascii=False)),
    )
    store.audit(actor["actor_id"], "decision", "case", case_id,
                {"fact_version": payload["fact_version"], "evidence_count": len(basis)})
    return {"case_id": case_id, "at": to_iso(ts), **payload}


def close_case(store, actor, case_id: str, body: dict):
    require_role(actor, INVESTIGATOR)
    _require_open(store, case_id)
    note = str(body.get("note", "结案归档"))
    ts = now_ts()
    store.execute("UPDATE cases SET status='closed',closed_ts=? WHERE case_id=?",
                  (ts, case_id))
    store.execute(
        "INSERT INTO case_events(case_id,type,actor_id,ts,payload) VALUES (?,?,?,?,?)",
        (case_id, "close", actor["actor_id"], ts,
         json.dumps({"note": note}, ensure_ascii=False)),
    )
    store.audit(actor["actor_id"], "close", "case", case_id)
    return get_case(store, case_id, actor)


# ---------------- 审计查询 ----------------

def query_audit(store, actor, params: dict):
    require_role(actor, AUDITOR)
    sql = "SELECT seq,ts,actor_id,action,target_type,target_id,detail FROM audit_logs"
    clauses, args = [], []
    for key, col in (("actor_id", "actor_id"), ("action", "action"),
                     ("target_type", "target_type"), ("target_id", "target_id")):
        if params.get(key):
            clauses.append(f"{col}=?")
            args.append(params[key])
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY seq DESC LIMIT 500"
    rows = store.query(sql, args)
    for r in rows:
        r["at"] = to_iso(r.pop("ts"))
        r["detail"] = json.loads(r["detail"])
    return rows


def dashboard(store, actor):
    if not (INVESTIGATOR in actor["roles"] or AUDITOR in actor["roles"]):
        raise ApiError(403, "forbidden")
    cases = store.query("SELECT * FROM cases WHERE status='open'")
    ts = now_ts()
    ids = [r["evidence_id"] for r in store.query(
        "SELECT DISTINCT evidence_id FROM evidence_custody")]
    return {
        "open_cases": [{"case_id": c["case_id"], "title": c["title"],
                        "deadline": to_iso(c["deadline_ts"]),
                        "remaining_ms": c["deadline_ts"] - ts,
                        "overdue": ts > c["deadline_ts"]} for c in cases],
        "pending_transfers": [p for p in
                              (pending_transfer(store, eid) for eid in ids) if p],
        "server_time": to_iso(ts),
    }
