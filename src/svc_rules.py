"""禁飞规则登记与版本管理。

规则更新一律新建版本行，旧行置 effective_to 并回指新行；已经作出的结论保存
旧规则的 id，规则更新不得让历史结论悄悄指向新规则。
"""

import sqlite3

import timeutil
from errors import ConflictError, NotFoundError, UnprocessableError


def _validate_zone(zone_geojson: str) -> None:
    if not isinstance(zone_geojson, str):
        raise UnprocessableError("zone_geojson 必须是 GeoJSON 字符串")
    import json
    try:
        geo = json.loads(zone_geojson)
    except ValueError as exc:
        raise UnprocessableError("zone_geojson 不是合法 JSON") from exc
    if not isinstance(geo, dict) or geo.get("type") != "Polygon":
        raise UnprocessableError("zone_geojson 目前仅支持 Polygon 类型")


def create_rule(conn, actor, *, rule_code, title, zone_geojson, altitude_max=None,
                effective_from=None) -> dict:
    effective = timeutil.normalize(effective_from or timeutil.now_iso(), "effective_from")
    _validate_zone(zone_geojson)
    # 同一编号在同一生效起点不得重复
    exists = conn.execute(
        "SELECT 1 FROM nofly_rules WHERE rule_code=? AND effective_from=?",
        (rule_code, effective),
    ).fetchone()
    if exists:
        raise ConflictError(f"规则 {rule_code} 在 {effective} 已存在版本")
    cur = conn.execute(
        "INSERT INTO nofly_rules (rule_code,title,zone_geojson,altitude_max,"
        "effective_from,created_at,created_by) VALUES (?,?,?,?,?,?,?)",
        (rule_code, title, zone_geojson, altitude_max, effective,
         timeutil.now_iso(), actor.display_name),
    )
    return dict(conn.execute("SELECT * FROM nofly_rules WHERE id=?", (cur.lastrowid,)).fetchone())


def update_rule(conn, actor, *, rule_code, title, zone_geojson, altitude_max=None,
                effective_from=None) -> dict:
    """发布新版本：截断当前生效版本，新建一行并回指。"""
    current = conn.execute(
        "SELECT * FROM nofly_rules WHERE rule_code=? AND effective_to IS NULL"
        " ORDER BY effective_from DESC LIMIT 1", (rule_code,)
    ).fetchone()
    if current is None:
        raise NotFoundError(f"规则 {rule_code} 不存在，请先登记首版")
    effective = timeutil.normalize(effective_from or timeutil.now_iso(), "effective_from")
    if timeutil.parse_iso(effective) < timeutil.parse_iso(current["effective_from"]):
        raise ConflictError("新版本生效时间不得早于当前版本")
    _validate_zone(zone_geojson)
    cur = conn.execute(
        "INSERT INTO nofly_rules (rule_code,title,zone_geojson,altitude_max,"
        "effective_from,created_at,created_by) VALUES (?,?,?,?,?,?,?)",
        (rule_code, title, zone_geojson, altitude_max, effective,
         timeutil.now_iso(), actor.display_name),
    )
    new_id = cur.lastrowid
    conn.execute(
        "UPDATE nofly_rules SET effective_to=?, superseded_by=? WHERE id=?",
        (effective, new_id, current["id"]),
    )
    return dict(conn.execute("SELECT * FROM nofly_rules WHERE id=?", (new_id,)).fetchone())


def get_rule(rule_id: int, conn: sqlite3.Connection) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM nofly_rules WHERE id=?", (rule_id,)).fetchone()
    if row is None:
        raise NotFoundError(f"禁飞规则 {rule_id} 不存在")
    return row


def rule_applicable_at(conn, rule_id: int, at_iso: str) -> bool:
    rule = get_rule(rule_id, conn)
    at = timeutil.parse_iso(at_iso)
    start = timeutil.parse_iso(rule["effective_from"])
    if at < start:
        return False
    if rule["effective_to"] is not None and at >= timeutil.parse_iso(rule["effective_to"]):
        return False
    return True
