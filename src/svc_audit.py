"""审计留痕查询。"""

from svc_common import get_case, row_dict


def query(conn, actor, *, case_id=None, object_type=None, object_id=None,
          action=None, limit=200) -> list[dict]:
    actor.require("audit:read")
    sql = "SELECT * FROM audit_log WHERE 1=1"
    params: list = []
    if case_id is not None:
        get_case(conn, int(case_id))
        sql += " AND case_id=?"
        params.append(int(case_id))
    if object_type:
        sql += " AND object_type=?"
        params.append(object_type)
    if object_id is not None:
        sql += " AND object_id=?"
        params.append(int(object_id))
    if action:
        sql += " AND action=?"
        params.append(action)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(min(int(limit), 1000))
    return [row_dict(r) for r in conn.execute(sql, params).fetchall()]
