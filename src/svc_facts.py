"""事实清单：版本只追加，多人编辑用乐观锁暴露冲突。"""

import json
import timeutil
from auth import audit
from errors import ConflictError, NotFoundError, UnprocessableError
from svc_common import get_case, require_writable_case, row_dict


def current_version(conn, case_id: int) -> int:
    row = conn.execute("SELECT version FROM case_fact_head WHERE case_id=?",
                       (case_id,)).fetchone()
    return int(row["version"]) if row else 0


def get_current(conn, actor, case_id: int) -> dict:
    get_case(conn, case_id)
    version = current_version(conn, case_id)
    if version == 0:
        return {"case_id": case_id, "version": 0, "content": None,
                "based_on": None, "author": None, "created_at": None}
    return get_version(conn, case_id, version)


def get_version(conn, case_id: int, version: int) -> dict:
    row = conn.execute(
        "SELECT * FROM fact_versions WHERE case_id=? AND version=?",
        (case_id, version),
    ).fetchone()
    if row is None:
        raise NotFoundError(f"事实版本 v{version} 不存在")
    data = row_dict(row)
    data["content"] = json.loads(data["content"])
    return data


def list_versions(conn, actor, case_id: int) -> list[dict]:
    get_case(conn, case_id)
    rows = conn.execute(
        "SELECT id,version,based_on,change_note,author,created_at"
        " FROM fact_versions WHERE case_id=? ORDER BY version", (case_id,)
    ).fetchall()
    return [row_dict(r) for r in rows]


def save(conn, actor, case_id: int, *, content, based_on: int, change_note: str) -> dict:
    """提交新版本。

    based_on 必须等于当前最新版本号：
    - 案件尚无版本时 based_on=0；
    - 若期间他人已提交，based_on 落后，返回 409，携带服务端最新版本，由调用方合并后重提。
    """
    case = get_case(conn, case_id)
    require_writable_case(case)
    if not change_note or not str(change_note).strip():
        raise UnprocessableError("change_note 不能为空")
    if not isinstance(content, (dict, list)):
        raise UnprocessableError("content 必须是结构化 JSON 对象或数组")
    try:
        serialized = json.dumps(content, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise UnprocessableError(f"content 无法序列化为 JSON: {exc}") from exc

    head = conn.execute("SELECT version FROM case_fact_head WHERE case_id=?",
                        (case_id,)).fetchone()
    server_version = int(head["version"]) if head else 0
    if int(based_on) != server_version:
        raise ConflictError(
            f"事实清单已被他人更新：你的基线 v{based_on}，服务端当前 v{server_version}，"
            "请拉取合并后用新的 based_on 重新提交",
            code="fact_version_conflict",
        )
    new_version = server_version + 1
    ts = timeutil.now_iso()
    conn.execute(
        "INSERT INTO fact_versions (case_id,version,content,change_note,based_on,"
        "author,author_id,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (case_id, new_version, serialized, change_note, based_on,
         actor.display_name, actor.id, ts),
    )
    conn.execute(
        "INSERT INTO case_fact_head (case_id,version,updated_at) VALUES (?,?,?)"
        " ON CONFLICT(case_id) DO UPDATE SET version=excluded.version,"
        " updated_at=excluded.updated_at",
        (case_id, new_version, ts),
    )
    audit(conn, actor, "fact.save", object_type="fact_version", object_id=new_version,
          case_id=case_id, detail=f"v{new_version} based_on v{based_on}")
    return {"case_id": case_id, "version": new_version, "based_on": based_on,
            "content": content, "change_note": change_note,
            "author": actor.display_name, "created_at": ts}
