"""HTTP 接口层（标准库 http.server）。

每个请求在同一事务内完成：业务写入与审计先执行，事务提交成功后才向客户端发
成功响应；任何异常一律回滚。写操作由应用级锁串行化，配合 SQLite WAL。
"""

import io
import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import svc_audit
import svc_cases
import svc_decisions
import svc_evidence
import svc_facts
import svc_identity
import svc_rules
from auth import audit, authenticate, create_user
from config import Config
from database import connect, init_db
from errors import ApiError
from security import (CASE_READ, CASE_WRITE, CUSTODY_HANDLE, DECISION_WRITE,
                      EVIDENCE_DOWNLOAD, EVIDENCE_INTAKE, EVIDENCE_READ, EVIDENCE_VOID,
                      FACT_WRITE, FINDING_WRITE, IDENTITY_GRANT, PUBLIC_WRITE,
                      ARCHIVE_READ, ARCHIVE_WRITE, USER_MANAGE)
from storage import BlobStore

MAX_BODY = 512 * 1024 * 1024


class Kit:
    def __init__(self, config: Config):
        self.config = config
        self.conn = connect(config.db_path)
        init_db(self.conn)
        self.store = BlobStore(config.blob_dir)
        from security import IdentityCipher
        self.cipher = IdentityCipher.load(config.data_dir / "identity.key")
        self.lock = threading.RLock()


# ---- 响应载体：提交成功后才真正写出 -----------------------------------------

class JsonResponse:
    def __init__(self, status: int, payload):
        self.status = status
        self.payload = payload


class FileResponse:
    def __init__(self, status: int, content: bytes, content_type: str, filename: str):
        self.status = status
        self.content = content
        self.content_type = content_type
        self.filename = filename


# ---- multipart/form-data 解析（标准库） -------------------------------------

def parse_multipart(body: bytes, boundary: bytes):
    delimiter = b"--" + boundary
    fields: dict[str, str] = {}
    files: dict[str, tuple[str, str, bytes]] = {}
    for part in body.split(delimiter):
        if not part or part in (b"--", b"--\r\n", b"\r\n"):
            continue
        # 每段形如 b"\r\n<headers>\r\n\r\n<content>\r\n"，精确剥离避免伤及原件字节
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.startswith(b"--"):
            break
        if b"\r\n\r\n" not in part:
            continue
        header_blob, content = part.split(b"\r\n\r\n", 1)
        if content.endswith(b"\r\n"):
            content = content[:-2]
        headers = {}
        for line in header_blob.decode("utf-8", "replace").split("\r\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        disp = headers.get("content-disposition", "")
        name_match = re.search(r'name="([^"]+)"', disp)
        if not name_match:
            continue
        name = name_match.group(1)
        filename_match = re.search(r'filename="([^"]*)"', disp)
        if filename_match:
            files[name] = (
                filename_match.group(1),
                headers.get("content-type", "application/octet-stream"),
                content,
            )
        else:
            fields[name] = content.decode("utf-8", "replace")
    return fields, files


class Handler(BaseHTTPRequestHandler):
    kit: Kit = None  # 由 create_server 注入

    # ---- 写出（仅在事务提交后调用） ----

    def _write(self, response) -> None:
        if isinstance(response, FileResponse):
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Disposition",
                             f'attachment; filename="{response.filename}"')
            self.send_header("Content-Length", str(len(response.content)))
            self.end_headers()
            self.wfile.write(response.content)
            return
        data = json.dumps(response.payload, ensure_ascii=False).encode("utf-8")
        self.send_response(response.status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _error(self, exc: ApiError) -> None:
        data = json.dumps({"error": exc.code, "message": exc.message},
                          ensure_ascii=False).encode("utf-8")
        self.send_response(exc.status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY:
            raise ApiError("请求体超过 512MB 上限", status=413)
        return self.rfile.read(length) if length else b""

    def _json_body(self) -> dict:
        raw = self._read_body()
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ApiError(f"请求体不是合法 JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ApiError("请求体必须是 JSON 对象")
        return data

    def _actor(self):
        return authenticate(self.kit.conn, self.headers.get("X-API-Key"))

    def log_message(self, *_args):
        return

    # ---- 统一入口 ----

    def do_GET(self):  # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self):  # noqa: N802
        self._dispatch("PUT")

    def _dispatch(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(parsed.query)
        conn = self.kit.conn
        response = None
        try:
            with self.kit.lock:
                try:
                    response = self._route(method, path, query, conn)
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
        except ApiError as exc:
            self._error(exc)
            return
        except Exception as exc:  # noqa: BLE001 - 边界兜底，避免堆栈泄出
            self._error(ApiError(str(exc), status=500, code="internal"))
            return
        self._write(response)

    # ---- 路由 ----

    def _route(self, method, path, query, conn):
        if method == "GET" and path == "/health":
            return JsonResponse(200, {"status": "ok",
                                      "service": "drone-case-backend"})

        if method == "POST" and path == "/admin/bootstrap":
            return self._bootstrap(conn)

        actor = self._actor()
        ip = self.client_address[0] if self.client_address else None

        # 用户管理
        if method == "POST" and path == "/admin/users":
            actor.require(USER_MANAGE)
            return self._create_user(conn, actor)
        if method == "GET" and path == "/admin/users":
            actor.require(USER_MANAGE)
            rows = conn.execute(
                "SELECT id,username,display_name,role,active,created_at,created_by"
                " FROM users ORDER BY id").fetchall()
            audit(conn, actor, "user.list", request_ip=ip)
            return JsonResponse(200, [dict(r) for r in rows])

        # 规则
        if method == "POST" and path == "/rules":
            actor.require(CASE_WRITE)
            rule = svc_rules.create_rule(conn, actor, **self._rule_body())
            audit(conn, actor, "rule.create", object_type="rule", object_id=rule["id"],
                  request_ip=ip)
            return JsonResponse(201, rule)
        m = re.fullmatch(r"/rules/(\d+)", path)
        if method == "GET" and m:
            actor.require(CASE_READ)
            return JsonResponse(200, dict(svc_rules.get_rule(int(m.group(1)), conn)))
        m = re.fullmatch(r"/rules/([^/]+)/versions", path)
        if method == "POST" and m:
            actor.require(CASE_WRITE)
            body = self._rule_body()
            body.pop("rule_code", None)
            rule = svc_rules.update_rule(conn, actor, rule_code=m.group(1),
                                         **body)
            audit(conn, actor, "rule.new_version", object_type="rule",
                  object_id=rule["id"], request_ip=ip)
            return JsonResponse(201, rule)

        # 案件
        if method == "POST" and path == "/cases":
            actor.require(CASE_WRITE)
            case = svc_cases.create_case(conn, actor, **self._case_body())
            audit(conn, actor, "case.create", object_type="case", object_id=case["id"],
                  request_ip=ip)
            return JsonResponse(201, case)
        if method == "GET" and path == "/cases":
            actor.require(CASE_READ)
            status = query.get("status", [None])[0]
            return JsonResponse(200, svc_cases.list_cases(conn, actor, status=status))

        m = re.fullmatch(r"/cases/(\d+)", path)
        if method == "GET" and m:
            actor.require(CASE_READ)
            case_id = int(m.group(1))
            audit(conn, actor, "case.view", object_type="case", object_id=case_id,
                  request_ip=ip)
            return JsonResponse(200, svc_cases.get_case_view(conn, case_id))

        m = re.fullmatch(r"/cases/(\d+)/archive", path)
        if method == "POST" and m:
            actor.require(ARCHIVE_WRITE)
            case_id = int(m.group(1))
            result = svc_cases.archive_case(conn, actor, case_id)
            audit(conn, actor, "case.archive", object_type="case", object_id=case_id,
                  case_id=case_id, request_ip=ip)
            return JsonResponse(200, result)
        m = re.fullmatch(r"/cases/(\d+)/archive/verify", path)
        if method == "GET" and m:
            actor.require(ARCHIVE_READ)
            return JsonResponse(200, svc_cases.verify_archive(conn, int(m.group(1))))

        # 证据集合
        m = re.fullmatch(r"/cases/(\d+)/evidence", path)
        if method == "POST" and m:
            actor.require(EVIDENCE_INTAKE)
            return self._intake(conn, actor, int(m.group(1)), ip)
        if method == "GET" and m:
            actor.require(EVIDENCE_READ)
            case_id = int(m.group(1))
            audit(conn, actor, "evidence.list_view", object_type="case",
                  object_id=case_id, case_id=case_id, request_ip=ip)
            return JsonResponse(200, svc_evidence.list_case_evidence(
                conn, actor, case_id))

        # 交接
        if method == "GET" and path == "/transfers/pending":
            return JsonResponse(200, svc_evidence.pending_for_user(conn, actor))
        m = re.fullmatch(r"/transfers/(\d+)/sign", path)
        if method == "POST" and m:
            return JsonResponse(200, svc_evidence.sign_transfer(
                conn, actor, int(m.group(1))))

        # 证据单项
        m = re.fullmatch(r"/evidence/(\d+)", path)
        if method == "GET" and m:
            actor.require(EVIDENCE_READ)
            return JsonResponse(200, svc_evidence.get_evidence(
                conn, actor, int(m.group(1)), request_ip=ip))
        m = re.fullmatch(r"/evidence/(\d+)/download", path)
        if method == "GET" and m:
            actor.require(EVIDENCE_DOWNLOAD)
            row, stream = svc_evidence.open_blob(
                conn, actor, self.kit.store, int(m.group(1)), request_ip=ip)
            data = stream.read()
            stream.close()
            return FileResponse(200, data, row["media_type"],
                                f"evidence-{row['id']}-{row['digest'][:12]}.bin")
        m = re.fullmatch(r"/evidence/(\d+)/custody", path)
        if method == "GET" and m:
            actor.require(EVIDENCE_READ)
            return JsonResponse(200, svc_evidence.custody_chain(
                conn, actor, int(m.group(1))))
        m = re.fullmatch(r"/evidence/(\d+)/void", path)
        if method == "POST" and m:
            actor.require(EVIDENCE_VOID)
            body = self._json_body()
            return JsonResponse(200, svc_evidence.void_evidence(
                conn, actor, int(m.group(1)), reason=self._reason(body)))
        m = re.fullmatch(r"/evidence/(\d+)/revoke-link", path)
        if method == "POST" and m:
            actor.require(CASE_WRITE)
            body = self._json_body()
            return JsonResponse(200, svc_evidence.revoke_link(
                conn, actor, int(m.group(1)), reason=self._reason(body)))
        m = re.fullmatch(r"/evidence/(\d+)/relink", path)
        if method == "POST" and m:
            actor.require(CASE_WRITE)
            body = self._json_body()
            to_case = body.get("to_case_id")
            if not isinstance(to_case, int):
                raise ApiError("to_case_id 必须是整数")
            return JsonResponse(200, svc_evidence.relink(
                conn, actor, int(m.group(1)), to_case_id=to_case,
                note=body.get("note")))
        m = re.fullmatch(r"/evidence/(\d+)/transfer", path)
        if method == "POST" and m:
            actor.require(CUSTODY_HANDLE)
            body = self._json_body()
            to_user = body.get("to_user_id")
            if not isinstance(to_user, int):
                raise ApiError("to_user_id 必须是整数")
            return JsonResponse(201, svc_evidence.transfer(
                conn, actor, int(m.group(1)), to_user_id=to_user,
                note=body.get("note")))
        m = re.fullmatch(r"/evidence/(\d+)/public-summaries", path)
        if method == "POST" and m:
            actor.require(PUBLIC_WRITE)
            body = self._json_body()
            content = body.get("content")
            if not isinstance(content, str):
                raise ApiError("content 必须是字符串")
            return JsonResponse(201, svc_evidence.add_public_summary(
                conn, actor, int(m.group(1)), content=content))
        m = re.fullmatch(r"/evidence/(\d+)/public-summary", path)
        if method == "GET" and m:
            # 任何有效登录用户（含只读 viewer）都可看脱敏摘要，不触碰原件
            evidence_id = int(m.group(1))
            summary = svc_evidence.public_summary_view(conn, evidence_id)
            audit(conn, actor, "public_summary.view", object_type="evidence",
                  object_id=evidence_id, request_ip=ip)
            return JsonResponse(200, summary)

        # 敏感身份
        m = re.fullmatch(r"/cases/(\d+)/identities", path)
        if method == "POST" and m:
            actor.require(CASE_WRITE)
            body = self._json_body()
            return JsonResponse(201, svc_identity.seal_identity(
                conn, actor, self.kit.cipher, int(m.group(1)),
                label=str(body.get("label", "")), data=body.get("data")))
        if method == "GET" and m:
            actor.require(CASE_READ)
            case_id = int(m.group(1))
            audit(conn, actor, "identity.list_view", object_type="case",
                  object_id=case_id, case_id=case_id, request_ip=ip)
            return JsonResponse(200, svc_identity.list_case_identities(
                conn, actor, case_id))
        m = re.fullmatch(r"/cases/(\d+)/identities/(\d+)/(grant|revoke)", path)
        if method == "POST" and m:
            actor.require(IDENTITY_GRANT)
            body = self._json_body()
            user_id = body.get("user_id")
            if not isinstance(user_id, int):
                raise ApiError("user_id 必须是整数")
            case_id, identity_id = int(m.group(1)), int(m.group(2))
            if m.group(3) == "grant":
                result = svc_identity.grant(conn, actor, case_id, identity_id,
                                            user_id=user_id)
            else:
                result = svc_identity.revoke_grant(conn, actor, case_id, identity_id,
                                                   user_id=user_id)
            return JsonResponse(200, result)
        m = re.fullmatch(r"/cases/(\d+)/identities/(\d+)/reveal", path)
        if method == "POST" and m:
            actor.require(CASE_READ)
            return JsonResponse(200, svc_identity.reveal(
                conn, actor, self.kit.cipher, int(m.group(1)), int(m.group(2))))

        # 事实清单
        m = re.fullmatch(r"/cases/(\d+)/facts", path)
        if method == "GET" and m:
            actor.require(CASE_READ)
            case_id = int(m.group(1))
            audit(conn, actor, "fact.view", object_type="case", object_id=case_id,
                  case_id=case_id, request_ip=ip)
            return JsonResponse(200, svc_facts.get_current(
                conn, actor, case_id))
        if method == "PUT" and m:
            actor.require(FACT_WRITE)
            body = self._json_body()
            based_on = body.get("based_on")
            if not isinstance(based_on, int):
                raise ApiError("based_on 必须是整数（乐观锁基线版本号）")
            result = svc_facts.save(
                conn, actor, int(m.group(1)), content=body.get("content"),
                based_on=based_on, change_note=str(body.get("change_note", "")))
            return JsonResponse(201, result)
        m = re.fullmatch(r"/cases/(\d+)/facts/versions", path)
        if method == "GET" and m:
            actor.require(CASE_READ)
            case_id = int(m.group(1))
            audit(conn, actor, "fact.versions_view", object_type="case",
                  object_id=case_id, case_id=case_id, request_ip=ip)
            return JsonResponse(200, svc_facts.list_versions(conn, actor, case_id))
        m = re.fullmatch(r"/cases/(\d+)/facts/versions/(\d+)", path)
        if method == "GET" and m:
            actor.require(CASE_READ)
            case_id = int(m.group(1))
            audit(conn, actor, "fact.version_view", object_type="fact_version",
                  object_id=int(m.group(2)), case_id=case_id, request_ip=ip)
            return JsonResponse(200, svc_facts.get_version(
                case_id, int(m.group(2))))

        # 决定
        m = re.fullmatch(r"/cases/(\d+)/decisions", path)
        if method == "POST" and m:
            body = self._json_body()
            kind = body.get("kind")
            scope = FINDING_WRITE if kind in ("finding", "supplement_notice") \
                else DECISION_WRITE
            actor.require(scope)
            return JsonResponse(201, svc_decisions.create_decision(
                conn, actor, int(m.group(1)), body))
        if method == "GET" and m:
            actor.require(CASE_READ)
            case_id = int(m.group(1))
            include = query.get("include_superseded", ["1"])[0] != "0"
            audit(conn, actor, "decision.list_view", object_type="case",
                  object_id=case_id, case_id=case_id, request_ip=ip)
            return JsonResponse(200, svc_decisions.list_case_decisions(
                conn, case_id, include_superseded=include))
        m = re.fullmatch(r"/decisions/(\d+)", path)
        if method == "GET" and m:
            actor.require(CASE_READ)
            return JsonResponse(200, svc_decisions.get_decision(
                conn, int(m.group(1))))
        m = re.fullmatch(r"/decisions/(\d+)/trace", path)
        if method == "GET" and m:
            actor.require(CASE_READ)
            decision_id = int(m.group(1))
            decision = svc_decisions.get_decision(conn, decision_id)
            audit(conn, actor, "decision.trace", object_type="decision",
                  object_id=decision_id, case_id=decision["case_id"], request_ip=ip)
            return JsonResponse(200, svc_decisions.trace(conn, decision_id))
        m = re.fullmatch(r"/decisions/(\d+)/supersede", path)
        if method == "POST" and m:
            if not (actor.has(FINDING_WRITE) or actor.has(DECISION_WRITE)):
                actor.require(FINDING_WRITE)
            body = self._json_body()
            return JsonResponse(200, svc_decisions.supersede_decision(
                conn, actor, int(m.group(1)), reason=self._reason(body)))

        # 审计
        if method == "GET" and path == "/audit":
            return JsonResponse(200, svc_audit.query(
                conn, actor,
                case_id=query.get("case_id", [None])[0],
                object_type=query.get("object_type", [None])[0],
                object_id=query.get("object_id", [None])[0],
                action=query.get("action", [None])[0],
                limit=int(query.get("limit", ["200"])[0])))

        return JsonResponse(404, {"error": "not_found",
                                  "message": f"无此路由: {path}"})

    # ---- 请求体辅助 ----

    def _bootstrap(self, conn):
        count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if count:
            raise ApiError("系统已初始化，引导接口已关闭", status=403)
        body = self._json_body() if self.headers.get("Content-Length") else {}
        username = body.get("username") or "admin"
        display = body.get("display_name") or "系统管理员"
        user_id, plain = create_user(conn, username, display, "officer", "bootstrap")
        audit(conn, None, "user.bootstrap", object_type="user", object_id=user_id)
        return JsonResponse(201, {
            "id": user_id, "username": username, "role": "officer",
            "api_key": plain,
            "warning": "api_key 仅显示这一次，请立即妥善保存",
        })

    def _create_user(self, conn, actor):
        body = self._json_body()
        for field in ("username", "display_name", "role"):
            if not isinstance(body.get(field), str) or not body[field].strip():
                raise ApiError(f"{field} 不能为空")
        user_id, plain = create_user(
            conn, body["username"], body["display_name"], body["role"],
            actor.display_name)
        audit(conn, actor, "user.create", object_type="user", object_id=user_id,
              detail=f"role={body['role']}")
        return JsonResponse(201, {
            "id": user_id, "username": body["username"],
            "display_name": body["display_name"], "role": body["role"],
            "api_key": plain,
            "warning": "api_key 仅显示这一次，请立即妥善保存",
        })

    def _rule_body(self) -> dict:
        body = self._json_body()
        for field in ("rule_code", "title", "zone_geojson"):
            if not isinstance(body.get(field), str) or not body[field].strip():
                raise ApiError(f"{field} 不能为空")
        return {
            "rule_code": body["rule_code"], "title": body["title"],
            "zone_geojson": body["zone_geojson"],
            "altitude_max": body.get("altitude_max"),
            "effective_from": body.get("effective_from"),
        }

    def _case_body(self) -> dict:
        body = self._json_body()
        for field in ("case_no", "title"):
            if not isinstance(body.get(field), str) or not body[field].strip():
                raise ApiError(f"{field} 不能为空")
        return {
            "case_no": body["case_no"], "title": body["title"],
            "location": body.get("location"),
            "incident_at": body.get("incident_at"),
            "deadline_days": body.get("deadline_days", 30),
        }

    def _reason(self, body: dict) -> str:
        reason = body.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ApiError("reason 不能为空")
        return reason

    def _intake(self, conn, actor, case_id: int, ip: str):
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            raise ApiError("证据入库必须使用 multipart/form-data 上传 file 字段")
        boundary_match = re.search(r"boundary=([^;]+)", ctype)
        if not boundary_match:
            raise ApiError("multipart 缺少 boundary")
        fields, files = parse_multipart(
            self._read_body(), boundary_match.group(1).strip().encode())
        if "file" not in files:
            raise ApiError("缺少 file 字段（原件）")
        filename, file_ctype, content = files["file"]
        for field in ("kind", "source_unit", "collected_at"):
            if not fields.get(field):
                raise ApiError(f"表单字段 {field} 不能为空")
        result = svc_evidence.intake_evidence(
            conn, actor, self.kit.store, io.BytesIO(content),
            case_id=case_id, kind=fields["kind"],
            source_unit=fields["source_unit"],
            collected_at=fields["collected_at"],
            media_type=fields.get("media_type") or file_ctype,
            source_reference=fields.get("source_reference") or filename or None,
            note=fields.get("note"))
        return JsonResponse(201, result)


def create_server(config: Config | None = None):
    config = config or Config.load()
    kit = Kit(config)
    Handler.kit = kit

    class _Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = _Server((config.host, config.port), Handler)
    server.kit = kit
    return server
