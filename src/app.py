"""违规飞行案件后端 HTTP 入口（标准库，无第三方依赖）。

鉴权：X-Actor-Id 请求头指定经办人；角色在登记时授予。
所有请求/响应均为 JSON（证据下载为原始字节），时间一律带时区 ISO 8601。
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import services
from services import ApiError, parse_time
from store import Store

SERVICE_NAME = "drone-case-backend"

STORE: Store | None = None


def store() -> Store:
    global STORE
    if STORE is None:
        STORE = Store(os.environ.get("DATA_DIR", ".data"))
    return STORE


def _json_response(handler, status: int, body: dict | list):
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _bytes_response(handler, status: int, data: bytes, filename: str, ctype: str):
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Disposition",
                        f'attachment; filename="{filename}"')
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _read_body(handler) -> dict:
    length = int(handler.headers.get("Content-Length") or 0)
    if length == 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        body = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApiError(400, "json_invalid") from exc
    if not isinstance(body, dict):
        raise ApiError(400, "body_object_required")
    return body


def _actor(handler):
    return services.load_actor(store(), handler.headers.get("X-Actor-Id"))


def _segments(path: str):
    return [p for p in urlparse(path).path.split("/") if p]


def _query(path: str) -> dict:
    return {k: v[0] for k, v in parse_qs(urlparse(path).query).items()}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        try:
            self._route_get()
        except ApiError as exc:
            _json_response(self, exc.status, {"error": exc.code, "message": exc.message})
        except Exception as exc:  # noqa: BLE001
            _json_response(self, 500, {"error": "internal_error", "message": str(exc)})

    def do_POST(self):  # noqa: N802
        try:
            self._route_post()
        except ApiError as exc:
            _json_response(self, exc.status, {"error": exc.code, "message": exc.message})
        except Exception as exc:  # noqa: BLE001
            _json_response(self, 500, {"error": "internal_error", "message": str(exc)})

    def log_message(self, *_args):
        return

    # ---------- GET ----------
    def _route_get(self):
        seg = _segments(self.path)

        if seg == ["health"]:
            _json_response(self, 200, {"status": "ok", "service": SERVICE_NAME})
            return
        actor = _actor(self)
        if seg == ["actors"]:
            _json_response(self, 200, services.list_actors(store()))
            return
        if seg == ["rules"]:
            _json_response(self, 200, services.list_rules(store(), actor))
            return
        if len(seg) == 2 and seg[0] == "rules":
            q = _query(self.path)
            if q.get("version"):
                result = services.get_rule(store(), seg[1], int(q["version"]))
            elif q.get("at"):
                result = services.get_rule(store(), seg[1], at_ts=parse_time(q["at"]))
            else:
                result = services.get_rule(store(), seg[1])
            _json_response(self, 200, result)
            return
        if seg == ["evidences"]:
            _json_response(self, 200, services.list_evidences(store(), actor))
            return
        if seg == ["transfers", "pending"]:
            _json_response(self, 200, services.list_pending_transfers(store(), actor))
            return
        if len(seg) == 2 and seg[0] == "evidences":
            _json_response(self, 200, services.get_evidence_meta(store(), seg[1], actor))
            return
        if len(seg) == 3 and seg[0] == "evidences" and seg[2] == "download":
            meta, data = services.download_evidence(store(), seg[1], actor)
            ext = {"video": "bin", "remote_id": "json", "transcript": "txt"}.get(
                meta["kind"], "bin")
            _bytes_response(self, 200, data, f"{seg[1]}.{ext}",
                            "application/octet-stream")
            return
        if len(seg) == 3 and seg[0] == "evidences" and seg[2] == "custody":
            _json_response(self, 200, services.custody_chain(store(), seg[1], actor))
            return
        if seg == ["cases"]:
            _json_response(self, 200, services.list_cases(store(), actor))
            return
        if seg == ["dashboard"]:
            _json_response(self, 200, services.dashboard(store(), actor))
            return
        if seg == ["audit"]:
            _json_response(self, 200, services.query_audit(store(), actor, _query(self.path)))
            return
        if len(seg) == 2 and seg[0] == "cases":
            _json_response(self, 200, services.get_case(store(), seg[1], actor))
            return
        if len(seg) == 3 and seg[0] == "cases" and seg[2] == "timeline":
            q = _query(self.path)
            as_of = parse_time(q["as_of"]) if q.get("as_of") else None
            _json_response(self, 200, services.timeline(store(), seg[1], actor, as_of))
            return
        if len(seg) == 3 and seg[0] == "cases" and seg[2] == "facts":
            q = _query(self.path)
            version = int(q["version"]) if q.get("version") else None
            _json_response(self, 200, services.get_facts(store(), seg[1], version, actor))
            return
        if len(seg) == 3 and seg[0] == "cases" and seg[2] == "findings":
            _json_response(self, 200, services.list_findings(store(), seg[1], actor))
            return
        if len(seg) == 4 and seg[0] == "cases" and seg[2] == "evidences":
            _json_response(self, 200, services.list_evidences(
                store(), actor, case_id=seg[1]))
            return
        if len(seg) == 2 and seg[0] == "findings":
            _json_response(self, 200, services.get_finding(store(), seg[1], actor))
            return
        if len(seg) == 3 and seg[0] == "findings" and seg[2] == "trace":
            _json_response(self, 200, services.trace_finding(store(), seg[1], actor))
            return
        _json_response(self, 404, {"error": "not_found"})

    # ---------- POST ----------
    def _route_post(self):
        seg = _segments(self.path)
        if seg == ["actors"]:  # 登记经办人（引导接口）
            _json_response(self, 201, services.register_actor(store(), _read_body(self)))
            return
        actor = _actor(self)
        body = _read_body(self)

        if seg == ["rules"]:
            _json_response(self, 201, services.create_rule(store(), actor, body))
            return
        if seg == ["evidences"]:
            _json_response(self, 201, services.ingest_evidence(store(), actor, body))
            return
        if len(seg) == 3 and seg[0] == "evidences" and seg[2] == "transfer":
            _json_response(self, 200, services.transfer_evidence(
                store(), actor, seg[1], body))
            return
        if len(seg) == 3 and seg[0] == "evidences" and seg[2] == "receive":
            _json_response(self, 200, services.receive_evidence(
                store(), actor, seg[1], body))
            return
        if len(seg) == 3 and seg[0] == "evidences" and seg[2] == "recall":
            _json_response(self, 200, services.recall_transfer(
                store(), actor, seg[1], body))
            return
        if len(seg) == 3 and seg[0] == "evidences" and seg[2] == "void":
            _json_response(self, 200, services.void_evidence(
                store(), actor, seg[1], body))
            return
        if seg == ["cases"]:
            _json_response(self, 201, services.create_case(store(), actor, body))
            return
        if len(seg) == 3 and seg[0] == "cases" and seg[2] == "evidences":
            _json_response(self, 201, services.link_evidence(
                store(), actor, seg[1], body))
            return
        if len(seg) == 3 and seg[0] == "cases" and seg[2] == "supplements":
            _json_response(self, 201, services.link_evidence(
                store(), actor, seg[1], body, supplement=True))
            return
        if len(seg) == 4 and seg[0] == "cases" and seg[2] == "evidences":
            _json_response(self, 200, services.unlink_evidence(
                store(), actor, seg[1], seg[3], body))
            return
        if len(seg) == 3 and seg[0] == "cases" and seg[2] == "facts":
            _json_response(self, 200, services.put_facts(store(), actor, seg[1], body))
            return
        if len(seg) == 3 and seg[0] == "cases" and seg[2] == "findings":
            _json_response(self, 201, services.create_finding(
                store(), actor, seg[1], body))
            return
        if len(seg) == 3 and seg[0] == "cases" and seg[2] == "decisions":
            _json_response(self, 201, services.record_decision(
                store(), actor, seg[1], body))
            return
        if len(seg) == 3 and seg[0] == "cases" and seg[2] == "close":
            _json_response(self, 200, services.close_case(store(), actor, seg[1], body))
            return
        _json_response(self, 404, {"error": "not_found"})


def create_server():
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    return ThreadingHTTPServer((host, port), Handler)
