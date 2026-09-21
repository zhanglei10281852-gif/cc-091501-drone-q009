"""测试辅助：临时数据目录、HTTP 客户端、multipart 编码。"""

import io
import json
import pathlib
import sys
import tempfile
import threading
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from api import create_server  # noqa: E402
from config import Config  # noqa: E402


class Client:
    def __init__(self, server, key=None):
        self.server = server
        self.key = key

    def with_key(self, key):
        return Client(self.server, key)

    def _request(self, method, path, body=None, raw=None, content_type=None):
        url = f"http://127.0.0.1:{self.server.server_port}{path}"
        headers = {}
        data = None
        if raw is not None:
            data = raw
            headers["Content-Type"] = content_type or "application/octet-stream"
        elif body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        if self.key:
            headers["X-API-Key"] = self.key
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read()
                ctype = resp.headers.get("Content-Type", "")
                if "application/json" in ctype:
                    return resp.status, json.loads(payload.decode("utf-8"))
                return resp.status, payload
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                return exc.code, json.loads(payload.decode("utf-8"))
            except ValueError:
                return exc.code, payload

    def get(self, path):
        return self._request("GET", path)

    def post(self, path, body=None):
        return self._request("POST", path, body=body)

    def put(self, path, body=None):
        return self._request("PUT", path, body=body)

    def upload(self, path, *, fields, file_field="file", filename="v.mp4",
               content=b"\x00\x01BINARY\xff\xfe",
               file_ctype="video/mp4"):
        boundary = "----caseboundary" + uuid.uuid4().hex
        buffer = io.BytesIO()
        for name, value in fields.items():
            buffer.write(f"--{boundary}\r\n".encode())
            buffer.write(
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
            buffer.write(str(value).encode("utf-8"))
            buffer.write(b"\r\n")
        buffer.write(f"--{boundary}\r\n".encode())
        buffer.write(
            f'Content-Disposition: form-data; name="{file_field}";'
            f' filename="{filename}"\r\n'.encode())
        buffer.write(f"Content-Type: {file_ctype}\r\n\r\n".encode())
        buffer.write(content)
        buffer.write(f"\r\n--{boundary}--\r\n".encode())
        return self._request("POST", path, raw=buffer.getvalue(),
                             content_type=f"multipart/form-data; boundary={boundary}")


class ServerHarness:
    def __init__(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="case-test-"))
        self.config = Config.load(self.tmp, host="127.0.0.1", port=0)
        self.server = create_server(self.config)
        # 固定首个随机端口，restart 时沿用同一端口，客户端连接不受影响
        self.config.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def restart(self):
        """模拟服务重启：新进程同一数据目录，期限与待签收交接必须保留。"""
        self.stop()
        self.server = create_server(self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
