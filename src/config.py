"""运行时配置。数据落盘位置一律由配置指定，测试不得依赖主机隐藏状态。"""

import os
import pathlib
import secrets


class Config:
    def __init__(self, data_dir: pathlib.Path, host: str, port: int, auth_secret: str):
        self.data_dir = data_dir
        self.db_path = data_dir / "cases.db"
        self.blob_dir = data_dir / "blobs"
        self.host = host
        self.port = port
        self.auth_secret = auth_secret

    @classmethod
    def load(cls, data_dir: str | pathlib.Path | None = None,
             host: str | None = None, port: int | None = None) -> "Config":
        path = pathlib.Path(
            data_dir
            or os.environ.get("DATA_DIR")
            or pathlib.Path.cwd() / "data"
        ).resolve()
        path.mkdir(parents=True, exist_ok=True)
        secret_file = path / "auth_secret"
        secret = os.environ.get("AUTH_SECRET")
        if not secret:
            if secret_file.exists():
                secret = secret_file.read_text(encoding="utf-8").strip()
            else:
                secret = secrets.token_hex(32)
                secret_file.write_text(secret, encoding="utf-8")
                secret_file.chmod(0o600)
        return cls(
            data_dir=path,
            host=host or os.environ.get("HOST", "0.0.0.0"),
            port=int(port if port is not None else os.environ.get("PORT", "8000")),
            auth_secret=secret,
        )
