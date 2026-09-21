"""兼容入口：实际服务在 api 模块。"""

from api import create_server  # noqa: F401

SERVICE_NAME = "drone-case-backend"
