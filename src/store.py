"""持久化层：SQLite 元数据 + 原文 blob 落盘，全程只追加、不覆盖。

所有时间戳均为毫秒 epoch（见 times.py）。连接级 RLock 保证 ThreadingHTTPServer
多线程下的串行化写；进程重启后状态完整恢复（期限、待签收交接均落库）。
"""

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS actors (
  actor_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  org TEXT NOT NULL DEFAULT '',
  roles TEXT NOT NULL DEFAULT '[]'          -- JSON 数组：investigator/auditor/public_viewer
);

CREATE TABLE IF NOT EXISTS rules (
  rule_id TEXT PRIMARY KEY,                 -- 业务编号，如 NFZ-2026-01
  version INTEGER NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '{}',         -- JSON：景区/空域/高度等结构化范围
  effective_from INTEGER NOT NULL,
  effective_to INTEGER,                     -- NULL 表示现行
  supersedes TEXT NOT NULL DEFAULT '',
  created_ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  status TEXT NOT NULL,                     -- open/closed
  created_ts INTEGER NOT NULL,
  deadline_ts INTEGER NOT NULL,             -- 办案期限，落库持久，重启不丢
  closed_ts INTEGER
);

CREATE TABLE IF NOT EXISTS evidences (
  evidence_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,                       -- video/remote_id/transcript/other
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  source_org TEXT NOT NULL,
  collected_ts INTEGER NOT NULL,            -- 采集时间（来源单位口径）
  received_ts INTEGER NOT NULL,             -- 接收时间（本系统口径）
  stored_ts INTEGER NOT NULL,
  status TEXT NOT NULL,                     -- sealed/void
  storage_ref TEXT NOT NULL,                -- 内容寻址：sha256 前两级分桶
  public_summary TEXT NOT NULL,
  sensitive_identity TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS evidence_custody (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  evidence_id TEXT NOT NULL,
  action TEXT NOT NULL,                     -- ingest/transfer/receive/void/seal
  from_actor TEXT NOT NULL DEFAULT '',
  to_actor TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT '',           -- 执行作废/封存的经办人
  note TEXT NOT NULL DEFAULT '',
  ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS case_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  type TEXT NOT NULL,                      -- create/link/supplement/unlink/procedure/close
  actor_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}'        -- JSON，全部结构化
);

CREATE TABLE IF NOT EXISTS fact_versions (
  case_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  content TEXT NOT NULL,                   -- JSON 事实清单
  editor_id TEXT NOT NULL,
  base_version INTEGER NOT NULL,           -- 乐观锁基线；-1 表示新建
  ts INTEGER NOT NULL,
  PRIMARY KEY (case_id, version)
);

CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  content TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_version INTEGER NOT NULL,           -- 固定到规则版本
  fact_version INTEGER NOT NULL,           -- 固定到事实清单版本
  evidence_ids TEXT NOT NULL DEFAULT '[]', -- JSON：结论直接引用的证据
  actor_id TEXT NOT NULL,
  ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,                    -- view/download/create/...
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}'
);
"""


class Store:
    def __init__(self, data_dir: str | None = None):
        self.data_dir = Path(data_dir or os.environ.get("DATA_DIR", ".data"))
        (self.data_dir / "blobs").mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.data_dir / "case.db", check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self):
        with self._lock:
            self._conn.close()

    # ---- 基础工具 ----
    def query(self, sql, args=()):
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    def query_one(self, sql, args=()):
        rows = self.query(sql, args)
        return rows[0] if rows else None

    def execute(self, sql, args=()):
        with self._lock:
            cur = self._conn.execute(sql, args)
            self._conn.commit()
            return cur.lastrowid

    def blob_path(self, sha256: str) -> Path:
        return self.data_dir / "blobs" / sha256[:2] / sha256[2:4] / sha256

    def put_blob(self, content: bytes) -> tuple[str, int, str]:
        """内容寻址写入；相同哈希复用既有文件，绝不覆盖已有原文。返回 (sha,size,ref)。"""
        digest = hashlib.sha256(content).hexdigest()
        path = self.blob_path(digest)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(content)
            os.replace(tmp, path)  # 原子落盘
        return digest, len(content), f"blobs/{digest[:2]}/{digest[2:4]}/{digest}"

    def get_blob(self, storage_ref: str) -> bytes:
        return (self.data_dir / storage_ref).read_bytes()

    # ---- 审计 ----
    def audit(self, actor_id: str, action: str, target_type: str, target_id: str,
              detail: dict | None = None, ts: int | None = None):
        from times import now_ts

        self.execute(
            "INSERT INTO audit_logs(ts,actor_id,action,target_type,target_id,detail)"
            " VALUES (?,?,?,?,?,?)",
            (ts or now_ts(), actor_id, action, target_type, target_id,
             json.dumps(detail or {}, ensure_ascii=False)),
        )
