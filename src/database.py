"""SQLite 落库与建表。

不变式（由触发器在数据库层强制执行，绕过服务代码也不成立）：
1. 原始证据记录只允许 INSERT；UPDATE 仅放行 sealed -> voided 这一种状态翻转且
   其余列必须原样不动；DELETE 一律拒绝。作废另写 void_marks 追加记录。
2. 证据与案件的关联是独立的追加表 evidence_links；关联错误时写撤销标记，
   证据本体及其采集口径永远不动，之后可重新关联到正确案件。
3. 保管链 custody_events、审计 audit_log、事实版本 fact_versions 只允许 INSERT。
4. 决定 decisions 禁止删除，错误结论只能置 superseded 并留痕。
"""

import sqlite3

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role         TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL,
    created_by   TEXT
);

-- 禁飞规则：结论引用“当时适用”的规则行；规则更新产生新行并回指旧行，历史指针不漂移
CREATE TABLE IF NOT EXISTS nofly_rules (
    id            INTEGER PRIMARY KEY,
    rule_code     TEXT NOT NULL,
    title         TEXT NOT NULL,
    zone_geojson  TEXT NOT NULL,
    altitude_max  REAL,
    effective_from TEXT NOT NULL,
    effective_to  TEXT,
    superseded_by INTEGER REFERENCES nofly_rules(id),
    created_at    TEXT NOT NULL,
    created_by    TEXT,
    UNIQUE (rule_code, effective_from)
);

CREATE TABLE IF NOT EXISTS cases (
    id              INTEGER PRIMARY KEY,
    case_no         TEXT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','supplementing','decided','archived')),
    location        TEXT,
    incident_at     TEXT,
    reported_by     TEXT,
    deadline        TEXT NOT NULL,          -- 持久化：重启后期限连续计算
    created_at      TEXT NOT NULL,
    created_by      TEXT,
    archived_at     TEXT,
    archive_ref     TEXT,
    archive_manifest TEXT
);

-- 证据：digest/来源/采集时间/接收时间在登记时固定。intake_case_id 仅作出处，不可变。
CREATE TABLE IF NOT EXISTS evidence (
    id               INTEGER PRIMARY KEY,
    intake_case_id   INTEGER NOT NULL REFERENCES cases(id),
    kind             TEXT NOT NULL CHECK (kind IN ('video','remote_id','record','other')),
    source_unit      TEXT NOT NULL,
    source_reference TEXT,
    collected_at     TEXT NOT NULL,          -- 出具单位采集时间（保留原口径，仅格式归一）
    received_at      TEXT NOT NULL,          -- 本机关接收时间（服务器时钟）
    registered_at    TEXT NOT NULL,          -- 入库固定时间
    media_type       TEXT NOT NULL,
    size_bytes       INTEGER NOT NULL,
    digest_alg       TEXT NOT NULL DEFAULT 'sha256',
    digest           TEXT NOT NULL,
    blob_path        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'sealed'
                     CHECK (status IN ('sealed','voided')),
    registered_by    TEXT NOT NULL,
    intaker_user_id  INTEGER REFERENCES users(id)
);

-- 证据-案件关联（追加），当前有效性由 link_revocations 是否存在决定
CREATE TABLE IF NOT EXISTS evidence_links (
    id           INTEGER PRIMARY KEY,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id),
    case_id      INTEGER NOT NULL REFERENCES cases(id),
    linked_by    TEXT NOT NULL,
    linked_by_id INTEGER REFERENCES users(id),
    linked_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_vault (
    id           INTEGER PRIMARY KEY,
    label        TEXT NOT NULL,
    ciphertext   BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_identities (
    id           INTEGER PRIMARY KEY,
    case_id      INTEGER NOT NULL REFERENCES cases(id),
    identity_id  INTEGER NOT NULL REFERENCES identity_vault(id),
    linked_by    TEXT NOT NULL,
    linked_at    TEXT NOT NULL,
    UNIQUE (case_id, identity_id)
);

-- 逐案逐人授权；撤销是追加一行 revoked_at，不删除授权历史
CREATE TABLE IF NOT EXISTS case_identity_grants (
    id            INTEGER PRIMARY KEY,
    case_id       INTEGER NOT NULL REFERENCES cases(id),
    identity_id   INTEGER NOT NULL REFERENCES identity_vault(id),
    user_id       INTEGER NOT NULL REFERENCES users(id),
    granted_by    TEXT NOT NULL,
    granted_at    TEXT NOT NULL,
    revoked_at    TEXT,
    UNIQUE (case_id, identity_id, user_id)
);

CREATE TABLE IF NOT EXISTS void_marks (
    id           INTEGER PRIMARY KEY,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id),
    reason       TEXT NOT NULL,
    marked_by    TEXT NOT NULL,
    marked_at    TEXT NOT NULL
);

-- 可公开摘要：独立追加表，单独 public:write 授权；查看不需要 identity 授权。
-- 每次修订都是新版本，保留脱敏处理人与时间，不覆盖原件或此前摘要。
CREATE TABLE IF NOT EXISTS public_summaries (
    id           INTEGER PRIMARY KEY,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id),
    version      INTEGER NOT NULL,
    content      TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_by_id INTEGER REFERENCES users(id),
    created_at   TEXT NOT NULL,
    UNIQUE (evidence_id, version)
);

CREATE TABLE IF NOT EXISTS custody_events (
    id           INTEGER PRIMARY KEY,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id),
    action       TEXT NOT NULL CHECK (action IN
                 ('intake','transfer','receive_sign','inspect','download','void')),
    actor        TEXT NOT NULL,
    actor_id     INTEGER REFERENCES users(id),
    from_holder  TEXT,
    to_holder    TEXT,
    note         TEXT,
    occurred_at  TEXT NOT NULL
);

-- 待签收交接持久化，服务重启不丢失
CREATE TABLE IF NOT EXISTS pending_transfers (
    id           INTEGER PRIMARY KEY,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id),
    to_user_id   INTEGER NOT NULL REFERENCES users(id),
    from_holder  TEXT,
    note         TEXT,
    created_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','signed','cancelled')),
    signed_at    TEXT
);

-- 事实清单：版本只追加；based_on 是乐观锁基线，冲突时服务返回 409
CREATE TABLE IF NOT EXISTS fact_versions (
    id           INTEGER PRIMARY KEY,
    case_id      INTEGER NOT NULL REFERENCES cases(id),
    version      INTEGER NOT NULL,
    content      TEXT NOT NULL,
    change_note  TEXT NOT NULL,
    based_on     INTEGER,
    author       TEXT NOT NULL,
    author_id    INTEGER REFERENCES users(id),
    created_at   TEXT NOT NULL,
    UNIQUE (case_id, version)
);

CREATE TABLE IF NOT EXISTS case_fact_head (
    case_id      INTEGER PRIMARY KEY REFERENCES cases(id),
    version      INTEGER NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id           INTEGER PRIMARY KEY,
    case_id      INTEGER NOT NULL REFERENCES cases(id),
    kind         TEXT NOT NULL CHECK (kind IN
                 ('finding','supplement_notice','penalty_notice','penalty_decision','closure')),
    title        TEXT NOT NULL,
    content      TEXT NOT NULL,
    rule_id      INTEGER REFERENCES nofly_rules(id), -- 作出时固定的规则快照指针
    fact_version INTEGER,                            -- 作出时固定的事实版本
    seq          INTEGER NOT NULL,
    made_by      TEXT NOT NULL,
    made_by_id   INTEGER REFERENCES users(id),
    made_at      TEXT NOT NULL,
    superseded   INTEGER NOT NULL DEFAULT 0,
    superseded_reason TEXT,
    superseded_at TEXT
);

-- 引用关系图：结论 -> 证据 / 事实版本 / 规则 / 前序决定 / 身份，溯源沿此回溯
CREATE TABLE IF NOT EXISTS decision_refs (
    id           INTEGER PRIMARY KEY,
    decision_id  INTEGER NOT NULL REFERENCES decisions(id),
    ref_type     TEXT NOT NULL CHECK (ref_type IN
                 ('evidence','fact_version','rule','prior_decision','identity')),
    ref_id       INTEGER NOT NULL,
    note         TEXT,
    created_at   TEXT NOT NULL
);

-- 补证：补交材料只影响其后的判断；引用关系在决定作出时固定，不倒置历史程序
CREATE TABLE IF NOT EXISTS supplements (
    id           INTEGER PRIMARY KEY,
    case_id      INTEGER NOT NULL REFERENCES cases(id),
    decision_id  INTEGER REFERENCES decisions(id),
    reason       TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    due_at       TEXT,
    closed_at    TEXT
);

CREATE TABLE IF NOT EXISTS link_revocations (
    id             INTEGER PRIMARY KEY,
    case_id        INTEGER NOT NULL REFERENCES cases(id),
    target_type    TEXT NOT NULL CHECK (target_type IN ('evidence_link','decision')),
    target_id      INTEGER NOT NULL,
    reason         TEXT NOT NULL,
    revoked_by     TEXT NOT NULL,
    revoked_by_id  INTEGER REFERENCES users(id),
    revoked_at     TEXT NOT NULL,
    prior_decision_id INTEGER REFERENCES decisions(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY,
    actor        TEXT NOT NULL,
    actor_id     INTEGER,
    action       TEXT NOT NULL,
    object_type  TEXT,
    object_id    INTEGER,
    case_id      INTEGER,
    detail       TEXT,
    occurred_at  TEXT NOT NULL,
    request_ip   TEXT
);

-- ===== 追加封存触发器 ========================================================

CREATE TRIGGER IF NOT EXISTS trg_evidence_no_update BEFORE UPDATE ON evidence
BEGIN
    SELECT CASE WHEN NOT (
        OLD.status = 'sealed' AND NEW.status = 'voided'
        AND NEW.id IS OLD.id
        AND NEW.intake_case_id IS OLD.intake_case_id
        AND NEW.kind IS OLD.kind
        AND NEW.source_unit IS OLD.source_unit
        AND NEW.source_reference IS OLD.source_reference
        AND NEW.collected_at IS OLD.collected_at
        AND NEW.received_at IS OLD.received_at
        AND NEW.registered_at IS OLD.registered_at
        AND NEW.media_type IS OLD.media_type
        AND NEW.size_bytes IS OLD.size_bytes
        AND NEW.digest_alg IS OLD.digest_alg
        AND NEW.digest IS OLD.digest
        AND NEW.blob_path IS OLD.blob_path
        AND NEW.registered_by IS OLD.registered_by
        AND NEW.intaker_user_id IS OLD.intaker_user_id
    ) THEN
        RAISE(ABORT, 'evidence 为封存记录：仅允许 sealed->voided 作废翻转，其余字段不可改')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_evidence_no_delete BEFORE DELETE ON evidence
BEGIN
    SELECT RAISE(ABORT, 'evidence 为封存记录：禁止 DELETE，作废请写 void_marks');
END;

CREATE TRIGGER IF NOT EXISTS trg_custody_no_update BEFORE UPDATE ON custody_events
BEGIN
    SELECT RAISE(ABORT, 'custody_events 只允许追加');
END;

CREATE TRIGGER IF NOT EXISTS trg_custody_no_delete BEFORE DELETE ON custody_events
BEGIN
    SELECT RAISE(ABORT, 'custody_events 禁止删除');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log 只允许追加');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log 禁止删除');
END;

CREATE TRIGGER IF NOT EXISTS trg_fact_no_update BEFORE UPDATE ON fact_versions
BEGIN
    SELECT RAISE(ABORT, 'fact_versions 只允许追加新版本');
END;

CREATE TRIGGER IF NOT EXISTS trg_fact_no_delete BEFORE DELETE ON fact_versions
BEGIN
    SELECT RAISE(ABORT, 'fact_versions 禁止删除');
END;

CREATE TRIGGER IF NOT EXISTS trg_decision_no_delete BEFORE DELETE ON decisions
BEGIN
    SELECT RAISE(ABORT, 'decisions 禁止删除，错误结论请走撤销(superseded)程序');
END;

CREATE INDEX IF NOT EXISTS idx_links_case ON evidence_links(case_id);
CREATE INDEX IF NOT EXISTS idx_links_evidence ON evidence_links(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_events(evidence_id);
CREATE INDEX IF NOT EXISTS idx_decision_case ON decisions(case_id);
CREATE INDEX IF NOT EXISTS idx_refs_decision ON decision_refs(decision_id);
CREATE INDEX IF NOT EXISTS idx_refs_object ON decision_refs(ref_type, ref_id);
CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id);
CREATE INDEX IF NOT EXISTS idx_pending_to ON pending_transfers(to_user_id, status);
"""


def connect(db_path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()
