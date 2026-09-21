"""端到端测试：证据 WORM、保管交接、案件时间轴、版本冲突、引用回溯、重启持久化。

每个用例使用独立临时 DATA_DIR，不依赖主机隐藏状态（见 docs/domain.md）。
"""

import base64
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import app  # noqa: E402


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class CaseBackendTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.environ["DATA_DIR"] = self.tmp.name
        app.STORE = None
        self.server = app.create_server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def _shutdown(self):
        self.server.shutdown()
        self.server.server_close()
        if app.STORE is not None:
            app.STORE.close()
        app.STORE = None

    def call(self, method, path, body=None, actor=None, raw=False):
        data = None
        headers = {"Content-Type": "application/json"}
        if actor:
            headers["X-Actor-Id"] = actor
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read()
                if raw:
                    return resp.status, payload
                return resp.status, json.loads(payload)
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            if raw:
                return exc.code, payload
            return exc.code, json.loads(payload)

    def restart_server(self):
        """模拟服务重启：同一 DATA_DIR 重新打开。"""
        self.server.shutdown()
        self.server.server_close()
        app.STORE.close()
        app.STORE = None
        self.server = app.create_server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    # ---- 引导 ----
    def bootstrap(self):
        self.call("POST", "/actors", {
            "actor_id": "inv1", "name": "张办案", "org": "景区执法大队",
            "roles": ["investigator"]})
        self.call("POST", "/actors", {
            "actor_id": "inv2", "name": "李保管", "org": "景区执法大队",
            "roles": ["investigator"]})
        self.call("POST", "/actors", {
            "actor_id": "aud1", "name": "王审计", "org": "法制处",
            "roles": ["auditor", "investigator"]})
        self.call("POST", "/actors", {
            "actor_id": "pub1", "name": "公开查询席", "org": "服务窗口",
            "roles": ["public_viewer"]})

    def test_01_health_baseline_unchanged(self):
        status, body = self.call("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], app.SERVICE_NAME)

    def test_02_auth_required_and_forbidden(self):
        self.bootstrap()
        status, body = self.call("GET", "/cases")
        self.assertEqual((status, body["error"]), (401, "actor_required"))
        status, body = self.call("GET", "/cases", actor="nobody")
        self.assertEqual((status, body["error"]), (401, "actor_unknown"))
        status, body = self.call("POST", "/rules",
                                 {"rule_id": "X", "title": "t", "content": "c",
                                  "effective_from": "2026-01-01T00:00:00+08:00"},
                                 actor="pub1")
        self.assertEqual((status, body["error"]), (403, "forbidden"))

    def test_03_time_must_be_timezone_aware(self):
        self.bootstrap()
        status, body = self.call("POST", "/evidences", {
            "kind": "video", "source_org": "景区监控中心",
            "collected_at": "2026-09-20T10:00:00",  # 无时区
            "content": b64("v"), "public_summary": "s"}, actor="inv1")
        self.assertEqual((status, body["error"]), (400, "time_timezone_required"))

    def test_04_evidence_ingest_fixes_hash_times_and_audit(self):
        self.bootstrap()
        content = b64("remote-id-frame-0001")
        status, ev = self.call("POST", "/evidences", {
            "evidence_id": "evi-1", "kind": "remote_id",
            "source_org": "民航空管站",
            "collected_at": "2026-09-20T10:00:00+08:00",
            "received_at": "2026-09-20T11:30:00+08:00",
            "content": content, "public_summary": "Remote ID 批次报文",
            "sensitive_identity": "操控人李某 身份证***"},
            actor="inv1")
        self.assertEqual(status, 201)
        self.assertEqual(ev["status"], "sealed")
        self.assertEqual(len(ev["sha256"]), 64)
        self.assertEqual(ev["collected_at"], "2026-09-20T10:00:00.000+08:00")
        self.assertEqual(ev["custody"][0]["action"], "ingest")
        # 原文可以下载且字节一致
        status, raw = self.call("GET", "/evidences/evi-1/download",
                                actor="inv1", raw=True)
        self.assertEqual(status, 200)
        self.assertEqual(raw, b"remote-id-frame-0001")
        # view 与 download 均进入审计
        _, logs = self.call("GET", "/audit?target_id=evi-1", actor="aud1")
        actions = {l["action"] for l in logs}
        self.assertIn("view", actions)
        self.assertIn("download", actions)

    def test_05_sensitive_identity_separate_authorization(self):
        self.bootstrap()
        self.call("POST", "/evidences", {
            "evidence_id": "evi-2", "kind": "transcript",
            "source_org": "派出所",
            "collected_at": "2026-09-20T10:05:00+08:00",
            "content": b64("现场笔录"), "public_summary": "现场询问笔录摘要",
            "sensitive_identity": "当事人王某"}, actor="inv1")
        # 公开角色只见公开摘要，不见敏感身份
        status, pub = self.call("GET", "/evidences/evi-2", actor="pub1")
        self.assertEqual(status, 200)
        self.assertNotIn("sensitive_identity", pub)
        self.assertEqual(pub["public_summary"], "现场询问笔录摘要")
        # 公开角色不能下载原文
        status, body = self.call("GET", "/evidences/evi-2/download", actor="pub1")
        self.assertEqual((status, body["error"]), (403, "forbidden"))
        # 办案人员可见敏感身份
        _, priv = self.call("GET", "/evidences/evi-2", actor="inv1")
        self.assertEqual(priv["sensitive_identity"], "当事人王某")

    def test_06_custody_transfer_receive_and_pending_persistence(self):
        self.bootstrap()
        self.call("POST", "/evidences", {
            "evidence_id": "evi-3", "kind": "video",
            "source_org": "景区监控中心",
            "collected_at": "2026-09-20T09:00:00+08:00",
            "content": b64("video-bytes"), "public_summary": "禁飞区无人机视频"},
            actor="inv1")
        # inv1 移交给 inv2
        status, overview = self.call("POST", "/evidences/evi-3/transfer",
                                     {"to_actor": "inv2", "note": "送检验"},
                                     actor="inv1")
        self.assertEqual(overview["state"], "in_transit")
        # 非接收人不能签收
        status, body = self.call("POST", "/evidences/evi-3/receive", {},
                                 actor="inv1")
        self.assertEqual((status, body["error"]), (403, "not_recipient"))
        # 待签收期间不得下载
        status, body = self.call("GET", "/evidences/evi-3/download",
                                 actor="aud1", raw=False)
        self.assertEqual((status, body["error"]), (409, "custody_in_transit"))
        # 待签收交接在服务重启后仍在
        self.restart_server()
        _, pending = self.call("GET", "/transfers/pending", actor="aud1")
        self.assertEqual([p["evidence_id"] for p in pending], ["evi-3"])
        _, case_dash = self.call("GET", "/dashboard", actor="inv2")
        self.assertEqual(case_dash["pending_transfers"][0]["to_actor"], "inv2")
        # inv2 签收后保管链完整
        status, overview = self.call("POST", "/evidences/evi-3/receive",
                                     {"note": "签收完好"}, actor="inv2")
        self.assertEqual(overview["state"], "held")
        self.assertEqual(overview["holder"], "inv2")
        actions = [c["action"] for c in
                   self.call("GET", "/evidences/evi-3/custody", actor="aud1")[1]]
        self.assertEqual(actions, ["ingest", "transfer", "receive"])

    def test_07_recall_transfer(self):
        self.bootstrap()
        self.call("POST", "/evidences", {
            "evidence_id": "evi-4", "kind": "other", "source_org": "巡防队",
            "collected_at": "2026-09-20T09:00:00+08:00",
            "content": b64("x"), "public_summary": "物证照片"}, actor="inv1")
        self.call("POST", "/evidences/evi-4/transfer",
                  {"to_actor": "inv2"}, actor="inv1")
        status, overview = self.call("POST", "/evidences/evi-4/recall",
                                     {"note": "误发"}, actor="inv1")
        self.assertEqual(overview["state"], "held")
        self.assertEqual(overview["holder"], "inv1")

    def test_08_case_link_supplement_unlink_and_decision_snapshot(self):
        self.bootstrap()
        deadline = "2026-10-20T18:00:00+08:00"
        status, case = self.call("POST", "/cases", {
            "case_id": "case-1", "title": "西湖景区禁飞区违规飞行案",
            "deadline": deadline}, actor="inv1")
        self.assertEqual(status, 201)
        self.assertFalse(case["overdue"])
        # 两项初始证据
        for eid, org, kind, payload in [
                ("evi-a", "景区监控中心", "video", "视频A"),
                ("evi-b", "空管站", "remote_id", "报文B")]:
            self.call("POST", "/evidences", {
                "evidence_id": eid, "kind": kind, "source_org": org,
                "collected_at": "2026-09-20T09:00:00+08:00",
                "content": b64(payload), "public_summary": f"{eid}摘要"},
                actor="inv1")
            self.call("POST", "/cases/case-1/evidences",
                      {"evidence_id": eid}, actor="inv1")
        # 事实清单 v1
        _, facts = self.call("POST", "/cases/case-1/facts",
                             {"base_version": 0,
                              "content": {"fact": "无人机在禁飞区内飞行"}},
                             actor="inv1")
        self.assertEqual(facts["version"], 1)
        # 规则 v1
        self.call("POST", "/rules", {
            "rule_id": "NFZ-01", "version": 1, "title": "景区禁飞规则",
            "content": "景区陆域及上空禁止无人机飞行",
            "scope": {"scenic_area": "西湖景区", "max_altitude_m": 0},
            "effective_from": "2026-01-01T00:00:00+08:00"}, actor="inv1")
        # 作出程序决定（落快照：事实 v1 + 证据 A/B）
        status, decision = self.call("POST", "/cases/case-1/decisions",
                                     {"content": "责令停止飞行并立案调查"},
                                     actor="inv1")
        self.assertEqual(status, 201)
        basis = {b["evidence_id"] for b in decision["evidence_basis"]}
        self.assertEqual(basis, {"evi-a", "evi-b"})
        self.assertEqual(decision["fact_version"], 1)

        # 事后：A 系错误关联，撤销；补交材料 C（与决定时刻拉开毫秒间隔，便于 as-of 切分）
        import time
        time.sleep(0.02)
        status, _ = self.call("POST", "/cases/case-1/evidences/evi-a",
                              {"reason": "画面时间戳与案发时间不符，错误关联"},
                              actor="inv1")
        self.assertEqual(status, 200)
        self.call("POST", "/evidences", {
            "evidence_id": "evi-c", "kind": "transcript", "source_org": "派出所",
            "collected_at": "2026-09-21T08:30:00+08:00",
            "content": b64("补交笔录"), "public_summary": "当事人陈述笔录"},
            actor="inv1")
        status, linked = self.call("POST", "/cases/case-1/supplements",
                                   {"evidence_id": "evi-c",
                                    "note": "复议阶段补交"}, actor="inv1")
        self.assertEqual(status, 201)
        self.assertEqual(set(linked["active_evidence_ids"]), {"evi-b", "evi-c"})

        # 旧决定的快照不被倒置：时间轴 procedure 事件仍固定 A/B 与事实 v1
        _, tl = self.call("GET", "/cases/case-1/timeline", actor="aud1")
        proc = [e for e in tl if e["type"] == "procedure"][0]
        self.assertEqual({b["evidence_id"] for b in proc["payload"]["evidence_basis"]},
                         {"evi-a", "evi-b"})
        # as-of 查询：决定作出时点在链证据只有 A/B，没有补交的 C
        from urllib.parse import quote
        _, tl_at = self.call(
            "GET", "/cases/case-1/timeline?as_of=" + quote(decision["at"], safe=""),
            actor="aud1")
        eids = {e["payload"].get("evidence_id") for e in tl_at
                if e["type"] in ("link", "supplement", "unlink")}
        self.assertEqual(eids, {"evi-a", "evi-b"})
        # unlink 必须有原因，且事件类型与 link 区分（错误关联撤销可追溯）
        unlink = [e for e in tl if e["type"] == "unlink"][0]
        self.assertIn("错误关联", unlink["payload"]["reason"])

    def test_09_fact_optimistic_lock_conflict(self):
        self.bootstrap()
        self.call("POST", "/cases", {"case_id": "case-2", "title": "冲突测试案",
                                     "deadline": "2026-10-01T00:00:00+08:00"},
                  actor="inv1")
        self.call("POST", "/cases/case-2/facts",
                  {"base_version": 0, "content": {"v": "inv1 初稿"}}, actor="inv1")
        # inv2 基于过期的 v0 提交 → 409，修改不被覆盖
        status, body = self.call("POST", "/cases/case-2/facts",
                                 {"base_version": 0, "content": {"v": "inv2 冲突"}},
                                 actor="inv2")
        self.assertEqual((status, body["error"]), (409, "fact_version_conflict"))
        # inv2 基于 v1 重新提交成功，冲突双方编辑人均留痕
        status, facts = self.call("POST", "/cases/case-2/facts",
                                  {"base_version": 1, "content": {"v": "inv2 合并"}},
                                  actor="inv2")
        self.assertEqual(status, 200)
        self.assertEqual(facts["base_version"], 1)
        _, v1 = self.call("GET", "/cases/case-2/facts?version=1", actor="aud1")
        self.assertEqual(v1["editor_id"], "inv1")

    def test_10_finding_traces_rule_evidence_chain_and_handlers(self):
        self.bootstrap()
        self.call("POST", "/cases", {"case_id": "case-3", "title": "认定回溯案",
                                     "deadline": "2026-10-01T00:00:00+08:00"},
                  actor="inv1")
        self.call("POST", "/evidences", {
            "evidence_id": "evi-d", "kind": "remote_id", "source_org": "空管站",
            "collected_at": "2026-09-20T09:00:00+08:00",
            "content": b64("rid"), "public_summary": "Remote ID"}, actor="inv1")
        self.call("POST", "/cases/case-3/evidences",
                  {"evidence_id": "evi-d"}, actor="inv1")
        self.call("POST", "/cases/case-3/facts",
                  {"base_version": 0, "content": {"altitude_m": 120}},
                  actor="inv1")
        self.call("POST", "/rules", {
            "rule_id": "NFZ-X", "version": 1, "title": "禁飞规则",
            "content": "全域禁飞", "effective_from": "2026-01-01T00:00:00+08:00"},
            actor="inv1")
        _, fnd = self.call("POST", "/cases/case-3/findings", {
            "finding_id": "fnd-1",
            "content": "认定在禁飞区内违规飞行，Remote ID 与事实清单相互印证",
            "rule_id": "NFZ-X", "evidence_ids": ["evi-d"]}, actor="inv1")
        self.assertEqual((fnd["rule_version"], fnd["fact_version"]), (1, 1))
        # 规则后来发布 v2，不影响结论固定引用的 v1
        self.call("POST", "/rules", {
            "rule_id": "NFZ-X", "title": "禁飞规则（修订）", "content": "全域禁飞+限高",
            "effective_from": "2026-09-21T00:00:00+08:00"}, actor="inv1")
        _, trace = self.call("GET", "/findings/fnd-1/trace", actor="aud1")
        self.assertEqual(trace["rule"]["version"], 1)
        self.assertEqual(trace["rule"]["content"], "全域禁飞")
        self.assertEqual(trace["facts"]["version"], 1)
        self.assertEqual(trace["evidences"][0]["meta"]["evidence_id"], "evi-d")
        self.assertEqual(trace["evidences"][0]["linked_at_finding_time"], True)
        self.assertEqual(len(trace["evidences"][0]["custody_chain"]), 1)
        self.assertEqual(trace["handler"]["actor_id"], "inv1")
        # 变更记录分为决定前/决定后两段，事后修订出现在 after 段
        after_types = [e["type"] for e in trace["changes_after_decision"]]
        self.assertNotIn("unlink", after_types)  # 本案未撤链

    def test_11_finding_rejects_unlinked_or_void_evidence(self):
        self.bootstrap()
        self.call("POST", "/cases", {"case_id": "case-4", "title": "依据校验案",
                                     "deadline": "2026-10-01T00:00:00+08:00"},
                  actor="inv1")
        self.call("POST", "/evidences", {
            "evidence_id": "evi-e", "kind": "video", "source_org": "监控中心",
            "collected_at": "2026-09-20T09:00:00+08:00",
            "content": b64("v"), "public_summary": "s"}, actor="inv1")
        self.call("POST", "/rules", {
            "rule_id": "R", "title": "t", "content": "c",
            "effective_from": "2026-01-01T00:00:00+08:00"}, actor="inv1")
        status, body = self.call("POST", "/cases/case-4/findings",
                                 {"content": "x", "rule_id": "R",
                                  "evidence_ids": ["evi-e"]}, actor="inv1")
        self.assertEqual((status, body["error"]), (409, "evidence_not_linked"))
        self.call("POST", "/cases/case-4/evidences",
                  {"evidence_id": "evi-e"}, actor="inv1")
        self.call("POST", "/evidences/evi-e/void",
                  {"note": "来源存疑"}, actor="inv1")
        status, body = self.call("POST", "/cases/case-4/findings",
                                 {"content": "x", "rule_id": "R",
                                  "evidence_ids": ["evi-e"]}, actor="inv1")
        self.assertEqual((status, body["error"]), (410, "evidence_void"))

    def test_12_void_is_marker_not_delete_and_blocks_download(self):
        self.bootstrap()
        self.call("POST", "/evidences", {
            "evidence_id": "evi-f", "kind": "other", "source_org": "巡防队",
            "collected_at": "2026-09-20T09:00:00+08:00",
            "content": b64("original"), "public_summary": "s"}, actor="inv1")
        status, body = self.call("POST", "/evidences/evi-f/void", {}, actor="inv1")
        self.assertEqual((status, body["error"]), (400, "void_reason_required"))
        status, ev = self.call("POST", "/evidences/evi-f/void",
                               {"note": "重复采集，作废"}, actor="inv1")
        self.assertEqual(ev["status"], "void")
        # 元数据与哈希仍可查，原文下载被拒
        status, body = self.call("GET", "/evidences/evi-f/download", actor="inv1")
        self.assertEqual((status, body["error"]), (410, "evidence_void"))
        _, meta = self.call("GET", "/evidences/evi-f", actor="aud1")
        self.assertEqual(len(meta["sha256"]), 64)
        self.assertEqual(meta["custody"][-1]["action"], "void")
        self.assertIn("重复采集", meta["custody"][-1]["note"])

    def test_13_closed_case_is_frozen(self):
        self.bootstrap()
        self.call("POST", "/cases", {"case_id": "case-5", "title": "结案案",
                                     "deadline": "2026-10-01T00:00:00+08:00"},
                  actor="inv1")
        status, _ = self.call("POST", "/cases/case-5/close",
                              {"note": "事实清楚，决定已送达"}, actor="inv1")
        self.assertEqual(status, 200)
        status, body = self.call("POST", "/cases/case-5/facts",
                                 {"base_version": 0, "content": {"x": 1}},
                                 actor="inv1")
        self.assertEqual((status, body["error"]), (409, "case_closed"))

    def test_14_deadline_and_all_state_survive_restart(self):
        self.bootstrap()
        self.call("POST", "/cases", {"case_id": "case-6", "title": "期限持久案",
                                     "deadline": "2026-09-20T00:00:00+08:00"},
                  actor="inv1")
        self.restart_server()
        _, cases = self.call("GET", "/dashboard", actor="inv1")
        c = [x for x in cases["open_cases"] if x["case_id"] == "case-6"][0]
        self.assertTrue(c["overdue"])  # 今天 2026-09-21，已超期
        _, detail = self.call("GET", "/cases/case-6", actor="inv1")
        self.assertEqual(detail["deadline"], "2026-09-20T00:00:00.000+08:00")
        self.assertTrue(detail["overdue"])

    def test_15_ingest_rejects_received_before_collected(self):
        self.bootstrap()
        status, body = self.call("POST", "/evidences", {
            "kind": "video", "source_org": "监控中心",
            "collected_at": "2026-09-20T10:00:00+08:00",
            "received_at": "2026-09-20T08:00:00+08:00",
            "content": b64("v"), "public_summary": "s"}, actor="inv1")
        self.assertEqual((status, body["error"]), (400, "time_order"))


if __name__ == "__main__":
    unittest.main()
