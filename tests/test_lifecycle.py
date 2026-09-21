"""端到端：立案 -> 证据入库/保管 -> 事实认定 -> 补证 -> 撤销 -> 归档 的完整生命周期。"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from harness import Client, ServerHarness  # noqa: E402

POLYGON = ('{"type":"Polygon","coordinates":[[[116.39,39.90],[116.40,39.90],'
           '[116.40,39.91],[116.39,39.91],[116.39,39.90]]]}')


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.h = ServerHarness()
        self.addCleanup(self.h.stop)

        # 引导首个办案员
        status, body = Client(self.h.server).post("/admin/bootstrap", {
            "username": "chief", "display_name": "张主办"})
        self.assertEqual(status, 201)
        self.chief = Client(self.h.server, body["api_key"])
        # 引导接口随即关闭
        status, _ = Client(self.h.server).post("/admin/bootstrap", {})
        self.assertEqual(status, 403)

        self.keys = {}
        for username, name, role in [
            ("approver", "李审批", "approver"),
            ("archivist", "王档案", "archivist"),
            ("auditor", "赵审计", "auditor"),
            ("intaker", "景区公安录入员", "intaker"),
            ("officer2", "陈协办", "officer"),
        ]:
            status, body = self.chief.post("/admin/users", {
                "username": username, "display_name": name, "role": role})
            self.assertEqual(status, 201, body)
            self.keys[role] = Client(self.h.server, body["api_key"])

    # -- 1. 规则与立案 --------------------------------------------------------

    def test_full_case_lifecycle(self):
        # 规则：9 月 1 日起生效
        status, rule = self.chief.post("/rules", {
            "rule_code": "NF-SCENIC-01", "title": "核心景区禁飞区规则",
            "zone_geojson": POLYGON, "altitude_max": 0.0,
            "effective_from": "2026-09-01T00:00:00+08:00"})
        self.assertEqual(status, 201, rule)
        rule_id = rule["id"]

        status, case = self.chief.post("/cases", {
            "case_no": "飞罚〔2026〕001号", "title": "核心景区无人机违规飞行案",
            "location": "核心景区北门", "incident_at": "2026-09-15T08:00:00Z",
            "deadline_days": 30})
        self.assertEqual(status, 201, case)
        case_id = case["id"]
        self.assertEqual(case["status"], "open")
        self.assertFalse(case["deadline_status"]["overdue"])
        self.assertEqual(case["deadline_status"]["days_left"], 29)

        # 录入员不能浏览案件列表
        status, body = self.keys["intaker"].get("/cases")
        self.assertEqual(status, 403)

    # -- 2. 多单位证据入库，时间口径分别保留 ----------------------------------

    def _open_case(self):
        self.chief.post("/rules", {
            "rule_code": "NF-SCENIC-01", "title": "核心景区禁飞区规则",
            "zone_geojson": POLYGON, "altitude_max": 0.0,
            "effective_from": "2026-09-01T00:00:00+08:00"})
        _, case = self.chief.post("/cases", {
            "case_no": "飞罚〔2026〕002号", "title": "违规飞行案",
            "incident_at": "2026-09-15T16:00:00+08:00"})
        return case["id"]

    def test_evidence_intake_preserves_distinct_time_bases(self):
        case_id = self._open_case()
        # 景区公安执法视频：UTC 口径；Remote ID 报文：运营单位 +08 口径；笔录：本单位
        status, video = self.keys["intaker"].upload(
            f"/cases/{case_id}/evidence",
            fields={"kind": "video", "source_unit": "景区公安分局",
                    "collected_at": "2026-09-15T08:00:00Z",
                    "source_reference": "JQ-VIDEO-7788"})
        self.assertEqual(status, 201, video)
        self.assertEqual(video["collected_at"], "2026-09-15T16:00:00+08:00")
        self.assertIsNotNone(video["received_at"])
        self.assertEqual(video["status"], "sealed")
        self.assertTrue(video["digest"])

        payload = b"\xaaRID-PACKET\x00\x01\r\n\xff"
        status, rid = self.chief.upload(
            f"/cases/{case_id}/evidence",
            fields={"kind": "remote_id", "source_unit": "Remote ID 运营单位",
                    "collected_at": "2026-09-15T16:00:30+08:00",
                    "note": "无人机识别广播"},
            filename="rid.bin", content=payload, file_ctype="application/octet-stream")
        self.assertEqual(status, 201, rid)
        self.assertEqual(rid["collected_at"], "2026-09-15T16:00:30+08:00")

        status, record = self.chief.upload(
            f"/cases/{case_id}/evidence",
            fields={"kind": "record", "source_unit": "本机关执法大队",
                    "collected_at": "2026-09-15T17:30:00+08:00"},
            filename="record.txt", content="现场笔录".encode())
        self.assertEqual(201, status)

        # 下载的原件与上传字节逐位一致（multipart 边界含 \r\n 也不能损坏）
        status, downloaded = self.chief.get(f"/evidence/{rid['id']}/download")
        self.assertEqual(status, 200)
        self.assertEqual(downloaded, payload)

        # 录入员只能访问本人提交的材料，看不到他人材料
        status, mine = self.keys["intaker"].get(f"/evidence/{video['id']}")
        self.assertEqual(status, 200)
        status, denied = self.keys["intaker"].get(f"/evidence/{rid['id']}")
        self.assertEqual(status, 403)

        # 保管链：入库 + 查看 + 下载均留痕
        status, chain = self.chief.get(f"/evidence/{rid['id']}/custody")
        self.assertEqual(status, 200)
        actions = [e["action"] for e in chain]
        self.assertEqual(actions[0], "intake")
        self.assertIn("download", actions)

        return case_id, video, rid, record

    # -- 3. 待签收交接跨重启不丢失 --------------------------------------------

    def test_pending_transfer_survives_restart(self):
        case_id = self._open_case()
        _, ev = self.chief.upload(
            f"/cases/{case_id}/evidence",
            fields={"kind": "video", "source_unit": "景区公安分局",
                    "collected_at": "2026-09-15T16:00:00+08:00"})
        approver_id = self._user_id("approver")

        status, t = self.chief.post(f"/evidence/{ev['id']}/transfer", {
            "to_user_id": approver_id, "note": "请审批前核验"})
        self.assertEqual(status, 201, t)
        transfer_id = t["transfer_id"]

        # 重启服务：待签收仍在，办案期限也在
        self.h.restart()
        status, pending = self.keys["approver"].get("/transfers/pending")
        self.assertEqual(status, 200)
        self.assertEqual([p["id"] for p in pending], [transfer_id])
        status, case = self.chief.get(f"/cases/{case_id}")
        self.assertIn("deadline_status", case)

        # 非接收人不能签收
        status, body = self.chief.post(f"/transfers/{transfer_id}/sign", {})
        self.assertEqual(status, 403)
        # 接收人本人签收
        status, signed = self.keys["approver"].post(
            f"/transfers/{transfer_id}/sign", {})
        self.assertEqual(status, 200, signed)
        self.assertEqual(signed["status"], "signed")
        status, pending = self.keys["approver"].get("/transfers/pending")
        self.assertEqual(pending, [])

    # -- 4. 事实清单乐观锁冲突 ------------------------------------------------

    def test_fact_version_conflict_exposed(self):
        case_id = self._open_case()
        status, v1 = self.chief.put(f"/cases/{case_id}/facts", {
            "content": {"time": "16:00", "altitude": 120},
            "based_on": 0, "change_note": "初版事实"})
        self.assertEqual(status, 201, v1)
        self.assertEqual(v1["version"], 1)

        # 陈协办基于旧基线 v0 提交 → 409，服务端返回冲突说明
        status, conflict = self.keys["officer"].put(f"/cases/{case_id}/facts", {
            "content": {"time": "16:05"}, "based_on": 0, "change_note": "迟到的初版"})
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"], "fact_version_conflict")

        # 合并后基于 v1 提交成功
        status, v2 = self.keys["officer"].put(f"/cases/{case_id}/facts", {
            "content": {"time": "16:05", "altitude": 120, "drone": "Mavic"},
            "based_on": 1, "change_note": "补充机型"})
        self.assertEqual(status, 201, v2)
        self.assertEqual(v2["version"], 2)
        status, versions = self.chief.get(f"/cases/{case_id}/facts/versions")
        self.assertEqual(len(versions), 2)

    # -- 5. 敏感身份与公开摘要分开授权 ----------------------------------------

    def test_identity_and_public_summary_separate_authorization(self):
        case_id = self._open_case()
        _, ev = self.chief.upload(
            f"/cases/{case_id}/evidence",
            fields={"kind": "record", "source_unit": "执法大队",
                    "collected_at": "2026-09-15T17:00:00+08:00"})

        # 封存敏感身份
        status, ident = self.chief.post(f"/cases/{case_id}/identities", {
            "label": "当事人/飞手",
            "data": {"name": "钱某", "id_number": "110***********123",
                     "phone": "138****0000"}})
        self.assertEqual(status, 201, ident)
        identity_id = ident["identity_id"]

        # 审批人未获逐案授权 → 拒绝
        status, denied = self.keys["approver"].post(
            f"/cases/{case_id}/identities/{identity_id}/reveal", {})
        self.assertEqual(status, 403)

        # 授权后可查看；撤销后再拒绝
        approver_id = self._user_id("approver")
        status, _ = self.chief.post(
            f"/cases/{case_id}/identities/{identity_id}/grant",
            {"user_id": approver_id})
        self.assertEqual(status, 200)
        status, revealed = self.keys["approver"].post(
            f"/cases/{case_id}/identities/{identity_id}/reveal", {})
        self.assertEqual(status, 200)
        self.assertEqual(revealed["data"]["name"], "钱某")
        status, _ = self.chief.post(
            f"/cases/{case_id}/identities/{identity_id}/revoke",
            {"user_id": approver_id})
        self.assertEqual(status, 200)
        status, _ = self.keys["approver"].post(
            f"/cases/{case_id}/identities/{identity_id}/reveal", {})
        self.assertEqual(status, 403)

        # 公开摘要单独授权：viewer 可读脱敏摘要，但拿不到原件
        _, viewer_key = self._make_user("v", "公众用户", "viewer")
        status, _ = self.chief.post(f"/evidence/{ev['id']}/public-summaries", {
            "content": "2026年9月15日下午，核心景区上空发现一架无人机违规飞行，"
                       "现场处置过程已记录（已脱敏）。"})
        self.assertEqual(status, 201)
        status, summary = viewer_key.get(f"/evidence/{ev['id']}/public-summary")
        self.assertEqual(status, 200)
        self.assertNotIn("钱某", summary["content"])
        status, _ = viewer_key.get(f"/evidence/{ev['id']}")
        self.assertEqual(status, 403)
        status, _ = viewer_key.get(f"/evidence/{ev['id']}/download")
        self.assertEqual(status, 403)

    # -- 6. 认定、溯源、补证不倒置、规则版本、作废、撤销、归档 ---------------

    def test_finding_trace_supplement_void_supersede_archive(self):
        # 规则 + 案件 + 三件证据 + 事实 v1
        status, rule = self.chief.post("/rules", {
            "rule_code": "NF-TRACE", "title": "禁飞区",
            "zone_geojson": POLYGON, "altitude_max": 0.0,
            "effective_from": "2026-09-01T00:00:00+08:00"})
        rule_id = rule["id"]
        _, case = self.chief.post("/cases", {
            "case_no": "飞罚〔2026〕003号", "title": "溯源案",
            "incident_at": "2026-09-15T16:00:00+08:00"})
        case_id = case["id"]

        evidences = []
        for kind, unit, ts in [
            ("video", "景区公安分局", "2026-09-15T16:00:00+08:00"),
            ("remote_id", "RID运营单位", "2026-09-15T16:00:30+08:00"),
            ("record", "执法大队", "2026-09-15T17:00:00+08:00"),
        ]:
            status, ev = self.chief.upload(
                f"/cases/{case_id}/evidence",
                fields={"kind": kind, "source_unit": unit, "collected_at": ts},
                content=f"{unit}-材料".encode())
            self.assertEqual(status, 201)
            evidences.append(ev)

        _, v1 = self.chief.put(f"/cases/{case_id}/facts", {
            "content": {"flight": {"altitude_m": 120, "duration_min": 8}},
            "based_on": 0, "change_note": "认定初稿"})

        # 未生效规则不能作为依据
        _, future_rule = self.chief.post("/rules", {
            "rule_code": "NF-FUTURE", "title": "未来规则",
            "zone_geojson": POLYGON,
            "effective_from": "2026-10-01T00:00:00+08:00"})
        status, body = self.chief.post(f"/cases/{case_id}/decisions", {
            "kind": "finding", "title": "违规飞行事实认定",
            "content": "认定在禁飞区飞行", "rule_id": future_rule["id"],
            "evidence_ids": [e["id"] for e in evidences]})
        self.assertEqual(status, 422, body)

        # 正式认定：固定规则、事实 v1、三件证据
        status, finding = self.chief.post(f"/cases/{case_id}/decisions", {
            "kind": "finding", "title": "违规飞行事实认定",
            "content": "当事人操控无人机在核心景区禁飞区内飞行约8分钟",
            "rule_id": rule_id, "evidence_ids": [e["id"] for e in evidences]})
        self.assertEqual(status, 201, finding)
        finding_id = finding["id"]
        self.assertEqual(finding["refs"]["fact_version"], [1])
        self.assertEqual(finding["refs"]["rule"], [rule_id])

        # 补证通知 -> 案件进入 supplementing；补交的新材料不能倒置为认定依据
        status, notice = self.chief.post(f"/cases/{case_id}/decisions", {
            "kind": "supplement_notice", "title": "补充证据通知",
            "content": "请补充飞手身份材料", "supplement_due_days": 5})
        self.assertEqual(status, 201, notice)
        _, case_after = self.chief.get(f"/cases/{case_id}")
        self.assertEqual(case_after["status"], "supplementing")

        _, late = self.chief.upload(
            f"/cases/{case_id}/evidence",
            fields={"kind": "other", "source_unit": "派出所",
                    "collected_at": "2026-09-16T10:00:00+08:00",
                    "note": "补交的身份核查材料"},
            content="补交".encode())

        status, trace = self.chief.get(f"/decisions/{finding_id}/trace")
        self.assertEqual(status, 200, trace)
        self.assertEqual(trace["rule_at_time"]["id"], rule_id)
        self.assertEqual(trace["fact_version_at_time"]["version"], 1)
        self.assertEqual(len(trace["evidence_chain"]), 3)
        self.assertTrue({c["action"] for c in trace["evidence_chain"][0]["custody_chain"]}
                        >= {"intake"})
        makers = {h["role"] for h in trace["handlers"]}
        self.assertIn("decision_maker", makers)
        self.assertIn("fact_author", makers)
        later_ids = {m["id"] for m in trace["later_materials_not_basis"]}
        self.assertIn(late["id"], later_ids)
        self.assertTrue(all(m["never_basis"] for m in trace["later_materials_not_basis"]))

        # 规则发布新版本：历史认定仍指向旧版
        status, rule_v2 = self.chief.post("/rules/NF-TRACE/versions", {
            "rule_code": "NF-TRACE", "title": "禁飞区（边界修订版）",
            "zone_geojson": POLYGON, "altitude_max": 0.0,
            "effective_from": "2026-09-20T00:00:00+08:00"})
        self.assertEqual(status, 201, rule_v2)
        _, trace = self.chief.get(f"/decisions/{finding_id}/trace")
        self.assertEqual(trace["rule_at_time"]["id"], rule_id)
        self.assertTrue(trace["rule_at_time"]["has_newer_version"])

        # 事实清单继续演进：溯源固定在 v1，并记录事后变化
        self.chief.put(f"/cases/{case_id}/facts", {
            "content": {"flight": {"altitude_m": 118}},
            "based_on": 1, "change_note": "校正高度"})
        _, trace = self.chief.get(f"/decisions/{finding_id}/trace")
        self.assertEqual(trace["fact_version_at_time"]["version"], 1)
        self.assertFalse(trace["fact_version_at_time"]["is_current"])
        change_types = {c["type"] for c in trace["change_history"]}
        self.assertIn("fact_advanced_after_decision", change_types)

        # 作废一件证据：不删除，原件普通角色不可下载，审计可核验，溯源标注事后作废
        status, voided = self.chief.post(
            f"/evidence/{evidences[1]['id']}/void", {"reason": "报文来源时钟异常，排除"})
        self.assertEqual(status, 200, voided)
        self.assertEqual(voided["status"], "voided")
        self.assertIsNotNone(voided["void_mark"])
        status, _ = self.chief.get(f"/evidence/{evidences[1]['id']}/download")
        self.assertEqual(status, 409)
        status, blob = self.keys["auditor"].get(
            f"/evidence/{evidences[1]['id']}/download")
        self.assertEqual(status, 200)
        _, trace = self.chief.get(f"/decisions/{finding_id}/trace")
        self.assertTrue(any(c["type"] == "evidence_voided_after_decision"
                            for c in trace["change_history"]))

        # 错误关联撤销：视频误关联本案，撤销后关联到正确案件；原件不动
        _, other_case = self.chief.post("/cases", {
            "case_no": "飞罚〔2026〕004号", "title": "另案",
            "incident_at": "2026-09-16T10:00:00+08:00"})
        status, rev = self.chief.post(
            f"/evidence/{evidences[0]['id']}/revoke-link",
            {"reason": "经查视频系他案材料，错误关联"})
        self.assertEqual(status, 200, rev)
        status, rel = self.chief.post(
            f"/evidence/{evidences[0]['id']}/relink",
            {"to_case_id": other_case["id"], "note": "更正归属"})
        self.assertEqual(status, 200, rel)
        status, case_ev = self.chief.get(f"/cases/{case_id}/evidence")
        case_ev_ids = {e["id"] for e in case_ev}
        self.assertNotIn(evidences[0]["id"], case_ev_ids)
        # RID、笔录与补交材料仍在本案
        self.assertEqual(case_ev_ids,
                         {evidences[1]["id"], evidences[2]["id"], late["id"]})
        status, other_ev = self.chief.get(f"/cases/{other_case['id']}/evidence")
        self.assertEqual([e["id"] for e in other_ev], [evidences[0]["id"]])

        # 程序链由审批人角色作出：告知 -> 处罚决定
        status, notice = self.keys["approver"].post(f"/cases/{case_id}/decisions", {
            "kind": "penalty_notice", "title": "行政处罚事先告知书",
            "content": "拟处罚款"})
        self.assertEqual(status, 201, notice)
        status, penalty = self.keys["approver"].post(f"/cases/{case_id}/decisions", {
            "kind": "penalty_decision", "title": "行政处罚决定书",
            "content": "罚款人民币伍万元",
            "prior_decision_ids": [notice["id"]]})
        self.assertEqual(status, 201, penalty)

        # 撤销被后续决定引用的决定 -> 409 并给出依赖
        status, dep = self.chief.post(f"/decisions/{notice['id']}/supersede",
                                      {"reason": "测试"})
        self.assertEqual(status, 409)
        self.assertEqual(dep["error"], "decision_has_dependents")

        # 归档前必须无待签收交接；制造一单后档案员归档应被阻止
        approver_id = self._user_id("approver")
        self.chief.post(f"/evidence/{evidences[2]['id']}/transfer",
                        {"to_user_id": approver_id})
        status, blocked = self.keys["archivist"].post(f"/cases/{case_id}/archive", {})
        self.assertEqual(status, 409)
        # 审批人签收（重启后仍可签收，再次验证持久化）
        self.h.restart()
        pending = self.keys["approver"].get("/transfers/pending")[1]
        self.keys["approver"].post(f"/transfers/{pending[0]['id']}/sign", {})

        status, archived = self.keys["archivist"].post(f"/cases/{case_id}/archive", {})
        self.assertEqual(status, 200, archived)
        self.assertEqual(archived["status"], "archived")
        self.assertTrue(archived["manifest"]["manifest_digest"])
        status, verify = self.keys["archivist"].get(
            f"/cases/{case_id}/archive/verify")
        self.assertEqual(status, 200, verify)
        self.assertTrue(verify["intact"])
        # 归档后封存：再传材料被拒
        status, frozen = self.chief.upload(
            f"/cases/{case_id}/evidence",
            fields={"kind": "other", "source_unit": "x",
                    "collected_at": "2026-09-20T10:00:00+08:00"})
        self.assertEqual(status, 409)

        # 审计日志包含下载与溯源记录（查看/下载必入审计）
        status, logs = self.keys["auditor"].get(
            f"/audit?case_id={case_id}&limit=1000")
        self.assertEqual(status, 200)
        actions = {e["action"] for e in logs}
        self.assertIn("evidence.download", actions)
        self.assertIn("decision.trace", actions)
        self.assertIn("case.archive", actions)

    def test_procedure_requires_prior_finding(self):
        case_id = self._open_case()
        status, body = self.keys["approver"].post(f"/cases/{case_id}/decisions", {
            "kind": "penalty_notice", "title": "告知", "content": "x"})
        self.assertEqual(status, 409)

    def test_supplemented_material_can_support_later_decision(self):
        # 补交材料不能倒置旧认定，但必须能进入其后的新决定
        status, rule = self.chief.post("/rules", {
            "rule_code": "NF-SUP", "title": "禁飞区", "zone_geojson": POLYGON,
            "effective_from": "2026-09-01T00:00:00+08:00"})
        _, case = self.chief.post("/cases", {
            "case_no": "飞罚〔2026〕010号", "title": "补证案",
            "incident_at": "2026-09-15T16:00:00+08:00"})
        case_id = case["id"]
        _, ev = self.chief.upload(
            f"/cases/{case_id}/evidence",
            fields={"kind": "video", "source_unit": "公安",
                    "collected_at": "2026-09-15T16:00:00+08:00"})
        self.chief.put(f"/cases/{case_id}/facts", {
            "content": {"f": 1}, "based_on": 0, "change_note": "v1"})
        _, finding = self.chief.post(f"/cases/{case_id}/decisions", {
            "kind": "finding", "title": "认定", "content": "x",
            "rule_id": rule["id"], "evidence_ids": [ev["id"]]})

        _, late = self.chief.upload(
            f"/cases/{case_id}/evidence",
            fields={"kind": "other", "source_unit": "派出所",
                    "collected_at": "2026-09-16T10:00:00+08:00"},
            content="补交".encode())
        self.chief.put(f"/cases/{case_id}/facts", {
            "content": {"f": 1, "supplement": "included"},
            "based_on": 1, "change_note": "吸收补交材料"})
        status, finding2 = self.chief.post(f"/cases/{case_id}/decisions", {
            "kind": "finding", "title": "补充认定", "content": "结合补交材料补充认定",
            "rule_id": rule["id"],
            "evidence_ids": [ev["id"], late["id"]],
            "prior_decision_ids": [finding["id"]]})
        self.assertEqual(status, 201, finding2)
        _, trace2 = self.chief.get(f"/decisions/{finding2['id']}/trace")
        basis = {e["id"] for e in trace2["evidence_chain"]}
        self.assertIn(late["id"], basis)
        # 旧认定的溯源里，该材料永远只是"事后材料"
        _, trace1 = self.chief.get(f"/decisions/{finding['id']}/trace")
        self.assertTrue(any(m["id"] == late["id"] and m["never_basis"]
                            for m in trace1["later_materials_not_basis"]))

    # -- 辅助 ----------------------------------------------------------------

    def _user_id(self, username):
        status, users = self.chief.get("/admin/users")
        self.assertEqual(status, 200)
        return next(u["id"] for u in users if u["username"] == username)

    def _make_user(self, username, name, role):
        status, body = self.chief.post("/admin/users", {
            "username": username, "display_name": name, "role": role})
        return status, Client(self.h.server, body["api_key"])


if __name__ == "__main__":
    unittest.main()
