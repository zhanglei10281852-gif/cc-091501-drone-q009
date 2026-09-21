# 无人机违规飞行案件后端

面向景区禁飞区内违规飞行案件的证据保管与办案后端（Python 标准库，无第三方依赖）。
解决多单位材料时间口径不一、覆盖式修改削弱复议证据效力的问题：

- **证据入库即固定**：SHA-256 内容寻址落盘，同时记录来源单位、采集时间（来源口径）、
  接收时间（本系统口径）、入库时间与初始保管人；原文只追加、不覆盖。
- **封存/作废/交接全程留痕**：状态变化只能追加保管事件（ingest/transfer/receive/recall/void），
  作废是标记而非删除，已作废原文仅停止下载、哈希仍可查；待签收交接落库，重启不丢。
- **案件只追加时间轴**：关联 link、补交 supplement、错误关联撤销 unlink（必须填原因）、
  程序决定 procedure、结案 close；历史永不被改写。
- **补证不倒置程序决定**：程序决定作出时固化依据快照（事实版本 + 在链证据及哈希），
  事后补交、撤链只影响后续判断；支持 `?as_of=` 时点回放。
- **事实清单乐观锁**：多人编辑按版本号提交（base_version），冲突返回 409 并暴露当前版本与编辑人。
- **认定结论可追溯**：结论固定禁飞规则版本、事实清单版本、证据 ID 集合与经办人；
  `GET /findings/{id}/trace` 沿引用找回规则原文、完整证据链（含保管链）、经办人及变更记录。
- **审计与分权**：每次查看/下载/变更都写审计日志（仅 auditor 可查）；
  敏感身份（investigator/auditor 可见）与可公开摘要（public_viewer 可见）分开授权。
- **期限持久**：办案期限落库，`GET /dashboard` 看待办与超期，服务重启后连续。

## 运行

需要 Python 3.11+。

```bash
python3 src/index.py            # 默认 0.0.0.0:8000，数据在 DATA_DIR（默认 .data）
python3 -m unittest discover -s tests
docker compose up --build
```

所有时间字段均为带时区的 ISO 8601（服务时区 Asia/Shanghai），无时区的时间串会被拒绝。
鉴权使用 `X-Actor-Id` 请求头，经办人先经 `POST /actors` 登记并授予角色。

## 主要接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/actors` | 登记经办人（investigator/auditor/public_viewer） |
| POST | `/rules` | 发布禁飞规则版本（连续版本号，旧版本自动截止，内容不改写） |
| POST | `/evidences` | 证据入库：base64 原文 + 来源 + 采集/接收时间 + 公开摘要 + 敏感身份 |
| GET | `/evidences/{id}` / `.../download` / `.../custody` | 元数据（含保管链）/ 下载原文（审计）/ 保管链 |
| POST | `/evidences/{id}/transfer` `/receive` `/recall` `/void` | 保管交接、签收、召回、作废标记 |
| GET | `/transfers/pending` | 待签收交接（重启后仍在） |
| POST | `/cases` | 建案，必填办案期限 deadline |
| POST | `/cases/{id}/evidences` `/supplements` | 初始关联 / 补交材料 |
| POST | `/cases/{id}/evidences/{eid}` | 撤销错误关联（必填原因，追加 unlink 事件） |
| GET | `/cases/{id}/timeline[?as_of=]` | 案件时间轴，支持时点回放 |
| POST | `/cases/{id}/facts` | 事实清单提交，带 base_version；冲突 409 |
| POST | `/cases/{id}/findings` | 认定结论，固定规则版本/事实版本/证据集合 |
| GET | `/findings/{id}/trace` | 结论→规则版本+事实版本+证据保管链+经办人+变更记录 |
| POST | `/cases/{id}/decisions` | 程序决定，固化依据快照，不被事后补证倒置 |
| POST | `/cases/{id}/close` | 结案归档，冻结案件 |
| GET | `/dashboard` | 在办案件期限、待签收交接 |
| GET | `/audit` | 审计查询（auditor） |
| GET | `/health` | 进程存活（不代表任何业务状态） |
