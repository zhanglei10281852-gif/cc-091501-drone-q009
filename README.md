# 无人机违规飞行案件后端

面向景区禁飞区违规飞行案件的取证办案后端。仅依赖 Python 3.11 标准库，
SQLite 落盘，围绕"证据效力不被破坏、程序不倒置、结论可溯源"建设。

## 核心合规设计

- **证据入库即固定**：登记时写死 SHA-256 摘要、出具单位、来源文号、来源单位
  采集时间（保留原口径，只做 ISO 8601 格式归一）、本机关接收时间（服务器时钟，
  客户端不可指定）、入库时间与首环节保管人。原件按摘要内容寻址落盘。
- **原始材料只追加、封存或作废**：数据库触发器拒绝对 `evidence` 的任何
  UPDATE（仅放行 sealed→voided 翻转且其他列原样）和 DELETE；作废另写
  `void_marks`，原件保留，普通角色不可下载，审计角色可调阅核验。
  保管链、审计日志、事实版本、决定同样由触发器禁止改删。
- **错误关联可撤销**：证据与案件的关联是独立追加表，错误关联写撤销留痕后
  可重新关联到正确案件；证据本体与采集口径永不动。
- **程序不倒置**：认定结论作出时固定规则 id、事实版本号、证据集合（decision_refs
  快照指针）。规则更新出新版、事实清单改版、证据补交/撤销/作废，都不改写历史
  结论；溯源接口把"决定之后才出现的材料"单列并标注 `never_basis=true`，但这些
  材料可以被其后的新决定引用。
- **事实清单乐观锁**：提交需带 `based_on`，多人并发编辑时返回 409
  `fact_version_conflict` 并附服务端最新版本，强制人工合并，不静默覆盖。
- **敏感身份与公开摘要分离授权**：身份信息以 ChaCha20 + HMAC-SHA256
  加密封存于独立密文库，逐案逐人 grant/revoke；可公开摘要单独追加版本、
  单独 `public:write` 权限，只读用户可看脱敏摘要但永远拿不到原件。
- **全程审计**：证据查看、下载、保管链查看、身份解明（含被拒绝）、事实/决定
  读取、溯源等均写只追加审计日志。
- **重启不中断**：办案期限、待签收交接全部持久化；案件视图实时计算
  `overdue/days_left`，交接重启后仍可签收。
- **结案归档**：归档前必须无待签收交接；归档生成含全部证据摘要、决定、事实
  版本的整体指纹清单（manifest），归档后案件冻结，可随时校验指纹是否一致。

## 运行

需要 Python 3.11+，无第三方依赖。

```bash
python src/index.py            # 默认 0.0.0.0:8000，数据在 ./data
PORT=9000 DATA_DIR=/var/lib/case python src/index.py
python -m unittest discover    # 运行全部测试（基线健康检查 + 端到端 9 项）
docker compose up --build      # 容器化，数据在 case-data 卷
```

首次启动后系统无用户，需先引导（仅一次，返回的 api_key 只显示一次）：

```bash
curl -s -X POST http://127.0.0.1:8000/admin/bootstrap \
  -H 'Content-Type: application/json' \
  -d '{"username":"chief","display_name":"张主办"}'
```

之后所有接口携带 `X-API-Key`。角色：`officer` 办案人员、`approver` 审批人、
`archivist` 档案管理员、`auditor` 审计员、`intaker` 外单位录入员（仅本人
提交件）、`viewer` 只读用户。

## 接口与办案流程

完整接口清单见 [docs/api.md](docs/api.md)，领域约定见 [docs/domain.md](docs/domain.md)。
典型流程：

1. `POST /rules` 登记禁飞规则（GeoJSON Polygon + 生效时间）；规则变更走
   `POST /rules/{code}/versions`，旧版回指新版，历史结论不漂移。
2. `POST /cases` 立案（案号、事发时间，自动生成办案期限）。
3. `POST /cases/{id}/evidence`（multipart）不同单位分别上传视频/Remote ID
   报文/笔录，各自带采集时间口径。
4. `POST /evidence/{id}/transfer` 发起保管转交 → 接收人
   `GET /transfers/pending` → `POST /transfers/{id}/sign`。
5. `PUT /cases/{id}/facts` 多人维护事实清单（`based_on` 乐观锁）。
6. `POST /cases/{id}/decisions` 依次作出 finding（认定）→ supplement_notice
   （补证通知）→ penalty_notice（处罚告知）→ penalty_decision（处罚决定），
   作出时固定规则/事实/证据引用；规则须在事发时点生效。
7. 错误关联 `POST /evidence/{id}/revoke-link` + `/relink`；错误结论
   `POST /decisions/{id}/supersede`（被后续决定引用时拒绝并提示依赖）。
8. `GET /decisions/{id}/trace` 从结论出发回溯当时规则、事实快照、完整证据链、
   各环节经办人、变更记录、补交材料。
9. `POST /cases/{id}/archive` 归档（先清空待签收交接），
   `GET /cases/{id}/archive/verify` 校验。

## 目录

```
src/
  config.py      运行配置与数据目录
  timeutil.py    时间口径（Asia/Shanghai，来源时间/接收时间分离）
  security.py    角色作用域、API Key 散列、ChaCha20/HMAC 身份封存
  database.py    表结构与追加封存触发器
  storage.py     原件内容寻址只追加存储
  auth.py        API Key 认证与审计写入
  errors.py      统一错误（401/403/404/409/422）
  svc_rules / svc_cases / svc_evidence / svc_identity /
  svc_facts / svc_decisions / svc_audit.py   领域服务
  api.py         HTTP 路由、multipart、请求级事务
```
