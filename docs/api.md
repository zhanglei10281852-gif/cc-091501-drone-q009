# 接口说明

所有接口（除 `/health` 与首次 `/admin/bootstrap`）均需请求头 `X-API-Key`。
时间一律为带时区 ISO 8601；输出统一按 Asia/Shanghai 呈现。错误响应：

```json
{"error": "fact_version_conflict", "message": "..."}
```

| 状态码 | 含义 |
| --- | --- |
| 401 | 未认证/凭据失效 |
| 403 | 角色或逐案授权不足 |
| 404 | 资源不存在 |
| 409 | 状态冲突（归档冻结、乐观锁冲突、程序前置缺失、存在依赖等） |
| 422 | 请求体语义不合法（未生效规则、引用作废证据等） |

## 引导与用户

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| POST | `/admin/bootstrap` | 仅库中无用户时 | 创建首个 officer，返回一次性 api_key |
| POST | `/admin/users` | `user:manage` | 创建用户，返回一次性 api_key |
| GET | `/admin/users` | `user:manage` | 用户列表（不含 key） |

## 禁飞规则

- `POST /rules`：登记规则。字段 `rule_code`、`title`、`zone_geojson`（Polygon）、
  `altitude_max`、`effective_from`。
- `POST /rules/{rule_code}/versions`：发布新版本（同号新生效起点），旧版置
  `effective_to` 并回指新版。
- `GET /rules/{id}`。

## 案件

- `POST /cases`：`case_no`、`title`、`location`、`incident_at`、`deadline_days`
  （默认 30）。响应含 `deadline_status.overdue/days_left/server_time`，重启持续计算。
- `GET /cases?status=open|supplementing|decided|archived`。
- `GET /cases/{id}`：案件、期限状态、当前 `pending_transfers`。
- `POST /cases/{id}/archive`（`archive:write`）：无待签收交接才可归档，返回
  证据/决定/事实的整体指纹清单。
- `GET /cases/{id}/archive/verify`（`archive:read`）：重算指纹比对。

## 证据与保管

- `POST /cases/{id}/evidence`：`multipart/form-data`，字段
  `file`（原件）、`kind`（video/remote_id/record/other）、`source_unit`、
  `collected_at`（来源单位口径，必填）、`source_reference`、`media_type`、`note`。
  `received_at` 由服务器时钟固定，不接受客户端传入。
- `GET /cases/{id}/evidence`：当前有效关联本案的证据（含作废标记、最新公开摘要）。
- `GET /evidence/{id}`：查看（写审计 + 保管链 inspect）。
- `GET /evidence/{id}/download`：下载原件（写审计 + 保管链 download）；
  作废件仅审计角色可调阅。
- `GET /evidence/{id}/custody`：保管链。
- `POST /evidence/{id}/void`：`{"reason": "..."}` 追加作废，原件不删。
- `POST /evidence/{id}/revoke-link`：撤销错误案件关联（证据不动）。
- `POST /evidence/{id}/relink`：`{"to_case_id": n}` 重新关联。
- `POST /evidence/{id}/transfer`：`{"to_user_id": n, "note": "..."}`
  生成持久化待签收交接。
- `GET /transfers/pending`：本人待签收。
- `POST /transfers/{id}/sign`：仅指定接收人本人可签收。

## 公开摘要

- `POST /evidence/{id}/public-summaries`（`public:write`）：追加脱敏摘要新版本。
- `GET /evidence/{id}/public-summary`：任何有效登录用户可读，不含原件任何字节。

## 敏感身份

- `POST /cases/{id}/identities`：`{"label": "当事人/飞手", "data": {...}}`
  加密封存。
- `GET /cases/{id}/identities`：列表含每条 `accessible`（本人是否有授权）。
- `POST /cases/{id}/identities/{identity_id}/grant`：`{"user_id": n}` 逐案授权。
- `POST /cases/{id}/identities/{identity_id}/revoke`：撤销（历史保留）。
- `POST /cases/{id}/identities/{identity_id}/reveal`：凭有效授权解明；
  拒绝也留审计。

## 事实清单

- `GET /cases/{id}/facts`：当前版本。
- `PUT /cases/{id}/facts`：`{"content": <结构化JSON>, "based_on": v,
  "change_note": "..."}`。`based_on` 必须等于当前版本，否则 409
  `fact_version_conflict`；首次提交 `based_on=0`。
- `GET /cases/{id}/facts/versions`、`GET /cases/{id}/facts/versions/{v}`。

## 认定与程序决定

- `POST /cases/{id}/decisions`：
  - `kind=finding`（`finding:write`）：字段 `title`、`content`、可选 `rule_id`、
    可选 `fact_version`（默认当前）、`evidence_ids[]`、`prior_decision_ids[]`。
    规则须在事发时点生效；证据须有效关联本案且未作废。
  - `kind=supplement_notice`：发出后案件进入 `supplementing`，可带
    `supplement_due_days`。
  - `kind=penalty_notice`（`decision:write`）：须先有有效 finding。
  - `kind=penalty_decision`：须先有 penalty_notice。
  - `kind=closure`：须先有处罚决定。
- `GET /cases/{id}/decisions?include_superseded=0`。
- `GET /decisions/{id}`：决定与固定引用集合。
- `GET /decisions/{id}/trace`：溯源——`rule_at_time`（含是否已有新版）、
  `fact_version_at_time`（含是否当前版本）、`evidence_chain`（每件保管链与
  事后作废/撤销标注）、`prior_decisions`、`handlers`、`change_history`、
  `supplements`、`later_materials_not_basis`（决定后才接收，`never_basis=true`）。
- `POST /decisions/{id}/supersede`：`{"reason": "..."}` 撤销错误结论（只标记
  不删除）；仍被后续有效决定引用时返回 409 `decision_has_dependents`。

## 审计

- `GET /audit?case_id=&object_type=&object_id=&action=&limit=`（`audit:read`）：
  只追加日志倒序返回。典型 action：`evidence.view`、`evidence.download`、
  `evidence.intake`、`evidence.void`、`custody.*`、`identity.reveal`、
  `identity.reveal_denied`、`fact.save`、`decision.create.*`、`decision.trace`、
  `case.archive`。
