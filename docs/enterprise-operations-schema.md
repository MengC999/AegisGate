# 企业安全运营数据结构

## 适用范围

本文件描述 `src/aegisguard/enterprise.py` 已实现的 SQLite 增量数据域。数据库在首次访问企业接口时创建于 `runtime/enterprise_operations.db`，不替换原有检测引擎、JSONL 审计或 `/api/v1/ops/*` 兼容接口。

所有业务表均包含 `tenant_id`、`project_id`、`created_by`、`created_at`、`updated_at`；HTTP 请求还携带 `user_id` 和角色。资产关联查询在数据库层应用 `role_asset_groups`，因此列表总数、详情、导出、仪表盘、待办和报告使用同一权限结果。

## 表清单

| 业务域 | 数据表 | 用途 |
|---|---|---|
| 元数据 | `enterprise_meta` | Schema 版本与幂等演示种子状态 |
| 资产 | `asset_groups`, `assets`, `asset_tags`, `asset_tag_links`, `asset_history` | 分组、台账、标签和不可覆盖的变更版本记录 |
| 探测 | `discovery_tasks` | 绑定授权单的单资产、单端口 DNS/TCP 连通性检查 |
| 告警 | `alerts`, `alert_notes`, `alert_filter_rules`, `notifications` | 多源告警、处置备注、过滤规则、重复聚合和站内通知 |
| 漏洞 | `scan_tasks`, `vulnerabilities`, `remediation_orders`, `retest_records` | 安全检查编排、漏洞生命周期、整改和批量复测 |
| 安全测试 | `security_test_projects`, `test_cases`, `test_records` | 授权测试项目、内置安全用例和测试过程摘要 |
| 应急 | `incidents`, `incident_actions`, `incident_links`, `forensics_records`, `iocs` | 事件工单、隔离到复盘流程、关联对象、证据摘要和 IOC |
| 运维 | `baseline_rules`, `inspection_tasks`, `baseline_findings`, `work_orders`, `work_order_receipts` | 基线规则、巡检、不合规项、整改工单与回执 |
| 报表 | `report_templates`, `report_archives` | 日/周/月、漏洞、测试、巡检和合规差距报告版本归档 |
| 权限审计 | `users`, `roles`, `user_roles`, `role_asset_groups`, `login_logs`, `operation_audit` | RBAC、资产组范围、登录日志与操作哈希链 |
| 系统配置 | `system_settings`, `scheduled_jobs`, `allowlist_entries`, `integration_configs` | 阈值、调度、IP/域名名单和第三方配置引用 |

数据库共 40 张表，其中 `enterprise_meta` 为内部元数据表。`operation_audit` 和 `login_logs` 均由 SQLite 触发器拒绝 `UPDATE` 与 `DELETE`。攻击载荷、原始日志、凭据和取证原文不进入这些表；系统只保存脱敏预览、SHA-256 摘要或外部凭据引用。

## 关键约束

- 资产地址与端口在租户/项目内唯一；资产变更增加版本号并追加 `asset_history`。
- 开放告警按来源、攻击类型、源 IP 和目标资产生成稳定指纹，重复告警更新 `repeat_count`。
- 漏洞风险优先级由 CVSS/严重度和资产权重计算，状态变更遵循固定生命周期。
- 安全测试、主动发现和扫描任务必须记录授权范围；平台不提供漏洞利用、提权或横向移动执行器。
- CSV、JSON、NDJSON 导入最多 500 条且不超过 200 KB，响应返回 `batch_sha256`、成功数和逐行错误。
- 非管理员角色没有资产组映射时默认看不到资产关联记录；控制面、完整审计和登录日志仅管理员可读写。

## 端到端业务链路

`Web 新建/筛选/流转/导出 -> /api/v1/enterprise/* -> Bearer/RBAC/租户项目与资产组校验 -> SQLite 事务与状态机 -> 脱敏证据和追加式审计 -> JSON/文件响应 -> 工作台表格、趋势图、详情和下载`

仪表盘的资产、告警、漏洞、事件、巡检、工单、高风险资产和 14 日趋势均从当前角色可见的真实业务记录聚合，不使用前端硬编码统计。

## 迁移边界

SQLite 适用于单机离线演示和小规模内部试用。共享环境应迁移到外部身份系统、PostgreSQL、对象存储、任务队列、集中日志和 TLS 反向代理，同时保留版本化 API、作用域字段、审计哈希和隐私最小化语义。
