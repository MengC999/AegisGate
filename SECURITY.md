# 安全问题报告

维护者：M4wwtr4c3。当前维护版本为 3.1.x。

请优先使用仓库 Security 页面的 **Report a vulnerability**：
https://github.com/MengC999/AegisGate/security/advisories/new

该入口需要仓库启用 Private vulnerability reporting。如果入口不可用，请创建标题为 `security: private contact requested` 的 Issue，正文只请求私密联系渠道。不要公开漏洞细节、真实日志、个人信息、令牌或可利用样本。

私密报告可包含受影响版本、最小化复现、影响、预期与实际行为及脱敏证据。具体响应与修复时间取决于维护者可用时间。

## 默认安全边界

- 默认回环监听；默认生成模型为 Mock。
- API Key 只从进程环境读取；不会自动加载 `.env`。
- 运行数据库、日志、审核队列和本地模型缓存不应提交到仓库。
- `AEGIS_LOG_PREVIEW=1` 仅用于受控本地调试。
- 远程共享令牌与 `X-Aegis-*` 请求头须由可信身份代理管理，不构成独立公网多用户认证。
- 模型故障会明确报告；规则回退不能视为完整语义模型继续可用。

提交 PR 前请检查代码、截图、测试数据和历史记录是否含凭证、个人信息或未经授权的第三方内容。
