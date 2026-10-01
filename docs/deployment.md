# 部署与配置

## 本地

按 README 创建虚拟环境、安装依赖、下载 ONNX v2 模型，然后运行 `python scripts/launch_demo.py`。前后端由同一个服务提供，无需另起 npm 服务。使用 `--port 8766` 选择端口，`--runtime-dir runtime/demo` 隔离本次数据库与审计。

默认 Mock 不联网。ONNX 是内容分类器，不生成对话。`provider: deepseek` 才会调用配置中的云端服务，需要在同一启动进程中设置 `DEEPSEEK_API_KEY`。程序不自动读取 `.env` 文件。

## 远程

默认监听回环地址。绑定非回环地址需要 `AEGIS_API_TOKEN`，但共享令牌本身不验证每一个业务用户。

当前实现接受 `X-Aegis-Tenant`、`X-Aegis-Project`、`X-Aegis-User` 和 `X-Aegis-Role` 请求头。对不可信客户端开放之前，需要可信身份代理完成用户认证、剥离客户端自带的作用域头、写入服务端确认的身份和角色，并阻止绕过代理直连后端。不要把 admin 共享令牌分发给普通用户。配置 TLS、网络访问控制、备份、限流与日志留存。

本项目没有宣称独立实现完整生产身份平台或取得安全合规认证。

## 数据

运行文件进入 `runtime/`；SQLite 的数据库、WAL/SHM、日志及审核队列均不属于源码。初次启动会生成本地演示数据。重置测试环境时使用新的 `--runtime-dir`，不要删除正在使用的业务目录。

项目启动后可通过 `/api/health`、`/api/v1/model/status` 和 `/api/v1/semantic-model/status` 分别确认服务、生成模型配置与语义分类模型状态。
