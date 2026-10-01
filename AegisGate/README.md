# AegisGate

**面向大模型的内容安全网关与安全运营工作台。**

作者：**M4wwtr4c3** · 代码版本：**3.1.0** · Apache-2.0

AegisGate 在模型调用前后执行内容检测、隐私脱敏和多轮关联判定，并提供资产、告警、漏洞、工单、报表与审计的本地 Web 工作台。前端使用原生 HTML/CSS/JavaScript 和玻璃材质；后端为 Python，同源提供页面与 API。

本发行版范围为 Python 后端与 Web 前端。原工作目录中的 Android WebView 实验壳及 APK 不在本源码包中，也不计入当前测试结果；它尚需独立构建与后端接入验证。

默认使用 Mock 生成模型，无需云端密钥。可选 ONNX 分类器在 CPU 上推理，可选 DeepSeek 或 OpenAI-compatible 服务提供生成能力。Mock、ONNX 内容分类器与 DeepSeek 生成模型是不同组件。

## 快速启动

建议使用 **Python 3.12**。代码兼容目标为 Python 3.10–3.13，实际验证范围见 [测试说明](docs/testing.md)。前端无构建步骤，无需 Node/npm 即可运行。

拿到源码 ZIP 后，将其解压到空文件夹，在包含本文件的目录打开终端即可；不要把 ZIP 本身或整个私人工作目录上传成仓库源码。也可在仓库公开后克隆：

```bash
git clone https://github.com/MengC999/AegisGate.git
cd AegisGate
python -m venv .venv
```

Windows PowerShell 激活：

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux/macOS 激活：

```bash
source .venv/bin/activate
```

仅体验工作台、Mock、规则与辅助分类器时，直接运行：

```bash
python scripts/launch_demo.py
```

这条路径只依赖 Python 标准库；缺少 ONNX 权重会明确显示语义模型 `unavailable`。完整语义检测需再安装依赖和权重：

```bash
python -m pip install -r requirements.txt
python scripts/download_models.py --model v2
python scripts/launch_demo.py
```

访问启动器显示的地址，默认是 <http://127.0.0.1:8765>。Windows 安装完成后也可以双击 `启动演示.bat`。

**模型权重通过独立的 `models-v1` Release 分发，不在 Git 源码中。** 下载器检查固定文件大小和 SHA-256。也可手动下载模型资产后运行 `python scripts/download_models.py --model all --source-dir <资产目录>`。首次安装依赖和模型需要网络，准备完成后默认演示可以离线使用。

若 Release 尚未发布或网络不可达，使用配套的 `AegisGate-3.1.0-with-models.zip`；在解压后的 `AegisGate/` 下运行 `python scripts/download_models.py --model all --source-dir ../model-assets`。该包包含源码和两个 ONNX 权重，不包含 Python、pip 依赖或 DeepSeek 权重。详细包结构与校验步骤见 [发行包说明](docs/releases.md)。

没有 ONNX 权重时仍可启动，规则与辅助分类器继续工作，系统状态会显示语义模型 `unavailable`；这不等于完整语义检测已启用。完整测试需要 `python scripts/download_models.py --model all`。

## 功能

- 输入、输出和多轮关联检测，支持 `pass`、`mask`、`review`、`block`、`support`。
- 关键词、正则、归一化、ONNX 五分类及辅助字符分类器联合形成判定证据。
- 批量治理、可解释证据、默认不保存原文的摘要审计链。
- 资产、告警、漏洞、巡检、工单、报告及权限范围管理。
- 可更换背景的玻璃界面，白色主信息、浅灰色辅助信息。
- 独立运营页面，可直接打开 `/?view=ops-reports` 等视图。

## 模型与配置

`config/api_config.json` 默认 `provider: mock`。启用云端 DeepSeek 需要主动修改配置，并在进程环境中设置 `DEEPSEEK_API_KEY`。程序不会自动读取 `.env`，`.env.example` 仅作配置提示。不要把密钥写入 JSON。

本地 DeepSeek-V2-Lite 使用 Ollama，安装和硬件说明见 [本地模型部署](docs/local-deepseek.md)。项目不会随源码分发 Ollama、DeepSeek 权重或本地运行数据，也不会在默认启动时自动下载这些大文件。

## API 示例

```bash
curl http://127.0.0.1:8765/api/health
curl -X POST http://127.0.0.1:8765/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"text":"请整理会议纪要","direction":"input"}'
```

完整契约见 [API 文档](docs/api-reference.md)，业务表结构见 [运营数据结构](docs/enterprise-operations-schema.md)。

## 开发与测试

```bash
python -m pip install -r requirements-dev.txt
python scripts/download_models.py --model all
python -m unittest discover -s tests -p "test_*.py"
node --test tests/test_dashboard.cjs tests/test_operations_navigation.cjs
python scripts/onnx_smoke_test.py
python scripts/launch_demo.py --health-check
```

Node.js 22 用于前端测试；正常运行前端无需 Node 或 npm。Python 依赖使用固定版本。GitHub Actions 配置提供 Windows/Linux Python 测试与前端检查；远程执行结果以仓库 Actions 页面为准。

## 目录

| 路径 | 内容 |
|---|---|
| `src/aegisguard/` | 安全判定、服务、运营与 API |
| `web/` | 控制台、玻璃着色器及本地前端资源 |
| `config/` | 默认策略和无密钥模型配置 |
| `data/` | 合成演示、词库及评测数据 |
| `models/` | 来源、许可证、校验和及下载清单 |
| `tests/` | 单元、API 和前端回归测试 |
| `docs/` | 部署、使用及贡献相关文档 |
| `reports/` | 匿名历史回归证据，不代表最新测试已通过 |
| `runtime/` | 首次运行自动生成的本地数据，禁止提交 |

## 部署边界

默认仅监听 `127.0.0.1`。它是单机研究和演示实现，不能仅凭本项目的角色请求头和共享令牌作为公网多用户认证系统。远程使用需要可信反向代理、独立身份认证、TLS 及严格控制的作用域请求头，详见 [部署说明](docs/deployment.md)。

检测会误报或漏报，合成评测结果不能代表生产准确率。生产使用前应进行目标业务评测，并设置人工复核、申诉与数据留存机制。

## 许可证与贡献

代码使用 [Apache-2.0](LICENSE)，版权说明见 [NOTICE](NOTICE)。第三方图标、图表、ONNX 衍生模型和数据分别保留原许可证，见 [第三方说明](THIRD_PARTY_NOTICES.md)。发布版本使用原创 SVG 背景，不含个人提供的照片、项目申报报告或专利申请材料。

贡献前请阅读 [贡献指南](CONTRIBUTING.md) 与 [行为准则](CODE_OF_CONDUCT.md)。漏洞报告请使用 [安全说明](SECURITY.md) 中的私密渠道；功能建议可提交 Issue。

## 维护与支持

3.1.x 是当前维护系列，问题和功能需求通过仓库 Issue 跟踪，尚无固定服务等级或更新时间承诺。提交问题请附版本、系统和脱敏后的复现步骤。依赖升级由 Dependabot 提出，合并前仍需完整回归；前端本地第三方脚本需人工同步版本与许可证。新背景的浏览器视觉检查及 Linux 验证状态单独记录，不以源码测试代替。
