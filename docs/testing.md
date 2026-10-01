# 测试与可复现性

建议 Python 3.12，安装 `requirements-dev.txt`。全量回归需要 v1/v2 ONNX 权重和它们原有的许可证、元数据、哈希。使用源码加模型包时，先运行 `python scripts/download_models.py --model all --source-dir ../model-assets`，无需访问模型下载站点。

```bash
python scripts/download_models.py --model all
python scripts/download_models.py --model all --verify-only
python -m unittest discover -s tests -p "test_*.py"
node --test tests/test_dashboard.cjs tests/test_operations_navigation.cjs
python scripts/onnx_smoke_test.py
python scripts/launch_demo.py --health-check
```

自动化使用 Mock 与本地 Fake Server，不需要真实 API Key。真实模型自检必须显式配置，不是默认测试步骤。

2026-10-01 的本地准备使用 Windows、CPython 3.12.14 与 Node.js 24.21.0。Node.js 22 是 CI 配置版本；Linux 与远程 Actions 尚需在发布后实际执行验证。

`reports/` 中五份历史匿名评测文件是现有回归测试的固定证据，用于核对指标、数据与代码哈希；它们不等于最新源码已经重新验收，也不代表开放环境效果。机器路径和操作系统信息不进入公开测试说明。新增运行日志保留在本地发布准备目录。

GitHub Actions 分别运行标准库源码打包检查、Node.js 22 前端测试和 Python 3.12 Windows/Linux 完整回归。源码包检查无需模型下载，会验证干净副本在缺少权重和第三方包时仍能启动。完整回归必须先上传 `models-v1` Release 的两个模型资产；权重不可用时该步骤会失败。只有实际执行通过的系统才可声称已验证。

发布前在干净暂存目录运行 `python scripts/build_manifest.py` 生成摘要，再运行 `python scripts/delivery_preflight.py --require-manifest --strict`。权重作为独立资产，不进入源码摘要；它们由各自的 `SHA256SUMS` 与 `models/downloads.json` 校验。缺少权重时预检显示 `external`，元数据和清单仍须完整；任一元数据或已安装权重损坏均阻止发布。

源码包校验命令：

```bash
python scripts/verify_release.py ../AegisGate-source-3.1.0.zip --sha256 <发行者提供的摘要>
```

该工具验证 ZIP CRC、路径、排除项、完整文件清单、SHA-256 和模型元数据，不安装依赖、不下载模型。BAT 文件按 CRLF 计算摘要，以兼容 Git 在不同平台的换行处理；数据、模型元数据及历史证据按原始字节校验。摘要应来自可信发行渠道，不能仅凭包内自带摘要证明发行者身份。

浏览器 E2E 脚本的背景断言已对应原创 SVG。当前准备环境未获浏览器预览权限，因此该脚本没有在本轮执行；需要有权使用浏览器的环境单独运行，不能将语法或 Node 测试视为视觉验收。
