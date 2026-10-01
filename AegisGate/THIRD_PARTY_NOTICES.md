# 第三方依赖与许可证说明

## 运行依赖

| 组件 | 固定版本/标识 | 许可证 | 用途与来源 |
|---|---|---|---|
| NumPy | 2.2.6 | BSD-3-Clause | ONNX 输入张量；<https://github.com/numpy/numpy> |
| ONNX Runtime | 1.23.2 | MIT | 本地 CPU 推理；<https://github.com/microsoft/onnxruntime> |
| hfl/rbt3 | revision `0aa0527ff4170f29e1dfd3eb6ef60dc67e1bf75c` | Apache-2.0 | 五分类微调基础编码器；<https://huggingface.co/hfl/rbt3> |

主模型目录 `models/official_four_onnx_v2/` 在源码中保存词表、标签、模型卡、固定来源 revision、修改说明、Apache-2.0 许可证和 SHA-256。微调衍生权重通过独立的 `models-v1` Release 资产分发，由 `scripts/download_models.py` 安装。`model.onnx` 为 154,006,588 bytes，SHA-256 为 `023e11ba9bef71b5e285e0f720bef4ea72aeeaf5e136f935abdeadf5cfc86710`。普通启动只使用已安装资产，不会联网下载模型；运行时显式使用 `CPUExecutionProvider`。

`models/official_four_onnx_v1/` 保留历史模型元数据与 Apache-2.0 文件，权重同样独立分发，供完整回归测试使用。重新分发任一权重时应同时保留对应模型卡、来源、修改说明、许可证和校验和。

## 数据集

`data/semantic_classifier_v2/` 为项目组自建合成与防御性改写的训练、验证和模型测试数据，许可证 CC BY-4.0。`data/e2e_holdout_v1/` 为项目组自建的冻结端到端集，许可证 CC BY-4.0，数据卡和 SHA-256 随目录保存。两类数据均不包含真实对话或真实个人信息；训练、验证、模型测试和冻结端到端评测分离。

`data/semantic_classifier_v1/` 为保留的历史自建合成资产，许可证 CC BY-4.0。

## 仅训练与导出

以下依赖只在显式安装 `requirements-training.txt` 时使用，不是最终演示运行依赖：

| 组件 | 固定版本 | 许可证 | 来源 |
|---|---:|---|---|
| PyTorch | 2.6.0 | BSD-3-Clause | <https://github.com/pytorch/pytorch> |
| Transformers | 4.48.3 | Apache-2.0 | <https://github.com/huggingface/transformers> |
| ONNX | 1.17.0 | Apache-2.0 | <https://github.com/onnx/onnx> |
| huggingface-hub | 0.36.2 | Apache-2.0 | <https://github.com/huggingface/huggingface_hub> |

## 前端运行依赖

| 组件 | 固定版本 | 许可证 | 用途与来源 |
|---|---|---|---|
| Lucide | 0.468.0 | ISC | 控制台图标；https://lucide.dev/；许可证见 `web/assets/lucide-LICENSE.txt` |
| Chart.js | 4.4.7 | MIT | 工作台趋势和分布图表；https://www.chartjs.org/；许可证见 `web/assets/chartjs-LICENSE.md` |

上述脚本随项目本地提供，页面运行时不请求外部 CDN。

## 项目视觉资源

`web/assets/mark.svg` 为项目标志；`glass-architecture.svg` 和 `glass-landscape.svg` 为本次开源准备新建的抽象 SVG 背景，按项目 Apache-2.0 许可证提供。来源或再分发许可不明确的照片没有纳入源码包。Lucide 与 Chart.js 仍适用上表所列各自许可证。

## 可选本地生成模型

Windows 安装脚本可另行下载 Ollama 0.34.2（MIT，<https://github.com/ollama/ollama>）和 DeepSeek-V2-Lite Chat 16B Q4_0（<https://ollama.com/library/deepseek-v2:16b>，上游 <https://huggingface.co/deepseek-ai/DeepSeek-V2-Lite-Chat>）到 `runtime/local-deepseek/`，这些文件不纳入源码或 ONNX 发布资产。DeepSeek 权重适用 DeepSeek Model License；模型许可证随 Ollama 模型 license layer 保存，推理运行时依赖的许可证包含在官方分发包中。使用和再分发须遵守相应上游条款。

## 云端与兼容接口

DeepSeek 和 OpenAI-compatible provider 是显式配置的下游对话服务，不是本地 ONNX 分类器依赖。默认 provider 为 Mock。启用 DeepSeek 时，程序只从当前进程环境变量 `DEEPSEEK_API_KEY` 读取密钥；配置、日志、报告和交付包不保存 Key、Authorization 或环境变量值。自动化测试使用本地 Fake Server，不调用真实 DeepSeek。

## 公开技术参考（非运行依赖）

- ApexSentinel：<https://github.com/Netsec-SJTU/ApexSentinel>
- 公开论文 DOI：<https://doi.org/10.1016/j.comnet.2026.112437>

上述资料仅用于高层安全工程方法研究。交付包不包含或派生其代码、数据、模型及视觉资产；该项目不是 AegisGate 的运行时、训练或构建依赖。

实际验证范围和复现命令见 [测试说明](docs/testing.md)；历史评测不代表已在所有目标平台验证。
