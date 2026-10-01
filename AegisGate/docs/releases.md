# 发行包与复现

## 选择文件

| 文件 | 包含内容 | 适用场景 |
|---|---|---|
| `AegisGate-source-3.1.0.zip` | 源码、默认配置、网页资源、合成数据、模型元数据、测试与许可证 | GitHub 源码发布与代码审阅 |
| `AegisGate-3.1.0-with-models.zip` | `AegisGate/` 源码和 `model-assets/` 两个 ONNX 权重、模型元数据及许可证 | 模型 Release 不可用时，本地安装完整分类器与运行全量测试 |
| `models-v1` Release | 单独的 v1/v2 ONNX 及许可证、元数据、校验和 | 已有源码后的按需安装 |

源码包在没有权重时可以启动 Mock、规则和辅助分类器；完整 ONNX 语义分类和全量测试必须安装权重。源码加模型包也不包含 Python 解释器、pip 依赖、Ollama 或 DeepSeek；完全离线部署前需要另行准备与目标系统匹配的 Python 依赖。

两种包均面向 Python + Web。原项目的 Android WebView 实验工程和 APK 未纳入当前源码发行版；因此本包不是原私人工作目录的完整镜像。项目报告、专利材料与授权不明确的照片也不在发布范围。

## 源码加模型包

解压到空目录，进入 `AegisGate/`，按照 README 创建并激活虚拟环境，然后运行：

```bash
python -m pip install -r requirements-dev.txt
python scripts/download_models.py --model all --source-dir ../model-assets
python scripts/download_models.py --model all --verify-only
python -m unittest discover -s tests -p "test_*.py"
python scripts/onnx_smoke_test.py
python scripts/launch_demo.py
```

仅运行时可将第一行替换为安装 `requirements.txt`。权重从配套目录复制并校验，不需要访问 GitHub。模型安装和依赖准备完成后，默认 Mock 与本地分类器可离线运行。

## 源码完整性

发行者应提供单独的 `SHA256SUMS`。使用 Python 标准库验证源码 ZIP：

```bash
python scripts/verify_release.py ../AegisGate-source-3.1.0.zip --sha256 <可信渠道取得的摘要>
```

验证器会拒绝路径越界、重复路径、私人文件、缺失文件、源文件摘要不符以及模型元数据损坏。它不访问外部服务。解压后也可用 `python scripts/build_manifest.py --verify` 检查源码是否发生变化。

## 维护者重新打包

在仓库工作目录运行以下命令。暂存目录必须是仓库外的新目录；先用当前环境完成实际测试，再打包：

```bash
python -B scripts/stage_delivery.py --destination ../AegisGate-staging
cd ../AegisGate-staging
python -B scripts/build_manifest.py
python -B scripts/delivery_preflight.py --require-manifest --strict
python -B scripts/build_delivery_package.py --output ../AegisGate-source-3.1.0.zip
python -B scripts/verify_release.py ../AegisGate-source-3.1.0.zip
```

生成器排除 Git 元数据、运行内容、虚拟环境、密钥文件、私人报告、专利材料、照片以及大模型权重。五份固定匿名评测 JSON 作为回归证据保留。不要直接压缩私人工作目录；源码 ZIP 应在独立干净目录再次解压验证。

## GitHub 发布顺序

先核对目标仓库及现有历史，再导入源码；不覆盖未知提交。发布 `models-v1` 的两版权重、`models-metadata.zip`、许可证、NOTICE 与 SHA256SUMS 后，执行完整 CI。验证通过再发布代码发行版，附源码包、配套包、摘要和真实测试记录。源码包 CI 不依赖模型下载，完整回归仍必须验证真实 ONNX 推理。

仓库公开前检查历史记录中有无私密文件，按 SECURITY.md 启用可用的私密漏洞报告渠道。发行标签应唯一；不要更改已发布模型资产来绕过固定哈希。
