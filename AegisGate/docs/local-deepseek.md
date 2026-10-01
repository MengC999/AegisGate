# 可选：DeepSeek-V2-Lite 本地生成

默认启动无需 DeepSeek。可选使用 Ollama 的 `deepseek-v2:16b`，对应 DeepSeek-V2-Lite Chat 量化模型，**不是完整 236B DeepSeek-V2**。模型下载约 9 GB，运行内存、显存和速度取决于设备、量化与上下文；不要把个别开发设备的性能作为保证。

使用上游官方安装包安装 Ollama 后：

```bash
ollama pull deepseek-v2:16b
ollama create aegis-deepseek-v2:16b -f config/DeepSeekV2.Modelfile
python scripts/launch_demo.py --model-config config/deepseek_local.json
```

Ollama 服务须已在 `127.0.0.1:11434` 运行。网页进入安全检测台，选择“双向流程”；单段检测只执行内容检测，不调用生成模型。

Windows 也提供 `start_deepseek_local.bat`，它会下载固定版本 Ollama 和模型到 `runtime/local-deepseek/`，执行文件校验，并在后台启动服务。首次使用需要下载大量文件。关闭网页不会自动结束后台服务；按本地 PID/进程命令行核对后关闭对应进程。

本地启动器从 `.venv` 或系统 Python 选择解释器；可显式传入 `-Python` 和 `-RuntimeDirectory`。本地模式不携带云端 `DEEPSEEK_API_KEY`。权重适用上游 DeepSeek Model License，Ollama 适用 MIT；源码 Apache-2.0 不重新许可这些权重。
