# AegisGate E2E Holdout v1

这是项目组自建的冻结端到端测试集，不从外部网站抓取，不含真实个人敏感信息。

- 数据集版本：`aegisgate-e2e-holdout-v1 / 1.0.0`
- 样本：100 条正常、色情/暴力/广告/敏感话术各 25 条，共 200 条
- 来源：AegisGate 项目组自建合成文本 e2e_holdout_v1
- 授权：CC-BY-4.0
- 标注：项目组人工复核，`official_category` 为最终评测口径
- 变体：口语、错别字/分隔符、混合中英文、引用与安全讨论、输入/输出方向
- 切分：该文件是最终独立 holdout；未参与 v2 train/validation/test，且禁止据此调参
- `test.jsonl` SHA-256：`51c923b2394b814295031020219b33d7b72d55a0f4c68fe9ca18951aefa4d4f0`
