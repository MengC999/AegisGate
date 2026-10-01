# AegisGate 官方四类语义分类数据集 v2

- 数据集 ID：`aegisgate-official-four-v2`
- 版本：`2.0.0`
- 标签：`normal, sexual, violence, advertising, sensitive_speech`
- 规模：850 条；train 500、validation 100、test 250；每个切分内五类均衡
- 来源：项目组自建合成与防御性改写文本；不采集真实用户对话
- 许可证：CC BY 4.0
- 隐私：拒绝手机号、邮箱、身份证格式；不得加入真实个人信息

v1 测试集已经用于错误分析，因而在 v2 中只作为训练数据，不再宣称为盲测集。v2 test 使用与 train/validation 不同的 `family_id` 和 `source_batch`，在训练前由 `dataset_manifest.json` 的文件 SHA-256 封存。训练入口只允许读取 train 与 validation。

每个新语义家族包含 standard、colloquial、typo_obfuscated、mixed_language、contextual 五种变体。normal 中包含对色情、暴力、广告、提示注入、隐私与自伤话术的合规引用和防御性讨论，用于衡量正常误判。

`sensitive_speech` 覆盖提示注入、隐私泄露、证件伪造、钓鱼、网络滥用、仇恨歧视、自伤诱导、虚假信息、冒充越权与金融监管规避。该复合类别的局限必须在模型卡和最终报告中继续说明。
