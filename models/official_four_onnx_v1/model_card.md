# AegisGate Official Four rbt3 ONNX v1

- Base encoder: `hfl/rbt3` at `0aa0527ff4170f29e1dfd3eb6ef60dc67e1bf75c`
- License: Apache-2.0; this directory contains the license and modification notice
- Task labels: `normal, sexual, violence, advertising, sensitive_speech`
- Training data: project-authored synthetic dataset; train 150, validation 25
- Test-set usage during training: 0
- Runtime: ONNX Runtime CPU; no Torch or Transformers required
- Export: genuine fine-tuned encoder plus five-class linear head, ONNX opset 17
- Best validation accuracy: 0.84
- Best validation macro F1: 0.831818

This model is an AegisGate fine-tuned derivative of HFL rbt3. It is not a rule or constant-output model. Final test-set metrics are produced separately by `python scripts/evaluate_onnx_classifier.py`; validation metrics must not be represented as open-world production accuracy.
