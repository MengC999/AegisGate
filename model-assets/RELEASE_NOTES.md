# AegisGate ONNX models v1

This release distributes both historical v1 and default v2 classifier weights for AegisGate 3.1.0. These are fine-tuned HFL rbt3 derivatives under Apache-2.0, not the optional DeepSeek generation model.

Download the corresponding ONNX asset along with models-metadata.zip, LICENSE.apache-2.0.txt, NOTICE and SHA256SUMS. Model metadata, vocabulary, labels, source attribution and modifications are also included in the source repository.

From the AegisGate source directory, install both models with:

```bash
python scripts/download_models.py --model all
python scripts/download_models.py --model all --verify-only
```

For offline installation, place the two ONNX assets in one directory and run:

```bash
python scripts/download_models.py --model all --source-dir <asset-directory>
```

The downloader validates exact file sizes and SHA-256 digests before installing. Default startup does not download weights. The v2 classifier is the default; v1 is retained for regression tests. Synthetic evaluation metrics are not guarantees of production performance.
