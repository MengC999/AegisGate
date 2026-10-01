# Bundled Runtime Notices

- CPython 3.12.10 Windows x64 embeddable package: https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip . License: `.runtime/python/LICENSE.txt`.
- NumPy 2.2.6 (BSD) and ONNX Runtime 1.23.2 (MIT), with their declared runtime dependencies. Versions are recorded in `runtime-packages.json`; distribution metadata and license files are retained under `.runtime/python/Lib/site-packages/`.
- Microsoft Visual C++ 14 runtime DLLs are included app-locally for the Python/native inference components. These Microsoft-signed redistributable runtime components remain subject to Microsoft's license terms: https://visualstudio.microsoft.com/license-terms/ . Windows operating-system DLLs are not included.
- The ONNX model is derived from `hfl/rbt3` (Apache-2.0), revision `0aa0527ff4170f29e1dfd3eb6ef60dc67e1bf75c`. Source, modification notes, license and checksums are in `models/official_four_onnx_v2/`.
- Lucide 0.468.0 (ISC): `web/assets/lucide-LICENSE.txt`.
- Chart.js 4.4.7 (MIT): `web/assets/chartjs-LICENSE.md`.
- The 4K landscape background comes from https://images.unsplash.com/photo-1501785888041-af3ef285b470?auto=format&fit=crop&w=3840&q=95 under the Unsplash License (https://unsplash.com/license), cropped to 3840 x 2160. SHA-256: `4cb9fe6a7f859242c1ad22d9adbf52af377ea00cfd7549c6436bc2f42bac05ea`. The other background images are existing user-provided project assets.

This application package does not include Ollama, DeepSeek generation weights or training frameworks.
