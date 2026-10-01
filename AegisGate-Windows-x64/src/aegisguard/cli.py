from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .service import ConversationService
from .web import serve


ROOT = Path(__file__).resolve().parents[2]


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegisguard", description="AegisGate 对话内容安全网关")
    commands = parser.add_subparsers(dest="command", required=True)

    detect = commands.add_parser("detect", help="检测单条文本")
    detect.add_argument("text")
    detect.add_argument("--direction", choices=["input", "output"], default="input")

    chat = commands.add_parser("chat", help="执行输入、模型、输出双向过滤流程")
    chat.add_argument("text")
    chat.add_argument("--mock-output", help="指定受控的模拟模型输出")

    sequence = commands.add_parser("sequence", help="检测多轮文本的片段拼接与风险强化")
    sequence.add_argument("turns", nargs="+", help="按时间顺序提供各轮文本")
    sequence.add_argument("--direction", choices=["input", "output"], default="input")

    batch = commands.add_parser("batch", help="批量检测 JSON 文件")
    batch.add_argument("path", type=Path, help="包含 records 数组的 JSON 文件")
    batch.add_argument("--direction", choices=["input", "output"], default="input")
    batch.add_argument("--include-safe-text", action="store_true")

    server = commands.add_parser("serve", help="启动演示控制台与 REST API")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)

    commands.add_parser("stats", help="显示运行统计")
    commands.add_parser("verify-audit", help="验证审计日志哈希链")

    words = commands.add_parser("words", help="管理热更新词库")
    word_commands = words.add_subparsers(dest="word_command", required=True)
    word_commands.add_parser("list", help="列出词库摘要")
    add = word_commands.add_parser("add", help="添加词条")
    add.add_argument("category")
    add.add_argument("term")
    remove = word_commands.add_parser("remove", help="删除词条")
    remove.add_argument("category")
    remove.add_argument("term")
    import_file = word_commands.add_parser("import", help="导入 JSON 词库")
    import_file.add_argument("path", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        serve(ROOT, args.host, args.port)
        return 0

    service = ConversationService(ROOT)
    if args.command == "detect":
        _print(service.detect(args.text, args.direction).to_dict())
    elif args.command == "sequence":
        decision, analysis = service.detect_sequence(args.turns, args.direction)
        _print({"decision": decision.to_dict(), "context_analysis": analysis})
    elif args.command == "chat":
        _print(service.process(args.text, mock_output=args.mock_output).to_dict())
    elif args.command == "batch":
        payload = json.loads(args.path.read_text(encoding="utf-8-sig"))
        records = payload.get("records") if isinstance(payload, dict) else payload
        _print(service.batch_detect(records, args.direction, args.include_safe_text))
    elif args.command == "stats":
        _print(service.stats())
    elif args.command == "verify-audit":
        result = service.audit.verify()
        _print(result)
        return 0 if result["valid"] else 1
    elif args.command == "words":
        library = service.engine.keywords
        if args.word_command == "list":
            _print(
                {
                    category: {"score": value.get("score"), "count": len(value.get("terms", [])), "terms": value.get("terms", [])}
                    for category, value in library.categories().items()
                }
            )
        elif args.word_command == "add":
            _print({"added": library.add(args.category, args.term)})
        elif args.word_command == "remove":
            _print({"removed": library.remove(args.category, args.term)})
        elif args.word_command == "import":
            _print({"added": library.import_file(args.path)})
    return 0
