# -*- coding: utf-8 -*-
"""
命令行版「邮箱域名体检」。

用法：
    python tools/probe_domain.py mydomain.com
    python tools/probe_domain.py a.com b.com --no-register
    python tools/probe_domain.py a.com,b.com --proxy http://127.0.0.1:7897

体检过程不购买任何邮箱、不消耗取码额度，只用一个随机 probe 地址走一遍
OpenAI 的注册链路，判断这个域名会不会被拒。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.domain_probe import (  # noqa: E402
    VERDICT_ACCEPTED,
    VERDICT_INCONCLUSIVE,
    VERDICT_REJECTED,
    probe_domains,
)

_VERDICT_TEXT = {
    VERDICT_ACCEPTED: "✅ 可用",
    VERDICT_REJECTED: "❌ 被 OpenAI 拒绝",
    VERDICT_INCONCLUSIVE: "⚠️ 无法判定",
}

_STAGE_TEXT = {
    "input": "打开登录页",
    "email_submit": "邮箱提交",
    "register": "建号提交",
    "exception": "异常",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="免费体检邮箱域名是否会被 OpenAI 拒绝")
    parser.add_argument("domains", nargs="+", help="一个或多个域名，可用逗号分隔")
    parser.add_argument("--proxy", default="", help="浏览器代理，如 http://127.0.0.1:7897；留空走项目配置")
    parser.add_argument(
        "--no-register",
        action="store_true",
        help="只探邮箱提交这一步（不建号）。快一些，但会漏掉域名级拒收。",
    )
    args = parser.parse_args()

    items: list[str] = []
    for chunk in args.domains:
        for item in str(chunk).replace(";", ",").split(","):
            text = item.strip()
            if text and text not in items:
                items.append(text)

    if not items:
        print("请至少给一个域名")
        return 2

    print(f"体检域名: {', '.join(items)}")
    print("说明: 不购买邮箱、不消耗额度；会打开浏览器，每个域名约 1~3 分钟。")
    print("提示: 结论是时效性的（域名会随当天注册量/IP 信誉翻转），建议每批开跑前先体检一次。")
    print("      '邮箱提交步被拒'会自动重试 3 次，避免把偶发失败当成域名被拒。\n")

    results = probe_domains(
        items,
        proxy=args.proxy.strip() or None,
        check_register=not args.no_register,
    )

    print()
    print("=" * 78)
    for item in results:
        verdict = _VERDICT_TEXT.get(item.verdict, item.verdict)
        stage = _STAGE_TEXT.get(item.stage, item.stage)
        print(f"{verdict}  {item.domain}")
        print(f"    卡在阶段: {stage}    耗时: {item.elapsed}s")
        if item.detail:
            print(f"    说明: {item.detail}")
        if item.probe_email:
            print(f"    探测地址: {item.probe_email}")
    print("=" * 78)

    if any(item.verdict == VERDICT_REJECTED for item in results):
        return 1
    if all(item.verdict == VERDICT_ACCEPTED for item in results):
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
