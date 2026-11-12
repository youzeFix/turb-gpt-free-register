# -*- coding: utf-8 -*-
"""Remail 接码通道批量体检。

对账号池中 email_source=remail 的账号逐个探测取码通道：
1. 恢复取件上下文（保存的 service token → 订单详情 → 按邮箱搜索订单）；
2. 订单详情 status/failureCode/serviceMode(expiresAt) 判断是否已终结；
3. 单次 pickup 探测，服务端确定性错误（404/过期/失效）才判死。

code 模式（短效接码）注册的账号在订单过期后无法再收取邮箱 OTP，
这类账号直接标记 deactivated 踢出账号池，避免后续查活浪费登录流量。
购买模式（purchase）订单不受影响。

用法：
    .venv\\Scripts\\python.exe tools\\remail_channel_check.py            # 只报告，不落库
    .venv\\Scripts\\python.exe tools\\remail_channel_check.py --apply    # 报告并标记废号
    .venv\\Scripts\\python.exe tools\\remail_channel_check.py --account-id 42 --apply

所有请求直连（不走住宅/注册代理），每账号约 2 次 API 调用。
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import time
from datetime import datetime
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from core import db  # noqa: E402
from core.remail_client import (  # noqa: E402
    RemailError,
    evaluate_order_dead,
    get_order_detail,
    probe_pickup_channel,
    restore_account_context,
)


def _load_remail_accounts() -> list[dict]:
    rows = db.list_accounts(limit=100000, archived="0")
    accounts = [
        r for r in rows
        if str(r.get("email_source") or "").strip().lower() == "remail"
        and str(r.get("email") or "").strip()
        and str(r.get("live_check_status") or "").strip().lower() != "deactivated"
    ]
    # code 模式误操作批次集中在早期账号；按注册时间从早到晚体检。
    accounts.sort(key=lambda a: str(a.get("created_at") or ""))
    return accounts


def _mark_deactivated(account: dict, reason: str, apply: bool) -> bool:
    if not apply:
        return False
    now = datetime.now().isoformat(timespec="seconds")
    email = str(account.get("email") or "")
    updated = db.update_account_liveness(int(account.get("id") or 0), {
        "ok": False,
        "status": "deactivated",
        "checked_at": now,
        "error": reason,
    })
    if updated:
        try:
            from core.email_provider import release_email
            release_email(email, status="failed", note=reason)
        except Exception:
            pass
    return updated


def check_account(account: dict) -> dict:
    """体检单个账号；返回 {"state": alive/dead/unknown, "reason": str}。"""
    email = str(account.get("email") or "").strip()
    # 1) 恢复取件上下文（保存 token → 订单详情 → 邮箱搜索）
    try:
        context = restore_account_context(email)
    except RemailError as exc:
        return {"state": "dead", "reason": f"Remail 上下文恢复失败: {str(exc)[:180]}"}
    except Exception as exc:
        return {"state": "unknown", "reason": f"{type(exc).__name__}: {str(exc)[:160]}"}
    if context is None:
        return {"state": "dead", "reason": "无法恢复 Remail 取件上下文（订单搜索不到或凭证缺失）"}

    # 2) 订单详情：status/failureCode/serviceMode 过期判断
    order_no = str(getattr(context, "order_no", "") or "").strip()
    if order_no:
        try:
            detail = get_order_detail(order_no)
        except RemailError as exc:
            return {"state": "unknown", "reason": f"订单详情查询失败: {str(exc)[:180]}"}
        except Exception as exc:
            return {"state": "unknown", "reason": f"{type(exc).__name__}: {str(exc)[:160]}"}
        dead_reason = evaluate_order_dead(detail)
        if dead_reason:
            return {"state": "dead", "reason": dead_reason}

    # 3) 单次 pickup 探测：只有服务端确定性错误才判死
    probe = probe_pickup_channel(email, getattr(context, "service_token", ""))
    if probe["dead"]:
        return {"state": "dead", "reason": f"Remail pickup 通道已失效: {probe.get('error')}"}
    if not probe["ok"]:
        return {"state": "unknown", "reason": f"pickup 探测不确定错误，跳过: {probe.get('error')}"}
    return {"state": "alive", "reason": ""}


def main() -> int:
    import io as _io
    sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Remail 接码通道批量体检")
    parser.add_argument("--apply", action="store_true", help="把判定失效的账号标记为 deactivated（默认只报告）")
    parser.add_argument("--account-id", type=int, default=0, help="只体检指定账号")
    parser.add_argument("--delay", type=float, default=0.3, help="每账号之间的间隔秒数")
    args = parser.parse_args()

    accounts = _load_remail_accounts()
    if args.account_id:
        accounts = [a for a in accounts if int(a.get("id") or 0) == args.account_id]
    print(f"待体检 Remail 账号: {len(accounts)} 个（apply={args.apply}）")

    summary = {"alive": 0, "dead": 0, "unknown": 0}
    dead_list: list[tuple[int, str, str]] = []
    for index, account in enumerate(accounts, 1):
        acc_id = int(account.get("id") or 0)
        email = str(account.get("email") or "")
        result = check_account(account)
        summary[result["state"]] += 1
        if result["state"] == "dead":
            dead_list.append((acc_id, email, result["reason"]))
            if args.apply:
                ok = _mark_deactivated(account, result["reason"], apply=True)
                print(f"[{index}/{len(accounts)}] {acc_id} {email} 已标记 deactivated: {result['reason'][:120]}"
                      + ("" if ok else "（落库失败）"))
            else:
                print(f"[{index}/{len(accounts)}] {acc_id} {email} 判定失效（未落库）: {result['reason'][:120]}")
        elif result["state"] == "unknown":
            print(f"[{index}/{len(accounts)}] {acc_id} {email} 不确定，跳过: {result['reason'][:120]}")
        if args.delay > 0 and index < len(accounts):
            time.sleep(args.delay)

    print(f"\n体检完成: 存活 {summary['alive']} / 失效 {summary['dead']} / 不确定 {summary['unknown']}")
    if summary["dead"] and not args.apply:
        print("确认后追加 --apply 重新执行即可标记 deactivated（账号池/巡检将自动跳过，可再通过 WebUI 删除）。")
    if summary["dead"]:
        path = Path(_PROJECT_ROOT) / "注册日志" / "remail-channel-dead.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dead_list, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"失效清单已保存: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
