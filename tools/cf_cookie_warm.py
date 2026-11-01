# -*- coding: utf-8 -*-
"""用真实有头 Chrome 给查活出口预热 CF __cf_bm Cookie。

Cloudflare 对 auth.openai.com 的 managed challenge 通常只针对无 JS 的自动化
TLS 指纹（curl_cffi/wreq、headless 浏览器）；有头真实 Chrome 访问一次即可
拿到未触发质询时的 __cf_bm，再由 core/cf_warm.py 注入协议查活会话。

用法（在项目根目录）：
    .venv\\Scripts\\python.exe tools\\cf_cookie_warm.py            # 预热全部出口
    .venv\\Scripts\\python.exe tools\\cf_cookie_warm.py --limit 3  # 只预热前 3 条
    .venv\\Scripts\\python.exe tools\\cf_cookie_warm.py --exit-key sid_12554321

注意事项：
- 会短暂弹出 Chrome 窗口，每条出口约 10~25 秒，预热窗口不要人为关闭。
- 走 config.proxy 的 PLAN_CHECK_PROXY + PLAN_CHECK_UPSTREAM_PROXY 链路，
  与查活完全同一网络路径（本地中继 -> 上游 -> 住宅出口）。
- 每条出口消耗约 0.1~0.3 MiB 住宅流量（auth 域首屏）。
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("cf_cookie_warm")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from core import cf_warm  # noqa: E402
from core.chatgpt_plan import _proxy_lines  # noqa: E402
from core.proxy_chain import ProxyChainRelay  # noqa: E402

AUTH_URL = "https://auth.openai.com/"
AUTH_COOKIE_FILTER = ("__cf_bm", "cf_clearance")


def _mask(proxy_url: str) -> str:
    parsed = urlparse(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
    auth = " ***@" if parsed.username else " "
    return f"{parsed.scheme or 'http'}://{auth}{parsed.hostname}:{parsed.port}"


def _maybe_click_turnstile(page) -> str:
    """尝试点击 CF 交互式质询里的 Turnstile 复选框；返回点击方式。"""
    try:
        for frame_handle in page.query_selector_all("iframe"):
            src = (frame_handle.get_attribute("src") or "")
            if "challenges.cloudflare.com" not in src:
                continue
            try:
                frame = frame_handle.content_frame()
                if frame is not None:
                    checkbox = frame.locator("input[type='checkbox'], [role='checkbox']").first
                    checkbox.click(timeout=2000)
                    return "checkbox"
            except Exception:
                pass
            box = frame_handle.bounding_box()
            if box:
                page.mouse.click(
                    box["x"] + box["width"] / 2,
                    box["y"] + min(box["height"] / 2, max(10.0, box["height"] - 8.0)),
                )
                return "center"
    except Exception:
        pass
    return ""


def warm_one_exit(proxy_url: str, *, upstream: str, headless: bool, profile_dir: str) -> dict:
    """对单个出口：本地开中继 -> 有头 Chrome 访问 auth 域 -> 保存 __cf_bm。"""
    relay = ProxyChainRelay(proxy_url, upstream, timeout=15).start() if upstream else None
    try:
        exit_ip, colo = "", ""
        if relay is not None:
            from curl_cffi import requests
            try:
                trace = requests.get(
                    "https://chatgpt.com/cdn-cgi/trace",
                    impersonate="chrome146", proxy=relay.proxy_url, timeout=15,
                )
                info = dict(
                    line.split("=", 1)
                    for line in trace.text.strip().splitlines()
                    if "=" in line
                )
                exit_ip, colo = info.get("ip", ""), info.get("colo", "")
            except Exception as exc:
                logger.warning("出口 IP 探测失败 %s: %s", _mask(proxy_url), exc)

        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            ctx = p.chromium.launch_persistent_context(
                user_data_dir=profile_dir,
                channel="chrome",
                headless=headless,
                proxy={"server": relay.proxy_url} if relay else None,
                locale="ja-JP",
                timeout=60000,
            )
            try:
                page = ctx.pages[0] if ctx.pages else ctx.new_page()

                def _challenging() -> bool:
                    try:
                        title = page.title() or ""
                        body_head = page.content()[:3000]
                    except Exception:
                        return False
                    return (
                        "just a moment" in title.lower()
                        or "challenge-platform" in body_head
                        or "しばらくお待ちください" in title
                    )

                resp = page.goto(AUTH_URL, wait_until="domcontentloaded", timeout=45000)
                status = resp.status if resp else None
                # managed challenge 完成后会自动回放原页面；等它求解完再取
                # Cookie 才是「已通过质询」的会话态（质询页首响应的 Cookie 无效）。
                # 质询策略波动时自动求解可能需要 2~4 分钟，这里最多等 4 分钟，
                # 每 5 秒查一次页面状态，只在页面逗留过久时才补偿性重新导航。
                start = time.time()
                interactive_hinted = False
                while time.time() - start < 300:
                    time.sleep(5)
                    if not _challenging():
                        break
                    elapsed = time.time() - start
                    if elapsed > 20 and not interactive_hinted:
                        print(f"    ⚠ {key} 遇到 CF 交互式人机验证；将自动点击复选框，"
                              "如 10 秒内仍停留验证页，请手动在弹出的 Chrome 窗口点击『确认您是真人』")
                        interactive_hinted = True
                    if elapsed > 25:
                        _maybe_click_turnstile(page)
                    if (50 < elapsed < 60 or 120 < elapsed < 130) and not _maybe_click_turnstile(page):
                        try:
                            resp = page.goto(AUTH_URL, wait_until="domcontentloaded",
                                             timeout=45000)
                            status = resp.status if resp else None
                        except Exception:
                            pass
                try:
                    resp = page.goto(AUTH_URL, wait_until="domcontentloaded", timeout=45000)
                    status = resp.status if resp else None
                except Exception:
                    pass
                ua = page.evaluate("navigator.userAgent")
                cookies = [
                    {k: c.get(k) for k in ("name", "value", "domain", "path", "expires")}
                    for c in ctx.cookies(AUTH_URL)
                    if c.get("name") in AUTH_COOKIE_FILTER
                    and ".auth.openai.com" in str(c.get("domain") or "")
                ]
            finally:
                ctx.close()
        return {
            "exit_key": cf_warm.exit_key_for_proxy(proxy_url),
            "exit_ip": exit_ip,
            "colo": colo,
            "http_status": status,
            "ua": ua,
            "cookies": cookies,
            "warmed_at": time.time(),
            "warmed_at_iso": datetime.now().isoformat(timespec="seconds"),
        }
    finally:
        if relay is not None:
            relay.close()


def main() -> int:
    import io as _io
    sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="预热查活出口 CF __cf_bm Cookie")
    parser.add_argument("--limit", type=int, default=0, help="只预热前 N 条出口（0=全部）")
    parser.add_argument("--exit-key", default="", help="只预热指定 exit_key（如 sid_12554321）")
    parser.add_argument("--headless", action="store_true", help="无头模式（容易仍被质询，默认有头）")
    args = parser.parse_args()

    from config import proxy as proxy_cfg
    plan_upstream = str(proxy_cfg.PLAN_CHECK_UPSTREAM_PROXY or "").strip()
    plan_proxies = _proxy_lines(proxy_cfg.PLAN_CHECK_PROXY)
    pool_upstream = str(proxy_cfg.PROXY_POOL_UPSTREAM_PROXY or "").strip()
    pool_proxies = _proxy_lines(proxy_cfg.PROXY_POOL)
    # 查活走住宅池（PLAN_CHECK 上游链路）；2FA/注册等其它协议流程走代理池本身。
    # 两组出口都可用预热缓存，按 exit_key 去重，避免同一出口重复预热烧流量。
    entries: list[tuple[str, str]] = []
    seen_keys: set[str] = set()
    for proxy_url, upstream in (
        [(p, plan_upstream) for p in plan_proxies]
        + [(p, pool_upstream) for p in pool_proxies]
    ):
        key = cf_warm.exit_key_for_proxy(proxy_url)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        entries.append((proxy_url, upstream))
    if args.exit_key:
        entries = [(p, u) for p, u in entries if cf_warm.exit_key_for_proxy(p) == args.exit_key]
    if args.limit > 0:
        entries = entries[: args.limit]
    if not entries:
        print("没有需要预热的出口（PLAN_CHECK_PROXY/PROXY_POOL 均为空）")
        return 1

    profile_dir_base = str(Path(tempfile.gettempdir()) / "turb-cf-warm-chrome")
    print(f"待预热出口 {len(entries)} 条；chrome profiles 目录={profile_dir_base}")

    ok = 0
    for index, (proxy_url, upstream) in enumerate(entries, 1):
        key = cf_warm.exit_key_for_proxy(proxy_url)
        print(f"[{index}/{len(entries)}] {key} 预热中（{_mask(proxy_url)}, 上游={upstream or '直连'}）...")
        try:
            data = warm_one_exit(proxy_url, upstream=upstream, headless=args.headless,
                                 profile_dir=str(Path(profile_dir_base) / f"exit-{key}"))
        except Exception as exc:
            print(f"[{index}/{len(entries)}] {key} 预热失败：{type(exc).__name__}: {str(exc)[:160]}")
            continue
        path = cf_warm.warmed_cache_path(proxy_url)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        status = data.get("http_status")
        got = [c.get("name") for c in data.get("cookies") or []] or [""]
        print(f"[{index}/{len(entries)}] {key} 完成：auth_status={status} exit={data.get('exit_ip')}/{data.get('colo')} cookies={got}")
        ok += 1 if status == 200 and got != [""] else 0
        time.sleep(1)

    print(f"预热完成：{ok}/{len(entries)} 条出口成功写入 cache/cf_warm/")
    if ok != len(entries):
        print("失败的出口不会注入 Cookie；查活时会在命中它们后记录 [CF预热] 缓存不可用。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
