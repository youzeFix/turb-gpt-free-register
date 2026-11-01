# -*- coding: utf-8 -*-
"""查活 CF 挑战预热：真实 Chrome 预取 auth.openai.com 的 __cf_bm，供协议会话注入。

背景：auth.openai.com 在风控升级期间会对没有 __cf_bm 的自动化客户端下发
Cloudflare managed challenge（cf-mitigated: challenge），纯协议客户端无法执行
JS 因此直接 403。真实有头 Chrome 访问一次 auth 域即可取到该 Cookie，且
__cf_bm 与出口 IP 绑定、对 UA 小版本差异不敏感（实测 chrome146 的 UA 也能复用）。

本模块只负责两件事：
1. 读取/校验 `tools/cf_cookie_warm.py` 预热的 Cookie 缓存（cache/cf_warm/<出口>.json）；
2. 把仍然新鲜的 __cf_bm 注入协议 BrowserSession 的 Cookie Jar。
"""
from __future__ import annotations

import io
import json
import logging
import re
import sys
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)

_WARM_DIR = Path(__file__).resolve().parent.parent / "cache" / "cf_warm"
# __cf_bm 官方有效期约 30 分钟；留 5 分钟余量给任务执行时间。
_MAX_AGE_SECONDS = 25 * 60
# 只注入 CF 侧鉴权 Cookie。oai-did 由 BrowserSession 统一生成，注入会与
# 会话设备 ID 不一致，属于可观测指纹冲突。
_INJECTABLE_COOKIE_NAMES = ("__cf_bm", "cf_clearance")
_SID_PATTERN = re.compile(r"sid_(\d+)")


def exit_key_for_proxy(proxy_url: str | None) -> str:
    """从代理 URL 提取出口键：住宅 sid 优先，回退 host:port。"""
    value = str(proxy_url or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value if "://" in value else f"http://{value}")
        username = unquote(parsed.username or "")
        match = _SID_PATTERN.search(username)
        if match:
            return f"sid_{match.group(1)}"
        host = parsed.hostname or ""
        port = parsed.port
        if port:
            return f"{host}:{port}"
        return host or value[:64]
    except (ValueError, TypeError):
        return value[:64]


def warmed_cache_path(proxy_url: str | None) -> Path:
    # exit_key 可能含 ":"（如 host:port），Windows 文件名不合法，这里统一 sanitize。
    # 真实 exit_key 仍保存在 JSON 里用于匹配校验。
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", exit_key_for_proxy(proxy_url)) or "exit"
    return _WARM_DIR / f"{safe}.json"


def load_warmed_exit(proxy_url: str | None, *, max_age_seconds: int = _MAX_AGE_SECONDS) -> dict | None:
    """读取一个出口的预热记录；过期/出口不符/格式损坏返回 None。"""
    path = warmed_cache_path(proxy_url)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        exit_key = exit_key_for_proxy(proxy_url)
        warmed_key = str(data.get("exit_key") or "")
        warmed_at = float(data.get("warmed_at") or 0)
        cookies = data.get("cookies") if isinstance(data.get("cookies"), list) else []
        usable = [
            c for c in cookies
            if isinstance(c, dict)
            and str(c.get("name") or "") in _INJECTABLE_COOKIE_NAMES
            and str(c.get("value") or "")
        ]
        if warmed_key != exit_key or not warmed_at or not usable:
            logger.info("[CF预热] 缓存不可用：%s", path.name)
            return None
        age = time.time() - warmed_at
        if age > max_age_seconds:
            return None
        data["usable_cookies"] = usable
        data["age_seconds"] = age
        return data
    except (OSError, ValueError, TypeError):
        logger.warning("[CF预热] 缓存读取失败：%s", path.name, exc_info=True)
        return None


def _short_age(age_seconds: float) -> str:
    return f"{int(age_seconds)}s"


def _platform_fields_from_ua(ua: str) -> dict:
    """从预热浏览器的 UA 反推一致的 UA/CH 平台画像。

    cf_clearance 与预热浏览器的 UA 精确绑定；只注入 Cookie 而 UA 仍是
    impersonate 档（旧版本/macOS）时 CF 会因 UA 不匹配重新质询。
    """
    fields: dict[str, str] = {}
    if "Windows NT" in ua:
        fields.update(
            browser_os="Windows", navigator_platform="Win32",
            user_agent_data_platform="Windows", sec_ch_ua_platform='"Windows"',
        )
    elif "Macintosh" in ua:
        fields.update(
            browser_os="macOS", navigator_platform="MacIntel",
            user_agent_data_platform="macOS", sec_ch_ua_platform='"macOS"',
        )
    elif "X11" in ua or "Linux" in ua:
        fields.update(
            browser_os="Linux", navigator_platform="Linux x86_64",
            user_agent_data_platform="Linux", sec_ch_ua_platform='"Linux"',
        )
    else:
        return {}

    major_match = re.search(r"Chrome?/(\d+)", ua) or re.search(r"Edg/(\d+)", ua)
    if not major_match:
        return {}
    major = major_match.group(1)
    if "Edg/" in ua:
        brand = "Microsoft Edge"
    elif "Chrome/" in ua:
        brand = "Google Chrome"
    else:
        return {}
    full_version = f"{major}.0.0.0"
    fields.update(
        browser_family="chrome",
        send_client_hints=True,
        navigator_vendor="Google Inc.",
        chrome_major=major,
        chrome_full_version=full_version,
        sec_ch_ua=f'"Chromium";v="{major}", "Not-A.Brand";v="24", "{brand}";v="{major}"',
        sec_ch_ua_full_version_list=(
            f'"Chromium";v="{full_version}", "Not-A.Brand";v="24.0.0.0", "{brand}";v="{full_version}"'
        ),
        user_agent=ua,
        safari_version="", safari_webkit_version="",
    )
    return fields


def apply_warmed_cf_cookies(session, warmed: dict | None) -> bool:
    """注入预热 Cookie，并把会话画像同步为预热浏览器的 UA/平台。

    cf_clearance 绑定预热浏览器的精确 UA；只注入 Cookie 而 UA 仍是
    impersonate 档时 CF 会因 UA 不匹配重新质询。BrowserSession 的
    browser_profile 每次请求动态读取，改 dict 即生效。
    注入失败必须静默，不能阻断查活/2FA主流程。
    """
    if not warmed:
        return False
    usable = warmed.get("usable_cookies") or []
    if not usable:
        return False
    # BrowserSession 的 curl_cffi/wreq 客户端会话位于 .session.cookies；
    # 兼容直接传入底层 HTTP 会话对象。
    jar = getattr(session, "cookies", None)
    if jar is None:
        inner = getattr(session, "session", None)
        jar = getattr(inner, "cookies", None) if inner is not None else None
    if jar is None:
        logger.warning("[CF预热] 会话对象上未找到 Cookie Jar，跳过注入")
        return False
    applied = 0
    for cookie in usable:
        try:
            jar.set(
                str(cookie["name"]),
                str(cookie["value"]),
                domain=str(cookie.get("domain") or ".auth.openai.com"),
                path=str(cookie.get("path") or "/"),
            )
            applied += 1
        except Exception:
            logger.warning("[CF预热] Cookie 注入失败：%s", cookie.get("name"), exc_info=True)
    # 画像同步：BrowserSession.profile 每次请求动态读取，直接改 dict 即生效。
    warmed_ua = str(warmed.get("ua") or "").strip()
    if warmed_ua:
        try:
            session.browser_profile.update(_platform_fields_from_ua(warmed_ua))
        except Exception:
            logger.warning("[CF预热] 浏览器画像同步失败", exc_info=True)
    if applied:
        logger.info(
            "[查活] 已注入预热 CF Cookie：%s（age=%s, 来源=cache/cf_warm）",
            warmed.get("exit_key"),
            _short_age(float(warmed.get("age_seconds") or 0)),
        )
    return bool(applied)


def main() -> int:
    """CLI 便捷入口：python -m core.cf_warm <代理URL> 查看该出口的预热状态。"""
    import io as _io

    sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    for arg in sys.argv[1:]:
        key = exit_key_for_proxy(arg)
        data = load_warmed_exit(arg)
        if not data:
            print(f"{key}: 无有效预热缓存（请运行 tools/cf_cookie_warm.py）")
            continue
        print(
            f"{key}: exit_ip={data.get('exit_ip')} "
            f"age={_short_age(data.get('age_seconds') or 0)} "
            f"cookies={[c.get('name') for c in data.get('usable_cookies') or []]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
