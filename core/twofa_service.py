# -*- coding: utf-8 -*-
"""账号 2FA/TOTP 后台设置队列。"""
from __future__ import annotations

import logging
import random
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from config import email as _email_cfg
from config import twofa as _twofa_cfg
from core import db
from core.account_export import setup_2fa
from core.session import BrowserSession, close_browser_session
from core.proxy_utils import mask_proxy_url

logger = logging.getLogger(__name__)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(_twofa_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_MAX_WORKERS = 16
_WORKERS = _int_setting("TWOFA_WORKERS", 4, 1, _MAX_WORKERS)
_QUEUE_LIMIT = _int_setting("TWOFA_QUEUE_LIMIT", 200, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="twofa")
_RUNNING: set[int] = set()
_OUTSTANDING = 0
_LOCK = threading.Condition()
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"


def apply_settings() -> dict:
    """Apply freshly loaded config values to the live queue service."""
    global _WORKERS, _QUEUE_LIMIT
    workers = _int_setting("TWOFA_WORKERS", 4, 1, _MAX_WORKERS)
    queue_limit = _int_setting("TWOFA_QUEUE_LIMIT", 200, workers, 5000)
    with _LOCK:
        _WORKERS = workers
        _QUEUE_LIMIT = queue_limit
        _LOCK.notify_all()
        return {
            "workers": _WORKERS,
            "queue_limit": _QUEUE_LIMIT,
            "running": len(_RUNNING),
            "outstanding": _OUTSTANDING,
        }


def _release_outstanding() -> None:
    global _OUTSTANDING
    with _LOCK:
        _OUTSTANDING = max(0, _OUTSTANDING - 1)
        _LOCK.notify_all()


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"twofa-{safe}.log"


def _normalize_proxy(proxy: str | None) -> str | None:
    """
    2FA 入口只接受真实代理地址。

    注册流程里有些 `proxy_used` 字段保存的是环境标签，例如 `skyvern:jp`、
    `browser_use:jp`，这类不是 curl_cffi 可用代理，会导致 Unsupported proxy syntax。
    """
    text = str(proxy or "").strip()
    if not text:
        return None
    low = text.lower()
    if low.startswith(("http://", "https://", "socks5://", "socks5h://", "socks4://", "socks4a://")):
        return text
    return None


def _resolve_twofa_proxy(proxy: str | None):
    """按 TWOFA_PROXY_MODE 解析传输代理。

    返回 (传输代理, 本地链式中继或 None, 模式标签, 预热目标代理)。
    预热目标代理是真实出口地址（CF 预热 Cookie 按出口绑定），plan_check
    模式下链式中继的本地回环地址不能用于匹配预热缓存。
    """
    mode = str(getattr(_twofa_cfg, "TWOFA_PROXY_MODE", "saved") or "saved").strip().lower()
    if mode not in {"saved", "pool", "plan_check"}:
        raise ValueError(f"TWOFA_PROXY_MODE={mode!r} 无效，可选 saved / pool / plan_check")
    if mode == "pool":
        from core.proxy_chain import open_proxy_pool_proxy
        transport, relay = open_proxy_pool_proxy(None)
        return transport or None, relay, "pool", None
    if mode == "plan_check":
        from config import proxy as proxy_cfg
        from core.chatgpt_plan import (
            _proxy_lines,
            open_plan_check_proxy,
            resolve_plan_check_route,
        )
        values = [
            str(item).strip()
            for item in _proxy_lines(getattr(proxy_cfg, "PLAN_CHECK_PROXY", ""))
            if str(item).strip()
        ]
        if not values:
            # 未配置套餐/查活住宅池时回退代理池，2FA 不能因此完全不可用。
            from core.proxy_chain import open_proxy_pool_proxy
            transport, relay = open_proxy_pool_proxy(None)
            return transport or None, relay, "pool_fallback", None
        target = random.choice(values)
        timeout = getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0)
        route = resolve_plan_check_route(explicit_proxy=target)
        # 显式覆盖时 resolve_plan_check_route 不带上游；与查活 _live_proxy_route
        # 保持一致，住宅出口必须经 PLAN_CHECK_UPSTREAM_PROXY 上游链路（部分
        # 住宅服务商拒绝中国大陆出口直连）。
        upstream = str(getattr(proxy_cfg, "PLAN_CHECK_UPSTREAM_PROXY", "") or "").strip()
        if upstream:
            route["upstream_proxy"] = upstream
        transport, relay = open_plan_check_proxy(route, target, timeout=timeout)
        return transport, relay, "plan_check", target
    target = _normalize_proxy(proxy)
    if not target:
        # 没有可复用的目标代理时交给 BrowserSession 从代理池选择；
        # BrowserSession 会自行管理代理池链式中继生命周期。
        from core.proxy_chain import open_proxy_pool_proxy
        transport, relay = open_proxy_pool_proxy(None)
        return transport or None, relay, "pool", None
    from core.proxy_chain import open_proxy_pool_proxy

    transport, relay = open_proxy_pool_proxy(target)
    return transport, relay, "saved", target


def is_running(acc_id: int) -> bool:
    with _LOCK:
        return int(acc_id) in _RUNNING


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {line}\n")


def _run_twofa(
    *, account_id: int, email: str, access_token: str, proxy: str | None,
    trigger: str,
) -> dict:
    global _OUTSTANDING
    fh: logging.FileHandler | None = None
    session: BrowserSession | None = None
    relay = None
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    try:
        with _LOCK:
            while len(_RUNNING) >= _WORKERS:
                _LOCK.wait()
            _RUNNING.add(int(account_id))
        if not db.mark_account_totp_setup_running(account_id):
            return {"ok": False, "status": "failed", "error": "账号已删除或 2FA 状态已被重置"}
        log_file = log_path(email)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("", encoding="utf-8")
        fh = logging.FileHandler(str(log_path(email)), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)
        logger.info("[2FA] 开始后台设置：email=%s trigger=%s", email, trigger)
        real_proxy, relay, proxy_source, warm_target = _resolve_twofa_proxy(proxy)
        identity = email.strip().lower()
        session = BrowserSession(proxy=real_proxy, fingerprint_seed=f"account:{identity}")
        # auth.openai.com 全站质询期间，协议会话必须携带真实 Chrome 预热的
        # __cf_bm（与出口 IP 绑定）；预热目标用真实出口地址：
        #   saved/pool 模式 = 会话目标代理本身；
        #   plan_check 模式链式中继只给本地回环 URL，按选中的住宅出口匹配缓存。
        from core.cf_warm import load_warmed_exit, apply_warmed_cf_cookies
        warmed = load_warmed_exit(warm_target or getattr(session, "proxy_target", None) or session.proxy)
        if warmed is not None:
            applied = apply_warmed_cf_cookies(session, warmed)
            if applied:
                _append_log(email, f"[2FA] 已注入预热 CF Cookie：{warmed.get('exit_key')}（age={int(warmed.get('age_seconds') or 0)}s）")
        else:
            _append_log(email, "[2FA] 该出口缺少新鲜 CF 预热缓存（>25分钟或未预热）；如 authorize 403 可执行 tools/cf_cookie_warm.py 预热")
        target_label = mask_proxy_url(getattr(session, "proxy_target", None) or session.proxy or "direct") or "direct"
        transport_label = mask_proxy_url(session.proxy or "direct") or "direct"
        _append_log(
            email,
            f"[2FA] 会话创建完成：target={target_label} transport={transport_label} "
            f"source={proxy_source} device_id={session.device_id}",
        )
        _append_log(email, f"[2FA] 指纹摘要：{session.fingerprint_summary_text()}")
        secret = setup_2fa(session, email, access_token=access_token)
        db.update_account_totp_secret(
            account_id,
            {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA 设置完成"},
        )
        _append_log(email, f"[2FA] 完成：secret={secret[:4]}...{secret[-4:]}")
        logger.info("[2FA] 完成：email=%s secret=%s...%s", email, secret[:4], secret[-4:])
        return {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA 设置完成"}
    except Exception as exc:
        result = {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
        try:
            db.update_account_totp_secret(account_id, result)
        except Exception:
            logger.exception("[2FA] 写回失败状态失败: account_id=%s", account_id)
        try:
            _append_log(email, f"[2FA] 失败：{result['error']}")
        except Exception:
            pass
        logger.exception("[2FA] 后台异常: %s", email)
        return result
    finally:
        if session is not None:
            try:
                close_browser_session(session)
            except Exception:
                pass
        if relay is not None:
            try:
                relay.close()
            except Exception:
                pass
        if fh is not None:
            try:
                root_logger.removeHandler(fh)
                fh.close()
            except Exception:
                pass
        with _LOCK:
            _RUNNING.discard(int(account_id))
            _OUTSTANDING = max(0, _OUTSTANDING - 1)
            _LOCK.notify_all()


def queue_settings() -> dict:
    apply_settings()
    with _LOCK:
        return {
            "workers": _WORKERS,
            "queue_limit": _QUEUE_LIMIT,
            "running": len(_RUNNING),
            "outstanding": _OUTSTANDING,
        }


def enqueue_account_totp_setup(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str = "manual",
    proxy: str | None = None,
) -> dict:
    global _OUTSTANDING
    apply_settings()
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email 为空"}
    if not access_token:
        return {"accepted": False, "busy": False, "error": "缺少 access_token"}
    if not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
        return {"accepted": False, "busy": False, "error": "启用 2FA 需要先开启 USE_EMAIL_SERVICE 自动收取邮箱验证码"}
    with _LOCK:
        if _OUTSTANDING >= _QUEUE_LIMIT:
            return {"accepted": False, "busy": False, "queue_full": True, "error": "2FA 队列已满，请稍后重试"}
        _OUTSTANDING += 1
    if not db.claim_account_totp_setup(acc_id=account_id, trigger=trigger):
        _release_outstanding()
        return {"accepted": False, "busy": True, "error": "该账号正在设置 2FA"}

    _append_log(email, f"[2FA] 已入队 account_id={account_id} trigger={trigger}", clear=True)
    try:
        future = _EXECUTOR.submit(
            _run_twofa,
            account_id=account_id,
            email=email,
            access_token=access_token,
            proxy=proxy,
            trigger=str(trigger or "manual"),
        )
        return {"accepted": True, "busy": False, "future": future, "log_path": str(log_path(email))}
    except Exception as exc:
        _release_outstanding()
        db.update_account_totp_secret(account_id, {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        return {"accepted": False, "busy": False, "error": f"{type(exc).__name__}: {exc}"}
