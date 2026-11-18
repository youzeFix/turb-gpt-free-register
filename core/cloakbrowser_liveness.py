# -*- coding: utf-8 -*-
"""CloakBrowser 浏览器查活：真实指纹浏览器重新登录并刷新最新 AT。

CF 对 auth.openai.com 的 managed challenge 对真实浏览器无碍（自动求解），
因此浏览器查活：
- 不需要 core/cf_warm 预热 Cookie，也不需要住宅代理；
- 出口默认走 PROXY_POOL（本地 clash），查活流量不再消耗住宅流量；
- 登录入口必须走 chatgpt.com/auth/login（携带 NextAuth authorize 状态，
  登录完成后自动经 OAuth callback 建立 chatgpt.com 会话）；直接访问裸的
  auth.openai.com/log-in 无 authorize state，SPA 只会渲染
  「セッションが終了しました」页而没有登录表单。
- 页面操作复用 roxy_codex_oauth / roxy_registration 已维护的助手
  （邮箱提交 → 登录密码/MFA → 邮箱 OTP → 废号检测）。

返回结构与 core.account_liveness.check_account_liveness 一致，便于
live_check_service 统一落库与套餐查询。
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from core.cloakbrowser_driver import build_cloak_driver
from core.email_provider import wait_for_otp
from core.humanize import delay as human_delay
from core.openai_auth import AccountUnusableError, detect_account_unusable_text
from core.roxy_codex_oauth import (
    _click_if_present,
    _fill_login_password_if_present,
    _fill_mfa_challenge_if_present,
    _install_email_otp_validate_hook,
    _is_mfa_challenge_page,
    _wait_after_email_otp_submit,
    _wait_for_otp_input,
)
from core.roxy_registration import (
    _check_manual_stop,
    _clear_otp_inputs,
    _click_resend_email_otp,
    _fetch_chatgpt_session,
    _maybe_accept,
    _submit_email_step,
    _type_email_address,
    _type_otp,
)

logger = logging.getLogger(__name__)

_LOGIN_ENTRY_URL = "https://chatgpt.com/auth/login"


def _browser_fingerprint_text(session_proxy: str | None, opened) -> str:
    profile = getattr(opened, "fingerprint", None) or {}
    return " ".join(
        f"{k}={str(v)[:64]}" for k, v in (
            ("profile", getattr(opened, "profile_id", "")),
            ("proxy", session_proxy or "direct"),
            ("ua", profile.get("userAgent") or ""),
            ("locale", profile.get("locale") or ""),
            ("timezone", profile.get("timezone") or ""),
        ) if str(v or "").strip()
    )


_LOGIN_ERROR_MARKERS = (
    "登录失败", "登陆失败", "login failed", "log in failed",
    "something went wrong", "エラー", "出错", "try again later",
)

_CHALLENGE_MARKERS = (
    "just a moment", "challenge-platform", "确认您是真人",
    "verify you are human", "しばらくお待ちください",
)


def _challenge_state(driver) -> str:
    """返回当前页面标题+正文（质询检测用）；读取失败返回空串。"""
    try:
        return str(driver.execute_script(
            "return (document.title || '') + '\\n' + "
            "(document.body ? document.body.innerText.slice(0, 2000) : '');") or "")
    except Exception:
        return ""


def _looks_challenged(driver) -> bool:
    text = _challenge_state(driver)
    if not text:
        return False
    low = text.lower()
    return any(m in low or m in text for m in _CHALLENGE_MARKERS)


def _page_blank(driver) -> bool:
    """隐形质询形态：页面正文为空/极短且没有邮箱输入框。

    CF 有时把质询嵌进主文档（title 仍是 ChatGPT、无 iframe、无 marker 文本），
    显式特征检测会漏过；此时把“长时间空白无表单”当作质询信号处理。
    """
    try:
        state = driver.execute_script(r"""
            return {
              text: (document.body ? document.body.innerText : '').trim(),
              hasInput: !!document.querySelector('input'),
            };
        """) or {}
    except Exception:
        return False
    if not isinstance(state, dict):
        return False
    # 任何输入框（email/otp/tel 等）都说明页面已渲染真实表单，不是空白质询页。
    return len(str(state.get("text") or "")) < 30 and not state.get("hasInput")


def _click_main_document_checkbox(driver) -> str:
    """点击主文档里的复选框（非 iframe 形态的 Turnstile）。"""
    page = getattr(driver, "page", None)
    if page is None:
        return ""
    try:
        for selector in ("input[type='checkbox']", "[role='checkbox']", "label"):
            loc = page.locator(selector).first
            try:
                if loc.is_visible(timeout=800):
                    loc.click(timeout=1500)
                    return f"main-doc:{selector}"
            except Exception:
                continue
    except Exception:
        pass
    return ""


def _maybe_click_turnstile(driver) -> str:
    """尝试点击 CF 交互式质询里的 Turnstile 复选框；返回点击方式。"""
    page = getattr(driver, "page", None)
    if page is None:
        return ""
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


def _ensure_challenge_cleared(driver, email: str, *, max_wait: float = 240.0) -> bool:
    """等待 CF 质询解决：自动点击 Turnstile（iframe 与主文档形态），点不动时
    提示手动点击；空壳页（隐形质询）则连续确认后重新导航。返回是否出现过质询。
    """
    start = time.time()
    handled = False
    hinted = False
    last_click = 0.0
    blank_streak = 0
    while time.time() - start < max_wait:
        explicit = _looks_challenged(driver)
        blank = _page_blank(driver) if not explicit else False
        if not explicit and not blank:
            if handled:
                logger.info("[Cloak查活] CF 质询已通过（%s）：%s",
                            f"{time.time() - start:.0f}s", email)
            return handled
        handled = True
        elapsed = time.time() - start
        if elapsed > 20 and not hinted:
            logger.warning(
                "[Cloak查活] %s 遇到 CF 人机验证（%s）；自动点击复选框中，"
                "如 15 秒后仍停留验证页，请手动在弹出的浏览器窗口点击『确认您是真人』",
                email, "交互式质询页" if explicit else "空白隐形质询页")
            hinted = True
        if elapsed > 25 and time.time() - last_click > 8:
            clicked = _maybe_click_turnstile(driver) or _click_main_document_checkbox(driver)
            if clicked:
                last_click = time.time()
                logger.info("[Cloak查活] 已点击质询复选框（%s）：%s", clicked, email)
        if blank and not explicit:
            # 空壳页连续两次确认（间隔一个轮询周期）才算隐形质询，避免误判加载中。
            blank_streak += 1
            if blank_streak >= 2:
                logger.info("[Cloak查活] 页面持续空白，判定为隐形质询，重新导航登录入口")
                return handled
        else:
            blank_streak = 0
        time.sleep(3)
    return handled


def _read_page_error(driver) -> str:
    """读取登录页可见文本；用于快速发现"登录失败"类页面错误。"""
    try:
        return str(driver.execute_script(
            "return (document.body ? document.body.innerText : '');"
        ) or "")
    except Exception:
        return ""


def _page_login_error(driver) -> str:
    text = _read_page_error(driver)
    if not text:
        return ""
    lowered = text.lower()
    for marker in _LOGIN_ERROR_MARKERS:
        if marker in lowered or marker in text:
            return marker
    return ""


def _submit_login_email(driver, email: str, *, timeout: float = 60.0) -> None:
    """等待 chatgpt.com/auth/login 跳转到 auth 域并出现邮箱表单，然后提交。

    提交前如遇 CF 交互式质询会自动点击 Turnstile（并提示手动兜底）。
    空白隐形质询允许重新导航最多 3 次；超限说明当前出口/时段 CF 持续
    挂质询，放弃本账号（failed 可重试），避免无限循环占死 worker。
    """
    end = time.time() + timeout
    last_error = ""
    renav_count = 0
    MAX_RENAVS = 3
    while time.time() < end:
        _check_manual_stop()
        # 登录页被 Turnstile 拦截时先处理质询，再尝试填邮箱。
        try:
            if _ensure_challenge_cleared(driver, email, max_wait=240.0):
                if renav_count >= MAX_RENAVS:
                    raise RuntimeError(
                        f"登录入口持续被 CF 质询拦截（空白隐形质询），已重新导航 "
                        f"{renav_count} 次仍无表单，放弃本账号（可稍后重试）"
                    )
                # 质询会打断 NextAuth 重定向链；解决后必须重新导航登录入口，
                # 否则页面停在 chatgpt.com/auth/login 原地，永远没有邮箱表单。
                renav_count += 1
                logger.info("[Cloak查活] 质询已解决，重新打开登录入口（第 %s/%s 次）",
                            renav_count, MAX_RENAVS)
                driver.get(_LOGIN_ENTRY_URL)
                human_delay("navigate")
                _maybe_accept(driver)
                end = time.time() + timeout  # 质询解决后重新计时
        except RuntimeError:
            raise
        except Exception:
            logger.debug("[Cloak查活] 质询处理异常，继续尝试表单", exc_info=True)
        try:
            _type_email_address(driver, email, timeout=8)
            human_delay("form")
            _submit_email_step(driver, email)
            logger.info("[Cloak查活] 已填写并提交邮箱：%s", email)
            return
        except Exception as exc:
            last_error = str(exc)
            # 授权跳转/SPA 渲染需要时间；未超时前保持等待重试。
            time.sleep(1.5)
    raise RuntimeError(f"登录页未出现可用的邮箱输入框（entry={_LOGIN_ENTRY_URL}）: {last_error[:200]}")


def _submit_email_otp(driver, email: str, *, max_attempts: int = 3) -> None:
    """提交邮箱 OTP 并等待登录推进；含废号检测与重发重试。

    取码之前先等待 OTP 输入框出现（期间检测"登录失败"类页面错误），
    避免页面已报错时仍空等取码服务 3 分钟。
    """
    form_deadline = time.time() + 75
    while time.time() < form_deadline:
        _check_manual_stop()
        # OTP 页也可能被插入 Turnstile 质询，先处理再等输入框。
        try:
            if _ensure_challenge_cleared(driver, email, max_wait=240.0):
                form_deadline = time.time() + 75  # 质询解决后重新计时
        except Exception:
            logger.debug("[Cloak查活] 质询处理异常，继续等待表单", exc_info=True)
        page_error = _page_login_error(driver)
        if page_error:
            raise RuntimeError(
                f"登录页报错：{page_error}（提交邮箱后未进入验证码页，页面文本: "
                f"{_read_page_error(driver)[:200]}）"
            )
        from core.roxy_registration import _locate_otp_input
        if _locate_otp_input(driver):
            break
        time.sleep(1.5)
    else:
        raise RuntimeError("提交邮箱后 OTP 输入框一直未出现（也未检测到页面错误文本）")

    otp_after_ts = time.time()
    used_codes: set[str] = set()
    for attempt in range(1, max_attempts + 1):
        logger.info("[Cloak查活] 等待邮箱 OTP：%s（第 %s/%s 次）", email, attempt, max_attempts)
        code = str(wait_for_otp(email, after_ts=otp_after_ts) or "")
        if not code:
            raise RuntimeError("邮箱 OTP 等待超时")
        used_codes.add(code)
        logger.info("[Cloak查活] 邮箱 OTP 已收到：%s", code)
        _wait_for_otp_input(driver, timeout=30)
        _clear_otp_inputs(driver)
        _type_otp(driver, code)
        logger.info("[Cloak查活] 已填写邮箱 OTP")
        human_delay("otp_input")
        _install_email_otp_validate_hook(driver)
        _click_if_present(driver, [
            "button[type='submit']",
            "//button[contains(., 'Continue')]",
            "//button[contains(., '继续')]",
            "//button[contains(., 'Verify')]",
            "//button[contains(., '検証')]",
        ], timeout=8)
        outcome = _wait_after_email_otp_submit(driver, timeout=45)
        logger.info("[Cloak查活] 邮箱 OTP 提交后状态：%s", outcome)
        if _is_mfa_challenge_page(driver):
            _fill_mfa_challenge_if_present(driver, email, timeout=15)
            return
        if outcome == "accepted":
            return
        if str(outcome).startswith("deactivated:"):
            error_code = str(outcome).split(":", 1)[1] or "account_deactivated"
            raise AccountUnusableError(f"账号已废（{error_code}）", error_code=error_code)
        if attempt >= max_attempts:
            raise RuntimeError("邮箱验证码连续错误/过期，已达到最大重试次数")
        logger.warning("[Cloak查活] 验证码错误/过期或页面未跳转，点击重发后重试（%s/%s）", attempt, max_attempts)
        try:
            _click_resend_email_otp(driver)
        except Exception as exc:
            logger.warning("[Cloak查活] 重发邮件失败，继续等待最新验证码：%s", str(exc)[:120])
        otp_after_ts = time.time()
        time.sleep(1)


def run_cloak_liveness(
    email: str,
    proxy: str | None = None,
    *,
    on_authenticated: Callable[[dict, object], dict] | None = None,
) -> dict:
    """用 CloakBrowser 重新登录账号并拉取最新 accessToken。

    返回与 check_account_liveness 相同的结构；``on_authenticated(result, driver)``
    与协议查活一致：先落库新 AT，再复用同一浏览器会话查套餐。
    """
    email = str(email or "").strip()
    if not email:
        raise ValueError("email 不能为空")

    checked_at = datetime.now().isoformat(timespec="seconds")
    driver = None
    try:
        driver, opened = build_cloak_driver(proxy=proxy)
        # 查活不安装 BrowserDataSaver：省流量拦截会把 CF 质询页渲染成空壳
        # （challenge 脚本被拦，质询检测与自动点击全部失效）。查活流量走
        # clash 免费，省流量在这里没有收益，只有副作用。

        logger.info(
            "[Cloak查活] 开始：%s profile=%s proxy=%s",
            email, getattr(opened, "profile_id", "-"), proxy or "direct/配置",
        )
        driver.get(_LOGIN_ENTRY_URL)
        human_delay("navigate")
        _maybe_accept(driver)

        _submit_login_email(driver, email)
        password_result = _fill_login_password_if_present(driver, email, timeout=30)
        if password_result == "next_step":
            logger.info("[Cloak查活] 账号已用密码完成登录：%s", email)
        elif password_result == "email_otp":
            logger.info("[Cloak查活] 密码登录后仍需邮箱验证")
            _submit_email_otp(driver, email)
        else:
            # 无密码账号：提交邮箱后直接进入邮箱验证码页。
            logger.info("[Cloak查活] 账号无注册密码，走邮箱 OTP 登录")
            _submit_email_otp(driver, email)
        human_delay("post_auth")

        session_info = _fetch_chatgpt_session(driver, timeout=90)
        access_token = str((session_info or {}).get("accessToken") or "")
        if not access_token:
            raise RuntimeError("浏览器登录后未拿到 accessToken")

        user = session_info.get("user") or {}
        account = session_info.get("account") or {}
        logger.info(
            "[Cloak查活] 正常：%s user_id=%s plan=%s",
            email, user.get("id"), account.get("planType"),
        )
        result = {
            "ok": True,
            "status": "live",
            "checked_at": checked_at,
            "access_token": access_token,
            "session": session_info,
            "proxy_used": proxy or None,
            "fingerprint_text": _browser_fingerprint_text(proxy, opened),
            "driver": "cloak",
        }
        if on_authenticated is not None:
            return on_authenticated(result, driver)
        return result

    except AccountUnusableError as exc:
        code = getattr(exc, "error_code", "") or detect_account_unusable_text(str(exc)) or "account_deactivated"
        logger.warning("[Cloak查活] 已废号：%s %s", email, code)
        return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code, "driver": "cloak"}
    except Exception as exc:
        code = detect_account_unusable_text(str(exc))
        if code:
            logger.warning("[Cloak查活] 已废号：%s %s", email, code)
            return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code, "driver": "cloak"}
        logger.warning("[Cloak查活] 失败：%s %s: %s", email, type(exc).__name__, str(exc)[:260])
        return {"ok": False, "status": "failed", "checked_at": checked_at,
                "error": f"{type(exc).__name__}: {str(exc)[:500]}", "driver": "cloak"}
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                logger.debug("[Cloak查活] 浏览器关闭异常", exc_info=True)
