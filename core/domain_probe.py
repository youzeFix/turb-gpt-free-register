# -*- coding: utf-8 -*-
"""
邮箱域名体检：在花钱买邮箱之前，免费判断某个域名会不会被 OpenAI 拒绝。

背景
----
OpenAI 的注册链路有**两个互相独立**的拒绝点：

1. 邮箱提交  -> 页面跳 ``/auth/error``                    （地址级拒绝）
2. 建号提交  -> 页面出现 "Failed to create account"       （域名级拒绝）

只探第 1 步会漏掉域名级拒绝：实测 ``*.onmicrosoft.com`` 在第 1 步是放行的
（能进验证码页、能进密码页），直到第 2 步建号才被拒。

为什么不需要真实邮箱
--------------------
建号接口 ``POST /api/accounts/user/register`` 只收 ``{username, password}``，
验证码是在建号成功之后才校验的。所以用���个探测邮箱就能走完整个建号流程：

- 不买邮箱、不花钱
- 不需要真收件箱
- 唯一副作用：域名被接受时，会真的在 OpenAI 建出一个"半成品账号"
  （已建号但没填验证码激活），对探测地址而言不可用，可忽略。

注意
----
体检必须在域名**已经配好 Email Routing（MX 生效）之后**再跑，否则 OpenAI
因为查不到 MX 可能给出误判。只想验证"OpenAI 是否按域名拦截"时，
提前跑也能给出参考结论。

**结论是时效性的，要当成"体检当天此刻"的状态，而不是域名的一次性认证。**
实测：``outlook.com`` 在 00:19 还能走通邮箱提交+建号，40 分钟后的复测就在
邮箱提交那一步被拒了。同一个域名会随着当天注册量累积、IP 信誉变化而翻转。

**"邮箱提交步被拒"必须重试。**
OpenAI 的 ``/auth/error?error=undefined`` 页面，既可能是真正的域名拦截，
也可能是风控/Cloudflare 挑战导致的偶发失败，两者页面表现完全一样。
实测同一个探测地址（``o60xpa0pvfsx@outlook.com``）隔半小时测，一次被拒
一次通过。所以本模块对"邮箱提交步被拒"会自动重试（默认 3 次），几次都拒
才判定为域名被拒；"建号步被拒"是服务端明确返回的结论，不重试。

所以正确用法是：**每批开跑前先体检一次**，只跑判为可用的域名；一个域名
一次只跑 1~2 个账号，被拒立刻换下一个域名 + 换 IP。
"""
from __future__ import annotations

import logging
import random
import re
import string
import time
from dataclasses import asdict, dataclass

logger = logging.getLogger(__name__)

# 判定结论
VERDICT_ACCEPTED = "accepted"          # 域名可用
VERDICT_REJECTED = "rejected"          # 域名被 OpenAI 拒绝
VERDICT_INCONCLUSIVE = "inconclusive"  # 网络/页面问题，无法判定

# 卡住的阶段
STAGE_INPUT = "input"                # 连邮箱输入框都没找到
STAGE_EMAIL_SUBMIT = "email_submit"  # 邮箱提交这一步
STAGE_REGISTER = "register"          # 建号提交这一步
STAGE_EXCEPTION = "exception"

LOGIN_URL = "https://chatgpt.com/auth/login"

# OpenAI 建号失败时页面上的固定文案（英文 / 日文 / 中文）
_CREATE_ACCOUNT_FAILED = (
    "failed to create account",
    "create account. please try again",
    "アカウントを作成",
    "无法创建账户",
    "無法建立帳戶",
)

# 密码页的原生 setter 填值，绕开 React 受控组件
_FILL_PASSWORD_JS = r"""
const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
  && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
const input = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="new-password"]')]
  .find(el => visible(el) && !el.disabled && !el.readOnly);
if (!input) return false;
const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
setter.call(input, arguments[0]);
input.dispatchEvent(new Event('input', {bubbles: true}));
input.dispatchEvent(new Event('change', {bubbles: true}));
input.focus();
return true;
"""

# 挑 Continue 按钮并点击，评分逻辑与注册主流程保持一致
_CLICK_SUBMIT_JS = r"""
const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
  && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
const enabled = el => !!el && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
const input = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="new-password"]')]
  .find(el => visible(el));
const form = input ? input.closest('form') : document.querySelector('form');
const scope = form || document;
const candidates = [...scope.querySelectorAll('button,input[type="submit"],[role="button"]')]
  .filter(el => visible(el) && enabled(el));
const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
const scored = candidates.map((el, idx) => {
  const attrs = [el.getAttribute('type'), el.getAttribute('data-dd-action-name'),
    el.getAttribute('data-login-web-auth-control'), el.getAttribute('aria-label'),
    el.getAttribute('name'), el.getAttribute('value'), el.textContent].join(' ').toLowerCase();
  const text = norm(el.textContent || el.getAttribute('value') || '');
  let score = 0;
  if ((el.getAttribute('type') || '').toLowerCase() === 'submit') score += 80;
  if ((el.getAttribute('data-dd-action-name') || '').toLowerCase() === 'continue') score += 90;
  if (/continue|next|submit|create|続行/.test(attrs) || /continue|next|submit|create|続行/.test(text)) score += 50;
  return {el, idx, score};
}).sort((a, b) => b.score - a.score || a.idx - b.idx);
const target = scored[0] && scored[0].el;
if (!target) return 'missing_submit';
target.scrollIntoView({block: 'center'});
target.click();
return 'clicked';
"""


@dataclass
class ProbeResult:
    """单个域名的体检结论。"""

    domain: str
    verdict: str
    stage: str
    url: str = ""
    detail: str = ""
    elapsed: float = 0.0
    probe_email: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_domain(domain: str) -> str:
    """把用户填的域名规整成纯域名（去协议头、去路径、去邮箱前缀、转小写）。"""
    text = str(domain or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", text)
    text = text.split("/")[0].split("?")[0].split("#")[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    return text.strip().strip(".")


def is_create_account_failure(text: str) -> bool:
    """判断页面报错是不是"建号被拒"的固定文案。"""
    low = str(text or "").lower()
    return any(keyword in low for keyword in _CREATE_ACCOUNT_FAILED)


def _random_probe_email(domain: str, local_part: str | None = None) -> str:
    """生成探测地址。

    local-part 用纯随机字母数字，**不要**加 "probe"/"test" 之类前缀：
    OpenAI 对明显是探测的地址可能直接按地址级拦截，那样测出来的
    "被拒"就不是域名本身的问题了，结论会失真。

    长度默认 8 位，与常见公池地址（njbf8a01 / emp36g30y4 这类）一致。
    长度太长的随机串（例如 12 位以上）实测更容易被 OpenAI 按"疑似伪造
    地址"拦在邮箱提交那一步，从而把可用域名误判成被拒。
    """
    if local_part:
        local = str(local_part).strip().lower()
    else:
        local = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{local}@{domain}"


def _random_password() -> str:
    body = "".join(random.choices(string.ascii_letters + string.digits, k=10))
    return f"{body}!Aa1"


def _probe_with_driver(driver, domain: str, *, check_register: bool, local_part: str | None = None) -> ProbeResult:
    """在已打开的浏览器上体检一个域名。"""
    from core.roxy_registration import (
        _click_continue_with_password_if_present,
        _is_email_verification_page,
        _is_signup_password_page,
        _password_page_state,
        _submit_email_and_wait_next,
        _wait_for_email_input,
    )

    started = time.time()
    email = _random_probe_email(domain, local_part)

    def _elapsed() -> float:
        return round(time.time() - started, 1)

    def _current_url() -> str:
        return str(getattr(driver, "current_url", "") or "")

    # ---------- 打开登录页 ----------
    driver.get(LOGIN_URL)
    if not _wait_for_email_input(driver, timeout=45):
        return ProbeResult(
            domain=domain,
            verdict=VERDICT_INCONCLUSIVE,
            stage=STAGE_INPUT,
            url=_current_url(),
            detail="未找到邮箱输入框（页面未加载出来，或被风控挡在门外）",
            elapsed=_elapsed(),
            probe_email=email,
        )

    # ---------- 阶段 1：提交邮箱 ----------
    submit_error = ""
    state = ""
    try:
        state = _submit_email_and_wait_next(driver, email, attempts=2)
    except Exception as exc:  # 被拒时这里会抛"未进入密码页/验证码页"
        submit_error = f"{type(exc).__name__}: {str(exc)[:160]}"

    url = _current_url()
    # 提交后可能迟到地跳 error 页，继续观察
    deadline = time.time() + 40
    while time.time() < deadline:
        current = _current_url()
        if "/auth/error" in current:
            url = current
            break
        if _is_email_verification_page(driver):
            url = current
            break
        time.sleep(1.0)

    if "/auth/error" in url:
        return ProbeResult(
            domain=domain,
            verdict=VERDICT_REJECTED,
            stage=STAGE_EMAIL_SUBMIT,
            url=url,
            detail="OpenAI 在邮箱提交这一步就拒绝了这个域名（地址级拦截）",
            elapsed=_elapsed(),
            probe_email=email,
        )

    if not check_register:
        accepted = state in ("otp", "password") or "verification" in url
        return ProbeResult(
            domain=domain,
            verdict=VERDICT_ACCEPTED if accepted else VERDICT_INCONCLUSIVE,
            stage=STAGE_EMAIL_SUBMIT,
            url=url,
            detail=(
                "邮箱提交通过（未检查建号步骤）"
                if accepted
                else (submit_error or "邮箱提交后状态未知")
            ),
            elapsed=_elapsed(),
            probe_email=email,
        )

    # ---------- 阶段 2：走到密码页并提交建号 ----------
    clicked: dict = {}
    for _ in range(15):
        clicked = _click_continue_with_password_if_present(driver)
        if clicked.get("ok"):
            break
        time.sleep(1.0)
    if not clicked.get("ok"):
        return ProbeResult(
            domain=domain,
            verdict=VERDICT_INCONCLUSIVE,
            stage=STAGE_REGISTER,
            url=url,
            detail="验证码页上找不到「使用密码继续」入口，无法验证建号步骤",
            elapsed=_elapsed(),
            probe_email=email,
        )

    for _ in range(30):
        if _is_signup_password_page(driver):
            break
        time.sleep(1.0)
    if not _is_signup_password_page(driver):
        return ProbeResult(
            domain=domain,
            verdict=VERDICT_INCONCLUSIVE,
            stage=STAGE_REGISTER,
            url=_current_url(),
            detail="没有进入注册密码页",
            elapsed=_elapsed(),
            probe_email=email,
        )

    try:
        filled = driver.execute_script(_FILL_PASSWORD_JS, _random_password())
    except Exception as exc:
        return ProbeResult(
            domain=domain,
            verdict=VERDICT_INCONCLUSIVE,
            stage=STAGE_REGISTER,
            url=_current_url(),
            detail=f"密码输入框操作失败: {type(exc).__name__}",
            elapsed=_elapsed(),
            probe_email=email,
        )
    if not filled:
        return ProbeResult(
            domain=domain,
            verdict=VERDICT_INCONCLUSIVE,
            stage=STAGE_REGISTER,
            url=_current_url(),
            detail="密码输入框不可用",
            elapsed=_elapsed(),
            probe_email=email,
        )

    time.sleep(2.0)
    try:
        driver.execute_script(_CLICK_SUBMIT_JS)
    except Exception as exc:
        return ProbeResult(
            domain=domain,
            verdict=VERDICT_INCONCLUSIVE,
            stage=STAGE_REGISTER,
            url=_current_url(),
            detail=f"提交密码失败: {type(exc).__name__}",
            elapsed=_elapsed(),
            probe_email=email,
        )

    deadline = time.time() + 45
    while time.time() < deadline:
        page_state = _password_page_state(driver)
        errors = page_state.get("errors") or []
        text = "；".join(str(item) for item in errors[:3])
        if text and is_create_account_failure(text):
            return ProbeResult(
                domain=domain,
                verdict=VERDICT_REJECTED,
                stage=STAGE_REGISTER,
                url=str(page_state.get("url") or ""),
                detail="建号被拒：" + text[:180],
                elapsed=_elapsed(),
                probe_email=email,
            )
        if text:
            return ProbeResult(
                domain=domain,
                verdict=VERDICT_INCONCLUSIVE,
                stage=STAGE_REGISTER,
                url=str(page_state.get("url") or ""),
                detail="密码页出现其它报错：" + text[:180],
                elapsed=_elapsed(),
                probe_email=email,
            )
        if not _is_signup_password_page(driver):
            return ProbeResult(
                domain=domain,
                verdict=VERDICT_ACCEPTED,
                stage=STAGE_REGISTER,
                url=_current_url(),
                detail="建号接口通过，这个域名可用",
                elapsed=_elapsed(),
                probe_email=email,
            )
        time.sleep(1.0)

    return ProbeResult(
        domain=domain,
        verdict=VERDICT_INCONCLUSIVE,
        stage=STAGE_REGISTER,
        url=_current_url(),
        detail="建号提交后没有明确结果",
        elapsed=_elapsed(),
        probe_email=email,
    )


def _probe_with_retry(
    driver,
    domain: str,
    *,
    check_register: bool,
    local_part: str | None = None,
    attempts: int = 3,
) -> ProbeResult:
    """体检一个域名；邮箱提交步出现"拒绝"时重试，避开偶发失败。

    OpenAI 的 `/auth/error?error=undefined` 这一个页面，既可能是真正的域名
    拦截，也可能是风控/Cloudflare 挑战导致的偶发失败，两者页面表现完全
    一样。实测同一个地址隔半小时测，一次拒绝一次通过。

    所以「邮箱提交步被拒」必须重试几次都拒，才能判定为域名被拒；
    而「建号步被拒」是服务端明确返回的结论，不需要重试。
    """
    last: ProbeResult | None = None
    for index in range(max(1, attempts)):
        result = _probe_with_driver(
            driver, domain, check_register=check_register, local_part=local_part
        )
        if result.verdict != VERDICT_REJECTED:
            return result
        last = result
        if result.stage != STAGE_EMAIL_SUBMIT or index >= max(1, attempts) - 1:
            break
        logger.info(
            "[域名体检] %s 邮箱提交步被拒，可能是偶发失败，重试第 %s 次",
            domain,
            index + 2,
        )
        time.sleep(5)
    assert last is not None
    last.detail = f"{last.detail}（重试 {max(1, attempts)} 次均为此结果）"
    return last


def probe_domain(
    domain: str,
    *,
    proxy: str | None = None,
    check_register: bool = True,
    local_part: str | None = None,
    attempts: int = 3,
) -> ProbeResult:
    """体检单个域名（自己开一个浏览器）。"""
    normalized = normalize_domain(domain)
    if not normalized or "." not in normalized or " " in normalized:
        return ProbeResult(
            domain=normalized,
            verdict=VERDICT_INCONCLUSIVE,
            stage=STAGE_INPUT,
            detail="域名格式无效，请只填域名本身，如 mydomain.com",
        )

    from core.cloakbrowser_driver import build_cloak_driver

    driver = None
    try:
        driver, _opened = build_cloak_driver(proxy=proxy)
        return _probe_with_retry(
            driver,
            normalized,
            check_register=check_register,
            local_part=local_part,
            attempts=attempts,
        )
    except Exception as exc:
        return ProbeResult(
            domain=normalized,
            verdict=VERDICT_INCONCLUSIVE,
            stage=STAGE_EXCEPTION,
            detail=f"{type(exc).__name__}: {str(exc)[:200]}",
        )
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass


def probe_domains(
    domains,
    *,
    proxy: str | None = None,
    check_register: bool = True,
    local_part: str | None = None,
    attempts: int = 3,
) -> list[ProbeResult]:
    """批量体检多个域名（共用一个浏览器，比逐个开浏览器快很多）。"""
    items: list[str] = []
    for item in domains or []:
        normalized = normalize_domain(item)
        if normalized and normalized not in items:
            items.append(normalized)
    if not items:
        return []

    from core.cloakbrowser_driver import build_cloak_driver

    results: list[ProbeResult] = []
    driver = None
    try:
        driver, _opened = build_cloak_driver(proxy=proxy)
    except Exception as exc:
        return [
            ProbeResult(
                domain=item,
                verdict=VERDICT_INCONCLUSIVE,
                stage=STAGE_EXCEPTION,
                detail=f"启动浏览器失败: {type(exc).__name__}: {str(exc)[:160]}",
            )
            for item in items
        ]

    try:
        for item in items:
            logger.info("[域名体检] 开始检查 %s", item)
            try:
                result = _probe_with_retry(
                    driver,
                    item,
                    check_register=check_register,
                    local_part=local_part,
                    attempts=attempts,
                )
            except Exception as exc:
                result = ProbeResult(
                    domain=item,
                    verdict=VERDICT_INCONCLUSIVE,
                    stage=STAGE_EXCEPTION,
                    detail=f"{type(exc).__name__}: {str(exc)[:200]}",
                )
            results.append(result)
            logger.info(
                "[域名体检] %s -> %s（%s）%s",
                result.domain,
                result.verdict,
                result.stage,
                f" {result.detail}" if result.detail else "",
            )
    finally:
        try:
            if driver is not None:
                driver.quit()
        except Exception:
            pass
    return results
