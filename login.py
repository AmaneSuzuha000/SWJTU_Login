from __future__ import annotations

import getpass
import json
import os
import time

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

import requests

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

CAS_BASE = "https://cas.swjtu.edu.cn/authserver"
SERVICE_URL = (
    "http://jwc.swjtu.edu.cn/"
    "vatuu/UserLoginForWiseduAction"
)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0 Safari/537.36"
)
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "keep-alive",
}
LOGIN_USERNAME_SELECTORS = [
    ".form > .m-account > * > #username",
    "#pwdLoginDiv #username",
    "input[name='username']",
]
LOGIN_PASSWORD_SELECTORS = [
    ".form > .m-account > * > #password",
    "#pwdLoginDiv #password",
    "input[name='password']",
]
LOGIN_CAPTCHA_SELECTORS = [
    ".form > .m-account > * > #captcha",
    "#pwdLoginDiv #captcha",
]
LOGIN_SUBMIT_SELECTORS = [
    "#login_submit",
    "button[type='submit']",
    "input[type='submit']",
]
REAUTH_DYNAMIC_CODE_SELECTORS = [
    "#dynamicCode",
]
REAUTH_GET_CODE_SELECTORS = [
    "#getDynamicCode",
]
REAUTH_TYPE_TOGGLE_SELECTORS = [
    "#changeReAuthTypeButton",
]
REAUTH_TYPE_OPTION_SELECTORS = [
    "#changeReAuthTypeDiv .changeReAuthTypes",
]
REAUTH_SUBMIT_SELECTORS = [
    "#reAuthSubmitBtn",
    ".submit_btn",
]
REAUTH_ERROR_SELECTORS = [
    ".reauth_error_submit",
    ".reauth_error",
]
TRUST_DEVICE_CANCEL_SELECTORS = [
    ".trust-device-cancel-btn",
]
TRUST_DEVICE_SUBMIT_SELECTORS = [
    ".trust-device-sub-btn",
]
REAUTH_TYPE_LABELS = {
    "2": "密码二次验证",
    "3": "短信验证码",
    "4": "企业微信验证码",
    "5": "校园 APP 验证码",
    "10": "OTP 令牌",
    "11": "邮箱验证码",
    "12": "钉钉验证码",
    "13": "WeLink 验证码",
    "14": "二维码验证",
}


@dataclass
class AuthState:
    cookies: list[dict[str, Any]]
    user_agent: str
    cas_base: str
    jwc_base: str
    service_url: str
    created_at: float = field(default_factory=time.time)

    def save(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(asdict(self), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "AuthState":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**data)


def derive_origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def build_requests_session(
    auth_state: AuthState,
    extra_headers: dict[str, str] | None = None,
) -> requests.Session:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    session.headers["User-Agent"] = auth_state.user_agent

    if extra_headers:
        session.headers.update(extra_headers)

    for cookie in auth_state.cookies:
        session.cookies.set(
            name=cookie["name"],
            value=cookie["value"],
            domain=cookie.get("domain"),
            path=cookie.get("path", "/"),
        )

    return session


def is_requests_session_ready(
    session: requests.Session,
    jwc_base: str,
    timeout: int = 10,
) -> bool:
    resp = session.get(
        f"{jwc_base}/vatuu/UserLoadingAction",
        allow_redirects=False,
        timeout=timeout,
    )
    location = resp.headers.get("Location") or resp.headers.get("location", "")

    if resp.status_code == 302 and "cas.swjtu.edu.cn" in location:
        return False

    return True


class PlaywrightLoginProvider:
    def __init__(
        self,
        username: str,
        password: str,
        *,
        cas_base: str = CAS_BASE,
        service_url: str = SERVICE_URL,
        user_agent: str = USER_AGENT,
        headless: bool = False,
        account_root: str | Path | None = None,
    ) -> None:
        self.username = username
        self.password = password
        self.cas_base = cas_base.rstrip("/")
        self.service_url = service_url
        self.jwc_base = derive_origin(service_url)
        self.user_agent = user_agent
        self.headless = headless

        base_dir = Path(account_root or Path(__file__).resolve().parent / "account")
        self.account_dir = base_dir / username
        self.user_data_dir = self.account_dir / "playwright_profile"
        self.account_dir.mkdir(parents=True, exist_ok=True)

    def _require_playwright(self) -> None:
        if sync_playwright is None:
            raise RuntimeError(
                "未安装 Playwright。请先执行 "
                "`pip install playwright`，再执行 "
                "`playwright install chromium`。"
            )

    def _build_login_url(self) -> str:
        return f"{self.cas_base}/login?{urlencode({'service': self.service_url})}"

    @staticmethod
    def _first_locator(page: Any, selectors: list[str]) -> Any | None:
        for selector in selectors:
            locator = page.locator(selector)
            if locator.count() > 0:
                return locator.first
        return None

    @staticmethod
    def _is_locator_visible(locator: Any | None) -> bool:
        if locator is None:
            return False

        try:
            return locator.is_visible()
        except Exception:
            return False

    def _has_visible_captcha(self, page: Any) -> bool:
        for selector in LOGIN_CAPTCHA_SELECTORS + ["#captchaDiv", "#sliderCaptchaDiv"]:
            locator = page.locator(selector)
            if locator.count() == 0:
                continue
            try:
                if locator.first.is_visible():
                    return True
            except Exception:
                continue
        return False

    def _captcha_required(self, page: Any) -> bool:
        return self._has_visible_captcha(page)

    @staticmethod
    def _safe_text(locator: Any | None) -> str:
        if locator is None:
            return ""

        try:
            return locator.inner_text().strip()
        except Exception:
            return ""

    def _first_visible_locator(self, page: Any, selectors: list[str]) -> Any | None:
        for selector in selectors:
            locator = page.locator(selector)
            if locator.count() == 0:
                continue
            try:
                first = locator.first
                if first.is_visible():
                    return first
            except Exception:
                continue
        return None

    @staticmethod
    def _url_contains(page: Any, needle: str) -> bool:
        return needle in page.url

    def _is_login_page(self, page: Any) -> bool:
        return self._url_contains(page, "/authserver/login")

    def _is_reauth_page(self, page: Any) -> bool:
        if self._url_contains(page, "/authserver/reAuthCheck/reAuthLoginView.do"):
            return True

        return self._first_visible_locator(page, REAUTH_SUBMIT_SELECTORS) is not None

    def _read_reauth_params(self, page: Any) -> dict[str, Any]:
        try:
            data = page.evaluate(
                """() => {
                    if (!window.reAuthParams) {
                        return {};
                    }
                    return {
                        reAuthType: window.reAuthParams.reAuthType || "",
                        service: window.reAuthParams.service || "",
                        isMultifactor: window.reAuthParams.isMultifactor || "",
                        reAuthUserId: window.reAuthParams.reAuthUserId || "",
                    };
                }"""
            )
        except Exception:
            return {}

        return data or {}

    def _read_reauth_options(self, page: Any, current_type: str) -> list[dict[str, str]]:
        options: list[dict[str, str]] = []

        current_label = page.evaluate(
            """() => {
                const el = document.querySelector(
                    "#changeReAuthTypeButton .drop_ellipsis"
                );
                return el ? el.textContent.trim() : "";
            }"""
        )
        if current_type and current_label:
            options.append({
                "id": current_type,
                "label": current_label,
            })

        extra_options = page.evaluate(
            """() => {
                return Array.from(
                    document.querySelectorAll("#changeReAuthTypeDiv .changeReAuthTypes")
                )
                    .filter((el) => {
                        const style = window.getComputedStyle(el);
                        return style.display !== "none";
                    })
                    .map((el) => ({
                        id: el.id || "",
                        label: (el.textContent || "").trim(),
                    }));
            }"""
        )

        for item in extra_options or []:
            if not item.get("id"):
                continue
            if any(existing["id"] == item["id"] for existing in options):
                continue
            options.append({
                "id": item["id"],
                "label": item.get("label", ""),
            })

        return options

    def _choose_reauth_option(
        self,
        page: Any,
        current_type: str,
    ) -> str:
        options = self._read_reauth_options(page, current_type)
        if not options:
            return current_type

        print("可用的 MFA 验证方式：")
        for index, option in enumerate(options, start=1):
            suffix = "（当前）" if option["id"] == current_type else ""
            print(f"{index}. {option['label']}{suffix}")

        while True:
            choice = input("请选择 MFA 方式编号：").strip()
            if not choice.isdigit():
                print("请输入数字编号。")
                continue

            selected_index = int(choice) - 1
            if selected_index < 0 or selected_index >= len(options):
                print("选择超出范围。")
                continue

            selected = options[selected_index]
            selected_type = selected["id"]

            if selected_type == current_type:
                return current_type

            toggle = self._first_visible_locator(page, REAUTH_TYPE_TOGGLE_SELECTORS)
            if toggle is None:
                print("未找到 MFA 方式切换器。")
                return current_type

            toggle.click()
            page.wait_for_timeout(500)

            option_locator = page.locator(
                f"#changeReAuthTypeDiv .changeReAuthTypes[id='{selected_type}']"
            )
            if option_locator.count() == 0:
                print("页面上没有找到所选的 MFA 方式。")
                return current_type

            option_locator.first.click()
            page.wait_for_timeout(1500)

            updated_params = self._read_reauth_params(page)
            updated_type = str(updated_params.get("reAuthType", "")).strip() or selected_type
            updated_options = self._read_reauth_options(page, updated_type)
            updated_label = next(
                (item["label"] for item in updated_options if item["id"] == updated_type),
                selected["label"],
            )
            print(f"已切换到 MFA 方式：{updated_label}")
            return updated_type

    def _wait_for_post_submit_state(self, page: Any, timeout_ms: int = 8000) -> str:
        deadline = time.time() + (timeout_ms / 1000)

        while time.time() < deadline:
            if self._is_reauth_page(page):
                return "reauth"

            if not self._is_login_page(page):
                return "other"

            if self._has_visible_captcha(page):
                return "login"

            error_box = self._first_visible_locator(page, ["#showErrorTip"])
            if self._safe_text(error_box):
                return "login"

            page.wait_for_timeout(300)

        if self._is_reauth_page(page):
            return "reauth"
        if self._is_login_page(page):
            return "login"
        return "other"

    @staticmethod
    def _describe_post_submit_state(state: str) -> str:
        descriptions = {
            "login": "仍停留在 CAS 登录页",
            "reauth": "已进入 MFA 页面",
            "other": "已离开 CAS 登录页，正在继续跳转到目标系统",
        }
        return descriptions.get(state, state)

    def _print_reauth_summary(self, reauth_params: dict[str, Any]) -> None:
        reauth_type = str(reauth_params.get("reAuthType", "")).strip()
        label = REAUTH_TYPE_LABELS.get(reauth_type, f"reAuthType={reauth_type or 'unknown'}")
        service = reauth_params.get("service", "")
        print(f"检测到 MFA 页面，当前方式：{label}。")
        if service:
            print(f"MFA 服务目标：{service}")

    def _print_reauth_errors(self, page: Any) -> None:
        for selector in REAUTH_ERROR_SELECTORS:
            locator = self._first_visible_locator(page, [selector])
            message = self._safe_text(locator)
            if message:
                print(f"MFA 页面提示：{message}")

    def _finalize_authenticated_navigation(self, page: Any) -> None:
        try:
            page.goto(self.service_url, wait_until="domcontentloaded")
        except Exception:
            pass

        try:
            page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass

    def _accept_trust_device_modal(self, page: Any) -> bool:
        for _ in range(10):
            trust_button = self._first_visible_locator(page, TRUST_DEVICE_SUBMIT_SELECTORS)
            if trust_button is not None:
                print("检测到信任设备弹窗，自动选择“信任此设备”。")
                trust_button.click()
                page.wait_for_timeout(800)
                return True
            page.wait_for_timeout(300)

        return False

    def _handle_dynamic_reauth(self, page: Any, reauth_type: str) -> bool:
        dynamic_code_input = self._first_visible_locator(page, REAUTH_DYNAMIC_CODE_SELECTORS)
        submit_button = self._first_visible_locator(page, REAUTH_SUBMIT_SELECTORS)

        if dynamic_code_input is None or submit_button is None:
            return False

        selected_type = self._choose_reauth_option(page, reauth_type)

        get_code_button = self._first_visible_locator(page, REAUTH_GET_CODE_SELECTORS)
        if get_code_button is None:
            print("未找到 MFA 页面上的发送验证码按钮。")
            return False

        get_code_button.click()
        page.wait_for_timeout(1200)
        print(
            "已触发 "
            f"{REAUTH_TYPE_LABELS.get(selected_type, selected_type)} 的验证码发送。"
        )
        self._print_reauth_errors(page)

        for attempt in range(1, 4):
            code = input("请输入收到的 MFA 验证码：").strip()
            if not code:
                print("未输入 MFA 验证码。")
                continue

            dynamic_code_input.fill("")
            dynamic_code_input.fill(code)
            submit_button.click()
            page.wait_for_timeout(800)
            self._accept_trust_device_modal(page)
            page.wait_for_timeout(1500)

            if not self._is_reauth_page(page):
                return True

            self._print_reauth_errors(page)
            if attempt < 3:
                print("MFA 页面仍未关闭。如有需要，请在浏览器中重新发送验证码后再试一次。")

        return False

    def _handle_password_reauth(self, page: Any) -> bool:
        password_input = self._first_visible_locator(page, ["#password"])
        submit_button = self._first_visible_locator(page, REAUTH_SUBMIT_SELECTORS)

        if password_input is None or submit_button is None:
            return False

        password_input.fill("")
        password_input.fill(self.password)
        submit_button.click()
        page.wait_for_timeout(800)
        self._accept_trust_device_modal(page)
        page.wait_for_timeout(1500)
        self._print_reauth_errors(page)
        return True

    def _wait_for_manual_reauth_flow(
        self,
        page: Any,
        timeout_seconds: int = 300,
    ) -> bool:
        print("浏览器当前位于 MFA 页面。")
        print("请在页面中选择 MFA 方式、发送验证码，并在页面中手动完成输入。")
        print("我会监控信任设备弹窗，并自动选择“信任此设备”。")

        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            self._accept_trust_device_modal(page)

            if not self._is_reauth_page(page):
                self._finalize_authenticated_navigation(page)
                return not self._is_login_page(page)

            page.wait_for_timeout(500)

        self._print_reauth_errors(page)
        print("等待浏览器中的 MFA 完成已超时。")
        return False

    def _handle_reauth_page(self, page: Any) -> bool:
        reauth_params = self._read_reauth_params(page)
        self._print_reauth_summary(reauth_params)
        reauth_type = str(reauth_params.get("reAuthType", "")).strip()

        if reauth_type in {"3", "4", "5", "11", "12", "13"}:
            return self._handle_dynamic_reauth(page, reauth_type)

        return self._wait_for_manual_reauth_flow(page)

    def _fill_login_form(self, page: Any) -> bool:
        username_input = self._first_locator(
            page,
            LOGIN_USERNAME_SELECTORS,
        )
        password_input = self._first_locator(
            page,
            LOGIN_PASSWORD_SELECTORS,
        )

        if (
            not self._is_locator_visible(username_input)
            or not self._is_locator_visible(password_input)
        ):
            return False

        username_input.fill("")
        username_input.fill(self.username)
        username_input.press("Tab")
        page.wait_for_timeout(800)
        password_input.fill("")
        password_input.fill(self.password)

        submit_button = self._first_locator(
            page,
            LOGIN_SUBMIT_SELECTORS,
        )

        if self._captcha_required(page):
            print("登录页需要图片验证码或滑块验证。")
            print("请先在浏览器中完成验证，然后回到终端按回车继续。")
            input("完成登录验证码后按回车继续：")
            if submit_button and self._is_locator_visible(submit_button):
                submit_button.click()
            else:
                password_input.press("Enter")
            return True

        print("当前登录页不需要图片验证码。")

        if submit_button and self._is_locator_visible(submit_button):
            submit_button.click()
        else:
            password_input.press("Enter")

        return True

    def _wait_for_manual_steps(self, page: Any) -> None:
        print("已打开真实浏览器窗口。")
        print("该页面使用 login.js 前端逻辑处理提交、验证码和密码流程。")
        print("请在浏览器中完成任何验证码、MFA 或信任设备确认。")
        print("如果页面仍停留在 CAS 登录页，请先完成挑战并点击页面上的登录按钮。")
        print("浏览器到达已登录状态后，请回到这里按回车继续。")
        input("按回车继续...")
        self._finalize_authenticated_navigation(page)
        print(f"导出前浏览器最终 URL：{page.url}")

    def export_auth_state(self, context: Any) -> AuthState:
        cookies = context.cookies(
            [
                self.cas_base,
                self.jwc_base,
                self.service_url,
            ]
        )
        return AuthState(
            cookies=cookies,
            user_agent=self.user_agent,
            cas_base=self.cas_base,
            jwc_base=self.jwc_base,
            service_url=self.service_url,
        )

    def login(self) -> AuthState:
        self._require_playwright()

        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                user_data_dir=str(self.user_data_dir),
                headless=self.headless,
                user_agent=self.user_agent,
                viewport={"width": 1440, "height": 900},
            )

            try:
                page = context.pages[0] if context.pages else context.new_page()
                page.goto(self._build_login_url(), wait_until="domcontentloaded")

                filled = self._fill_login_form(page)
                if filled:
                    print("已自动填入 CAS 登录表单账号密码。")
                else:
                    print("未自动填充登录表单。")
                    print("浏览器可能已经登录，或当前停留在其他页面。")

                page.wait_for_timeout(1200)
                state = self._wait_for_post_submit_state(page)
                print(
                    "登录提交结果："
                    f"{self._describe_post_submit_state(state)}."
                )

                if state == "reauth":
                    handled = self._handle_reauth_page(page)
                    if not handled or self._is_reauth_page(page):
                        self._wait_for_manual_steps(page)
                    else:
                        self._finalize_authenticated_navigation(page)
                elif state == "login":
                    print(
                        "CAS 仍停留在登录页。"
                        "这通常意味着验证码或账号密码仍需处理。"
                    )
                    self._wait_for_manual_steps(page)
                else:
                    print(
                        "CAS 未进入 MFA。"
                        "如果当前设备已被信任，这通常属于预期的快速登录路径。"
                    )
                    self._finalize_authenticated_navigation(page)

                if "/authserver/login" in page.url:
                    print("浏览器当前仍停留在 CAS 登录页。")
                    print("导出的 requests.Session 可能尚未完成认证。")

                auth_state = self.export_auth_state(context)
                print(f"浏览器最终 URL：{page.url}")
                print(f"已为 requests.Session 导出 {len(auth_state.cookies)} 个 Cookie。")
                return auth_state
            finally:
                context.close()

    def login_and_build_session(self) -> tuple[AuthState, requests.Session]:
        auth_state = self.login()
        session = build_requests_session(auth_state)
        return auth_state, session


class SWJTUAssessor:
    def __init__(
        self,
        username: str,
        password: str,
        *,
        headless: bool = False,
        account_root: str | Path | None = None,
    ) -> None:
        self.username = username
        self.password = password
        self.provider = PlaywrightLoginProvider(
            username=username,
            password=password,
            headless=headless,
            account_root=account_root,
        )
        self.auth_state_path = self.provider.account_dir / "auth_state.json"
        self.auth_state: AuthState | None = None
        self.session: requests.Session | None = None

    def login(self, save_auth_state: bool = False) -> bool:
        self.auth_state, self.session = self.provider.login_and_build_session()

        if save_auth_state and self.auth_state:
            self.auth_state.save(self.auth_state_path)
            print(f"认证状态已保存到：{self.auth_state_path}")

        ready = is_requests_session_ready(self.session, self.auth_state.jwc_base)
        print(f"requests.Session 是否可用：{ready}")
        return ready

    def restore_session(self, path: str | Path | None = None) -> bool:
        target = Path(path or self.auth_state_path)
        self.auth_state = AuthState.load(target)
        self.session = build_requests_session(self.auth_state)
        ready = is_requests_session_ready(self.session, self.auth_state.jwc_base)
        print(f"requests.Session 恢复结果：{ready}")
        return ready

    def get_session(self) -> requests.Session:
        if self.session is None:
            raise RuntimeError("当前没有可用的 requests.Session，请先调用 login()。")
        return self.session

    def export_auth_state(self) -> AuthState:
        if self.auth_state is None:
            raise RuntimeError("当前没有可用的认证状态，请先调用 login()。")
        return self.auth_state


def login_and_get_session(
    username: str,
    password: str,
    *,
    headless: bool = False,
    account_root: str | Path | None = None,
    save_auth_state: bool = False,
) -> requests.Session:
    client = SWJTUAssessor(
        username=username,
        password=password,
        headless=headless,
        account_root=account_root,
    )
    success = client.login(save_auth_state=save_auth_state)
    if not success:
        raise RuntimeError("登录流程已完成，但导出的 requests.Session 不可用。")
    return client.get_session()


if __name__ == "__main__":

    client = SWJTUAssessor(
        username="Username",
        password="Password",
        headless=False,
    )
    success = client.login(save_auth_state=False)
    print("登录结果：", success)
