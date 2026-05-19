import time
import random
import base64

from urllib.parse import urlparse

import requests

from bs4 import BeautifulSoup

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from ddddocr import DdddOcr

# 全局初始化
ocr = DdddOcr(show_ad=False)
from PIL import Image
import io

import pickle
import json
import os

CAS_BASE = "https://cas.swjtu.edu.cn/authserver"

SERVICE_URL = ("http://jwc.swjtu.edu.cn/"
               "vatuu/UserLoginForWiseduAction"
               )

AES_CHARS = (
    "ABCDEFGHJKMNPQRSTWXYZ"
    "abcdefhijkmnprstwxyz2345678"
)


class SWJTUAssessor:

    def __init__(self, username, password):

        self.username = username
        self.password = password

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/136.0 Safari/537.36"
        })

        self.user_dir = os.path.join(
            "account",
            self.username
        )

        os.makedirs(
            self.user_dir,
            exist_ok=True
        )

        self.cookie_file = os.path.join(
            self.user_dir,
            "cookies.pkl"
        )

        self.config_file = os.path.join(
            self.user_dir,
            "config.json"
        )

        #检测CAS统一认证平台协议）
        cas_domain = "cas.swjtu.edu.cn"
        cas_test_endpoint = "/authserver"
        self.CAS_BASE = f"https://{cas_domain}"

        try:
            print(f"\n开始测试CAS连通性和协议: {self.CAS_BASE}{cas_test_endpoint}")
            response = self.session.get(
                f"{self.CAS_BASE}{cas_test_endpoint}",
                timeout=5,
                allow_redirects=True,
                verify=True
            )

            print(f"CAS最终URL: {response.url}")
            parsed = urlparse(response.url)
            if parsed.scheme == "https":
                self.CAS_BASE = f"https://{cas_domain}/authserver"
                print("CAS HTTPS协议正常可用。")
            else:
                self.CAS_BASE = f"https://{cas_domain}/authserver"
                print("检测到CAS使用HTTP，已切换为HTTP访问。")

        except Exception as e:
            print(f"CAS HTTPS检测失败: {e}，尝试HTTP协议")
            self.CAS_BASE = f"http://{cas_domain}"
            try:
                response = self.session.get(
                    f"{self.CAS_BASE}{cas_test_endpoint}",
                    timeout=5,
                    allow_redirects=True
                )
                print(f"CAS HTTP协议可用，最终URL: {response.url}")
            except Exception as e2:
                raise RuntimeError(f"CAS服务完全无法访问: {e2}") from e2

        # 检测教务系统协议
        jwc_domain = "jwc.swjtu.edu.cn"
        jwc_test_endpoint = "/vatuu/UserLoginForWiseduAction"
        self.JWC_BASE = f"https://{jwc_domain}"

        try:
            print(f"\n开始测试教务系统连通性和协议: {self.JWC_BASE}{jwc_test_endpoint}")
            response = self.session.get(
                f"{self.JWC_BASE}{jwc_test_endpoint}",
                timeout=5,
                allow_redirects=True,
                verify=True
            )

            if response.history:
                print(f"\n重定向路径 ({len(response.history)} 次):")
                for i, resp in enumerate(response.history, 1):
                    status = resp.status_code
                    from_url = resp.url
                    to_url = resp.headers.get('location', resp.url)
                    print(f"  {i}. [{status}] {from_url}")
                    print(f"     重定向到: {to_url}")

            print(f"教务系统最终URL: {response.url}")
            parsed = urlparse(response.url)
            if parsed.scheme == "http":
                self.JWC_BASE = f"http://{jwc_domain}"
                print("检测到教务系统使用HTTP，已切换为HTTP访问。")
            else:
                print("教务系统HTTPS协议正常可用。")

        except Exception as e:
            print(f"教务系统HTTPS检测失败: {e}，尝试HTTP协议")
            self.JWC_BASE = f"http://{jwc_domain}"
            try:
                response = self.session.get(
                    f"{self.JWC_BASE}{jwc_test_endpoint}",
                    timeout=5,
                    allow_redirects=True
                )
                print(f"教务系统HTTP协议可用，最终URL: {response.url}")
            except Exception as e2:
                raise RuntimeError(f"教务系统完全无法访问: {e2}") from e2

        self.SERVICE_URL = f"{self.JWC_BASE}/vatuu/UserLoginForWiseduAction"

        print(f"\n{'=' * 60}")
        print("✅ 西南交大登录器初始化完成")
        print(f"CAS_BASE = {self.CAS_BASE}")
        print(f"SERVICE_URL = {self.SERVICE_URL}")
        print(f"用户名: {self.username}")


    # Random_String
    def random_string(self, length):

        return ''.join(
            random.choice(AES_CHARS)
            for _ in range(length)
        )

    # CryptoJS AES-CBC-PKCS7
    def encrypt_password(self, password, salt):

        iv = self.random_string(16)

        plain = self.random_string(64) + password

        cipher = AES.new(
            salt.encode("utf-8"),
            AES.MODE_CBC,
            iv.encode("utf-8")
        )

        encrypted = cipher.encrypt(
            pad(
                plain.encode("utf-8"),
                AES.block_size
            )
        )

        return base64.b64encode(encrypted).decode()

    # 获取登录页
    def get_login_page(self):

        url = f"{self.CAS_BASE}/login"

        resp = self.session.get(
            url,
            params={
                "service": self.SERVICE_URL
            }
        )

        resp.raise_for_status()

        soup = BeautifulSoup(
            resp.text,
            "html.parser"
        )

        execution = soup.find(
            "input",
            {"name": "execution"}
        )["value"]

        lt_input = soup.find(
            "input",
            {"name": "lt"}
        )

        lt = ""

        if lt_input:
            lt = lt_input.get("value", "")

        salt = soup.find(
            "input",
            {"id": "pwdEncryptSalt"}
        )["value"]

        return execution, lt, salt

    # 检查是否需要验证码
    def check_need_captcha(self):

        url = (
            f"{self.CAS_BASE}/"
            "checkNeedCaptcha.htl"
        )

        resp = self.session.get(
            url,
            params={
                "username": self.username,
                "_": int(time.time() * 1000)
            }
        )

        resp.raise_for_status()

        try:

            data = resp.json()
            if data.get("isNeed", False) :
                print("需要验证码")
            else:
                print("不需要验证码")

            return data.get("isNeed", False)

        except Exception:

            return False

    # 获取验证码图片
    def get_captcha_image(self):

        url = (
            f"{CAS_BASE}/"
            "getCaptcha.htl"
        )

        resp = self.session.get(
            url,
            params={
                "_": int(time.time() * 1000)
            }
        )

        resp.raise_for_status()
        return resp.content

    # DDDDOCR
    def recognize_captcha(self, image_bytes):

        img = Image.open(io.BytesIO(image_bytes)).convert("L")
        threshold = img.getextrema()[1] * 0.8
        img = img.point(lambda x: 0 if x < threshold else 255, "1")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        bytes=buf.getvalue()

        captcha = ocr.classification(bytes)
        print(f"验证码为{captcha}")

        return captcha.strip()

    def handle_reauth(self, reauth_url):

        if reauth_url.startswith("/"):
            reauth_url = "https://cas.swjtu.edu.cn" + reauth_url

        print("进入 MFA 页面:", reauth_url)

        # 让用户选择验证方式
        print("请选择多因子验证方式:")
        print("1.短信验证")
        print("2.微信验证")
        choice = input("输入 1 或 2: ").strip()
        if choice == "1":
            reAuthType = 3
            authCodeTypeName = "reAuthDynamicCodeType"
        elif choice == "2":
            reAuthType = 4
            authCodeTypeName = "reAuthWChatDynamicCodeType"
        else:
            print("输入无效，默认使用短信验证")
            reAuthType = 3
            authCodeTypeName = "reAuthDynamicCodeType"

        # 切换验证方式
        change_type_url = "https://cas.swjtu.edu.cn/authserver/reAuthCheck/changeReAuthType.do"
        payload_type = {
            "isMultifactor": "true",
            "reAuthType": reAuthType
        }
        resp = self.session.post(change_type_url, data=payload_type)
        if resp.status_code != 200:
            print("切换验证方式失败")
            return False
        print(f"已切换为 {'短信' if reAuthType == 3 else '微信'} 验证")

        # 请求验证码
        get_code_url = "https://cas.swjtu.edu.cn/authserver/dynamicCode/getDynamicCodeByReauth.do"
        payload_code = {
            "userName": self.username,
            "authCodeTypeName": authCodeTypeName
        }
        resp = self.session.post(get_code_url, data=payload_code)
        if resp.status_code != 200:
            print("获取验证码失败")
            return False
        print("验证码已发送，请查收手机/微信")

        # 用户输入验证码
        dynamic_code = input("请输入收到的验证码: ").strip()

        # 提交 MFA + 信任设备
        submit_url = "https://cas.swjtu.edu.cn/authserver/reAuthCheck/reAuthSubmit.do"
        payload_submit = {
            "service": self.SERVICE_URL,
            "reAuthType": reAuthType,
            "isMultifactor": "true",
            "password": "",
            "dynamicCode": dynamic_code,
            "uuid": "",
            "answer1": "",
            "answer2": "",
            "otpCode": "",
            "skipTmpReAuth": "true"  # 信任此设备
        }

        verify_resp = self.session.post(
            submit_url,
            data=payload_submit,
            allow_redirects=False
        )

        try:

            result = verify_resp.json()

            if result.get("code") != "reAuth_success":
                print("MFA验证失败")
                return False

            print("MFA验证成功")

        except Exception:

            print("MFA返回异常")
            return False

        ticket_resp = self.session.get(
            f"{self.CAS_BASE}/login",
            params={
                "service": self.SERVICE_URL
            },
            allow_redirects=False
        )

        location = ticket_resp.headers.get("Location")

        print("MFA后跳转:", location)

        if not location:
            print("未获取 Ticket")
            return False

        # 跟随 ticket
        self.session.get(location)

        # 建立教务系统 session
        self.finish_jwc_login()

        return True

    # 登录
    def login(self):

        # 尝试恢复 Cookie
        if self.load_cookies():

            print("正在尝试使用历史登录状态...")

            test = self.session.get(
                f"{self.JWC_BASE}/vatuu/UserLoadingAction",
                allow_redirects=False
            )

            # 未跳转 CAS
            if test.status_code != 302:
                print("历史 Cookie 仍有效，无需 MFA")

                return True

            print("Cookie 已失效，需要重新登录")

        execution, lt, salt = (
            self.get_login_page()
        )

        need_captcha = (
            self.check_need_captcha()
        )

        captcha_code = ""

        if need_captcha:
            img = self.get_captcha_image()

            with open("captcha.jpg", "wb") as f:
                f.write(img)

            captcha_code = (
                self.recognize_captcha(img)
                )

        encrypted_password = (
            self.encrypt_password(
                self.password,
                salt
            )
        )

        payload = {

            "username": self.username,

            # 核心
            "password": encrypted_password,

            "execution": execution,

            "lt": lt,

            "_eventId": "submit",

            "cllt": "userNameLogin",

            "dllt": "generalLogin",

        }

        if captcha_code:
            payload["captcha"] = captcha_code

        login_url = (
            f"{self.CAS_BASE}/login"
        )

        resp = self.session.post(
            login_url,
            params={
                "service": self.SERVICE_URL
            },
            data=payload,
            allow_redirects=False
        )

        # 登录失败
        if resp.status_code != 302:

            print("CAS登录失败")
            soup = BeautifulSoup(resp.text, "html.parser")
            error_tip = soup.find(id="showErrorTip")
            if error_tip:
                text = error_tip.get_text(strip=True)
                print("错误信息:", text)
            else:
                print("未找到错误提示")

            return False

        redirect_url = resp.headers.get("Location")

        if not redirect_url:
            print("未获取到跳转链接")
            return False

        print("首次跳转:", redirect_url)

        # 检测是否进入 MFA
        if "reAuthCheck" in redirect_url:

            print("检测到新版多因子验证")

            ok = self.handle_reauth(redirect_url)

            if not ok:
                print("多因子验证失败")
                return False

            return True

        if not redirect_url:

            print("未获取到CAS Ticket")

            return False

        print("CAS登录成功")

        print("Ticket跳转:", redirect_url)

        # 跟随Ticket跳转
        self.session.get(redirect_url)

        self.finish_jwc_login()

        return True

    def finish_jwc_login(self):

        print("正在建立教务系统 Session...")

        self.session.get(
            f"{self.JWC_BASE}/vatuu/UserLoginForCAS",
            timeout=10
        )

        self.session.get(
            f"{self.JWC_BASE}/vatuu/UserLoadingAction",
            timeout=10
        )

        print("教务系统登录完成")

        self.save_cookies()

    def save_cookies(self):

        with open(self.cookie_file, "wb") as f:
            pickle.dump(self.session.cookies, f)

        print("Cookie 已保存")

    def load_cookies(self):

        if not os.path.exists(self.cookie_file):
            return False

        try:

            with open(self.cookie_file, "rb") as f:
                cookies = pickle.load(f)

            self.session.cookies.update(cookies)

            print("Cookie 已加载")

            return True

        except Exception as e:

            print("Cookie 加载失败:", e)

            return False


if __name__ == "__main__":

    username = ("Username")

    password = "Password"

    client = SWJTUAssessor(
        username,
        password
    )

    success = client.login()

    print("登录结果:", success)