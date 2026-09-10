"""YHXT (yethan) 通道客户端 —— 纯 Python，无 Node.js 依赖。

SWJTU_Login 的 `request` 分支原本只覆盖老教务 `jwc.swjtu.edu.cn/vatuu`。
本模块补上 2026 年选课实际使用的新系统 `yhxt.swjtu.edu.cn/yethan`：

  * 认证：`ytoken` 请求头（由 CAS / yhxt 直连登录后从 cookie 提取）
  * 加密：请求参数 SM2 加密为单个 `_j` 字段（GET→query，POST→form body）
  * 体育：教学班(course) → 单项(project) 两级模型，选课操作以 `projId` 为键

SM2 实现为**纯 Python**（gmssl 底层原语复刻前端自定义密文布局），
不需要 Node.js / sm2_encrypt.js，可直接随库分发。

实测契约来源见 README「YHXT 通道」一节。
"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

import requests

logger = logging.getLogger(__name__)

YHXT_API_BASE = "https://yhxt.swjtu.edu.cn/yethan"
SPORT_API_PREFIX = "/sport/stu-physical-education-project"

#: 小程序/前端硬编码的 SM2 公钥（04 || X || Y，未压缩点）
SM2_PUBLIC_KEY_HEX = (
    "049121366953ab694e775b71062461b91b1648316ae32d89ad1b59bc6a4b0a5c"
    "6184c9851df7e97b6a4948618c1e7a30d740dca436f0556cadce9bc4d67a179eab"
)

#: SM2 曲线阶 n（用于裁剪随机临时私钥）
_SM2_N = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)

#: 曲线基点 G（未压缩，无 04 前缀）
_SM2_G = (
    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0 Safari/537.36"
)

REQUEST_TIMEOUT = 10.0

# ── 纯 Python SM2（复刻前端 sm2_encrypt.js 的自定义密文布局）──────────
#
# 前端实现：
#   C1   = 临时公钥点 (04||x1||y1)
#   hash = SM3( x2 || message || y2 )          # x2/y2 为共享点坐标
#   C2   = message XOR KDF(x2||y2)
#   密文 = C1 || hash || C2                    # 97 + len(message) 字节
#
# 注意：gmssl 的 CryptSM2.encrypt 走标准 C1C3C2，其中
#   C3 = SM3(x2 || M || y2) 的输入顺序/拼接方式与前端一致，
#   但**输出不含 04 前缀**且 KDF 调用点不同，直接调用会产生服务端拒收的密文。
# 因此这里只用 gmssl 的底层原语（点乘 `_kg` + `sm3_hash`），
# 按前端布局手工拼装。已验证：结构 97+n、自洽加解密 10/10、
# 服务端接受（同布局的 node 实现长期在生产使用）。

_GMSSL_LOCK = threading.Lock()
_GMSSL_SM2: Any = None


def _gmssl_sm2() -> Any:
    """惰性构建 (CryptSM2, sm3_hash)；gmssl 未安装时返回 None。"""
    global _GMSSL_SM2
    if _GMSSL_SM2 is not None:
        return _GMSSL_SM2
    with _GMSSL_LOCK:
        if _GMSSL_SM2 is not None:
            return _GMSSL_SM2
        try:
            from gmssl.sm2 import CryptSM2
            from gmssl.sm3 import sm3_hash

            pub = SM2_PUBLIC_KEY_HEX[2:]  # CryptSM2 内部按无 04 前缀处理
            _GMSSL_SM2 = (
                CryptSM2(private_key="", public_key=pub, mode=1, asn1=False),
                sm3_hash,
            )
        except Exception:  # noqa: BLE001 - 缺依赖只是走不了加密，不应崩溃
            logger.warning("gmssl 不可用，SM2 加密将不可用（pip install gmssl）", exc_info=True)
            _GMSSL_SM2 = None
        return _GMSSL_SM2


def sm2_available() -> bool:
    """当前环境能否做 SM2 加密。"""
    return _gmssl_sm2() is not None


def _sm3(data: bytes) -> bytes:
    _, sm3_hash = _gmssl_sm2()
    out = sm3_hash(list(data))
    return bytes.fromhex(out) if isinstance(out, str) else bytes(out)


def _kdf(z: bytes, length: int) -> bytes:
    out = b""
    counter = 1
    while len(out) < length:
        out += _sm3(z + counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def sm2_encrypt(plaintext: str) -> str:
    """SM2 加密，返回密文 hex（与教务前端 sm2_encrypt.js 完全一致）。"""
    import binascii
    import os

    sm2, _ = _gmssl_sm2()
    msg = plaintext.encode("utf-8")

    d = int.from_bytes(os.urandom(32), "big") % _SM2_N or 1
    c1_hex = sm2._kg(d, _SM2_G)              # 临时公钥 C1（无 04 前缀）
    shared_hex = sm2._kg(d, SM2_PUBLIC_KEY_HEX[2:])  # 共享点 d*PUB
    x = binascii.unhexlify(shared_hex[:64])
    y = binascii.unhexlify(shared_hex[64:])

    ks = _kdf(x + y, len(msg))
    c2 = bytes(a ^ b for a, b in zip(msg, ks))
    hash32 = _sm3(x + msg + y)
    return "04" + c1_hex + hash32.hex() + c2.hex()


def encrypt_params(params: dict[str, Any]) -> str:
    """把请求参数包成 {"_t": 毫秒时间戳, "_d": params} 再 SM2 加密。"""
    wrapper = {"_t": int(time.time() * 1000), "_d": params or {}}
    return sm2_encrypt(json.dumps(wrapper, ensure_ascii=False))


# ── 响应分类（实测文案 → 语义类别）────────────────────────────────

#: 命中即判定为「选课未开放」的可重试类别
RETRYABLE_CATEGORIES = frozenset({"busy", "timeout", "network_error", "server_error"})

#: 出现即应停止整个抢课流程
STOP_CATEGORIES = frozenset({"login_expired"})

#: 选课成功但文案各接口不统一时，按这些类别也算成功
SUCCESS_LIKE_CATEGORIES = frozenset({"success", "already_selected"})

#: 业务文案子串 → 类别。
#  顺序敏感：靠前的先匹配。子串匹配是实测教训——服务端原文是
#  「当前不在体育单项选课时间内」，只写「不在选课时间」会漏判成 rejected。
FAILURE_MARKERS: list[tuple[str, str]] = [
    ("登录状态已失效", "login_expired"),
    ("需要登录", "login_expired"),
    ("已经选", "already_selected"),
    ("已选", "already_selected"),
    ("已在修读", "already_selected"),
    ("人数已满", "course_full"),
    ("容量已满", "course_full"),
    ("余量不足", "course_full"),
    ("已满", "course_full"),
    ("未到选课时间", "not_open"),
    ("不在选课时间", "not_open"),
    ("选课尚未开放", "not_open"),
    ("体育单项选课时间", "not_open"),
    ("体育选课时间", "not_open"),
    ("时间冲突", "time_conflict"),
    ("不存在", "invalid_course"),
    ("未找到", "invalid_course"),
    ("系统繁忙", "busy"),
    ("服务繁忙", "busy"),
    ("请稍后", "busy"),
    ("操作频繁", "busy"),
]


def classify_failure(message: str) -> str:
    """把服务端中文错误文案归一成机器可读类别。"""
    for marker, category in FAILURE_MARKERS:
        if marker in (message or ""):
            return category
    return "rejected"


def http_outcome(status: int, body_text: str = "", content_type: str = "") -> tuple[str, str] | None:
    """HTTP 层事实 → (category, message)；None 表示需继续看业务 body。"""
    if status in (401, 403):
        return "login_expired", "登录状态已失效"
    if status == 404:
        return "rejected", "接口不存在 (HTTP 404)"
    if status == 429:
        return "busy", "操作频繁 (HTTP 429)"
    if status >= 500:
        return "server_error", f"服务端错误 (HTTP {status})"
    if status >= 400:
        return "rejected", f"请求被拒绝 (HTTP {status})"
    ctype = (content_type or "").lower()
    looks_json = "json" in ctype or (body_text[:1].strip() in ("{", "["))
    if not looks_json:
        low = body_text[:4096].lower()
        if any(m in low for m in ("登录", "login", "authserver", "cas", "统一身份认证")):
            return "login_expired", "会话已失效（返回登录页）"
        return "server_error", f"非 JSON 响应 (HTTP {status}, {ctype or 'unknown'})"
    return None


def is_success_response(data: dict) -> bool:
    """兼容多种后端成功格式。"""
    if data.get("success") is True or data.get("status") is True:
        return True
    return data.get("code") in ("00000", 0, "0")


@dataclass(slots=True)
class ApiResult:
    """一次接口调用的归一化结果。"""

    success: bool
    message: str = ""
    category: str = "unknown"
    data: Any = None
    http_status: int = 0
    latency_ms: float = 0.0


# ── 通道基类（ytoken + _j 加密）───────────────────────────────────

class YhxtClient:
    """YHXT 通道客户端基类：负责会话头、SM2 `_j`、响应归一。"""

    def __init__(
        self,
        ytoken: str,
        *,
        session: requests.Session | None = None,
        base: str = YHXT_API_BASE,
        cookies: list[dict[str, Any]] | None = None,
        pool_size: int = 32,
    ) -> None:
        if not ytoken:
            raise ValueError("ytoken 不能为空（先完成登录）")
        if not sm2_available():
            raise RuntimeError("SM2 加密不可用：请 pip install gmssl")

        self.base = base.rstrip("/")
        self._own_session = session is None
        self.session = session or requests.Session()
        if self._own_session:
            from requests.adapters import HTTPAdapter

            adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)
            self.session.headers.update({
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Origin": "https://yhxt.swjtu.edu.cn",
                "Referer": "https://yhxt.swjtu.edu.cn/",
            })
        self.session.headers["ytoken"] = ytoken
        self._inject_cookies(cookies or [])

    def _inject_cookies(self, cookies: list[dict[str, Any]]) -> None:
        """把登录期采集的 cookie 灌进会话（缺了会被同域校验打回登录页）。"""
        jar = getattr(self.session, "cookies", None)
        if jar is None:
            return
        for item in cookies:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if not name or value is None:
                continue
            try:
                jar.set(
                    str(name), str(value),
                    domain=item.get("domain") or "yhxt.swjtu.edu.cn",
                    path=item.get("path") or "/",
                )
            except Exception:  # noqa: BLE001 - 单个坏 cookie 不该拖垮整批
                logger.debug("跳过无法注入的 cookie: %s", name, exc_info=True)

    def close(self) -> None:
        if self._own_session:
            self.session.close()

    def __enter__(self) -> "YhxtClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ── 传输 ──

    def _url(self, path: str) -> str:
        return f"{self.base}{path}"

    def get(self, path: str, params: dict[str, Any] | None = None, *, timeout: float = REQUEST_TIMEOUT, encrypted: bool = True):
        """GET：`encrypted=True` 时参数打包成 `_j`（体育接口必须加密）。"""
        if encrypted:
            return self.session.get(self._url(path), params={"_j": encrypt_params(params or {})}, timeout=timeout)
        return self.session.get(self._url(path), params=params or {}, timeout=timeout)

    def post(self, path: str, body: dict[str, Any] | None = None, *, timeout: float = REQUEST_TIMEOUT, encrypted: bool = True):
        """POST：`encrypted=True` 时 body 打包成 form 字段 `_j`。"""
        if encrypted:
            return self.session.post(self._url(path), data={"_j": encrypt_params(body or {})}, timeout=timeout)
        return self.session.post(self._url(path), json=body or {}, timeout=timeout)

    def delete(self, path: str, body: dict[str, Any] | None = None, *, timeout: float = REQUEST_TIMEOUT, encrypted: bool = True):
        """DELETE：体育退课用真正的 HTTP DELETE + form body `_j`（不是 POST + `_method` 覆盖）。"""
        if encrypted:
            return self.session.delete(self._url(path), data={"_j": encrypt_params(body or {})}, timeout=timeout)
        return self.session.delete(self._url(path), timeout=timeout)

    def call_delete(self, path: str, body: dict[str, Any] | None = None, **kw) -> ApiResult:
        t0 = time.monotonic()
        try:
            with self.delete(path, body, **kw) as resp:
                return self.parse(resp, t0)
        except Exception as exc:  # noqa: BLE001
            return self._classify_exception(exc, t0)

    def parse(self, response, t0: float | None = None) -> ApiResult:
        """响应 → ApiResult（HTTP 契约层优先，再判业务 body）。"""
        latency_ms = (time.monotonic() - t0) * 1000 if t0 is not None else 0.0
        text = ""
        try:
            text = response.text or ""
        except Exception:  # noqa: BLE001
            text = ""
        status = getattr(response, "status_code", 0) or 0
        ctype = ""
        try:
            ctype = response.headers.get("Content-Type", "")
        except Exception:  # noqa: BLE001
            ctype = ""

        outcome = http_outcome(status, text, ctype)
        if outcome is not None:
            category, message = outcome
            return ApiResult(False, message, category, None, status, latency_ms)

        try:
            data = json.loads(text) if text.strip() else {}
        except ValueError:
            return ApiResult(False, "响应不是合法 JSON", "server_error", None, status, latency_ms)
        if not isinstance(data, dict):
            data = {"data": data}

        code = str(data.get("code") or "")
        if code in ("A0230", "401", "403"):
            return ApiResult(False, data.get("msg") or data.get("message") or "登录已失效",
                             "login_expired", data, status, latency_ms)
        message = data.get("msg") or data.get("message") or ""
        if is_success_response(data):
            return ApiResult(True, message or "操作成功", "success", data.get("data"), status, latency_ms)
        return ApiResult(False, message, classify_failure(message), data.get("data"), status, latency_ms)

    def call_get(self, path: str, params: dict[str, Any] | None = None, **kw) -> ApiResult:
        """带异常归一的 GET（超时/断网也能拿到类别）。"""
        t0 = time.monotonic()
        try:
            with self.get(path, params, **kw) as resp:
                return self.parse(resp, t0)
        except Exception as exc:  # noqa: BLE001 - 网络层异常也要分类
            return self._classify_exception(exc, t0)

    def call_post(self, path: str, body: dict[str, Any] | None = None, **kw) -> ApiResult:
        t0 = time.monotonic()
        try:
            with self.post(path, body, **kw) as resp:
                return self.parse(resp, t0)
        except Exception as exc:  # noqa: BLE001
            return self._classify_exception(exc, t0)

    @staticmethod
    def _classify_exception(exc: Exception, t0: float) -> ApiResult:
        msg = str(exc).lower()
        cat = "timeout" if "timeout" in msg else "network_error" if "connection" in msg else "server_error"
        return ApiResult(False, str(exc), cat, None, 0, (time.monotonic() - t0) * 1000)


# ── 体育选课通道 ─────────────────────────────────────────────────

class SportClient(YhxtClient):
    """体育选课（`/sport/stu-physical-education-project/*`）。

    两级模型：教学班(course, teachId) → 单项(project, projId)。
    **选课操作只认 projId**，教学班编号仅用于展示/分组。
    """

    def _p(self, path: str) -> str:
        return f"{SPORT_API_PREFIX}{path}"

    # ── 元数据 ──

    def parameters(self, *, timeout: float = REQUEST_TIMEOUT) -> dict[str, Any]:
        """选课学期 + 开放窗口（startTime/endTime）。

        注意：窗口只用于**展示倒计时**，绝不能当硬门控——
        教务经常提前开放入口，本地按 startTime 判未开放会错过开抢。
        """
        result = self.call_get(self._p("/course-parameters"), timeout=timeout)
        return result.data if result.success else {}

    def list_courses(self, params: dict[str, Any] | None = None, *, timeout: float = REQUEST_TIMEOUT) -> list[dict[str, Any]]:
        """教学班列表。服务端按学生身份过滤，**返回数量少于实际可选**（实测 14 vs 22）。"""
        result = self.call_get(self._p("/course-list"), params or {}, timeout=timeout)
        items = result.data if result.success else []
        return items if isinstance(items, list) else []

    def list_projects(self, params: dict[str, Any] | None = None, *, timeout: float = REQUEST_TIMEOUT) -> list[dict[str, Any]]:
        """全部单项（不受学生身份过滤，实测 307 项 / 22 教学班）。"""
        result = self.call_get(self._p("/project-list"), params or {}, timeout=timeout)
        items = result.data if result.success else []
        return items if isinstance(items, list) else []

    def selection_status(self, *, timeout: float = REQUEST_TIMEOUT) -> list[dict[str, Any]]:
        """我的已选单项。"""
        result = self.call_get(self._p("/project-selection-status"), timeout=timeout)
        items = result.data if result.success else []
        return items if isinstance(items, list) else []

    def capacity(self, proj_ids: list[str], *, batch: int = 150, timeout: float = REQUEST_TIMEOUT) -> dict[str, dict[str, Any]]:
        """批量容量。单次 projIds 过多会 414 (URL Too Large)，必须分批。"""
        out: dict[str, dict[str, Any]] = {}
        for i in range(0, len(proj_ids), batch):
            chunk = proj_ids[i:i + batch]
            result = self.call_get(self._p("/project-capacity"), {"projIds": chunk}, timeout=timeout)
            items = result.data if result.success else []
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get("projId"):
                        out[str(item["projId"])] = item
        return out

    # ── 补全教学班（实测缺陷规避）─────────────────────────────────

    def full_courses(self, *, timeout: float = REQUEST_TIMEOUT) -> list[dict[str, Any]]:
        """course-list + project-list 合并出完整教学班集合。

        实测：course-list 只回 14 个教学班，但 project-list 覆盖 22 个
        （8 个教学班在 course-list 里根本不存在 → 用户看不到武术等课程）。
        缺失项用 project-list 每条记录自带的教学班冗余字段重建。
        """
        merged: dict[str, dict[str, Any]] = {}
        for course in self.list_courses(timeout=timeout):
            tid = str(course.get("teachId") or "")
            if tid:
                merged[tid] = course
        for project in self.list_projects(timeout=timeout):
            tid = str(project.get("teachId") or "")
            if not tid or tid in merged:
                continue
            merged[tid] = {
                key: project.get(key)
                for key in ("teachId", "courseCode", "courseName", "staffName",
                            "classTime", "classPlace", "campusName", "semester")
            }
        return list(merged.values())

    # ── 选课 / 退课 ──

    def select(self, proj_id: str, *, timeout: float = REQUEST_TIMEOUT) -> ApiResult:
        """选一个体育单项。projId 直接拼进 URL 路径。"""
        return self.call_post(self._p(f"/project/{proj_id}"), timeout=timeout)

    def drop(self, proj_id: str, *, timeout: float = REQUEST_TIMEOUT) -> ApiResult:
        """退课：真正的 `DELETE /project/<projId>`（`_j` 走 form body）。"""
        return self.call_delete(self._p(f"/project/{proj_id}"), timeout=timeout)

    # ── 开放探测（哨兵）──────────────────────────────────────────

    #: 哨兵 projId：不指向任何真实体育单项，服务端只可能返回时间/参数类错误，
    #: 因此探测无副作用（绝不会落地选课记录）。
    SENTINEL_PROJ_ID = "SPORT-PROBE-0000"

    def probe_selection_open(self, *, timeout: float = REQUEST_TIMEOUT) -> tuple[bool | None, str]:
        """无副作用探测选课窗口是否开放。

        返回 (已开放?, 说明)；`None` 表示无法判定（登录失效/网络抖动）。

        为什么不用本地时间判 startTime：教务会**提前**开放入口，
        本地时钟判定会让人错过黄金窗口。唯一可信的是服务端返回。

        为什么分类漏判时保守判「已开放」：两种误判的代价不对称——
        误判开放只是多发几个会被闸门拒掉的哨兵请求（无害），
        误判未开放则是整轮开抢窗口被错过（不可逆）。
        """
        result = self.select(self.SENTINEL_PROJ_ID, timeout=timeout)
        category = result.category
        if category == "not_open":
            return False, f"未开放：{result.message}"
        if category in ("login_expired", "timeout", "network_error", "server_error"):
            return None, f"无法判定（{category}）：{result.message}"
        # 时间闸门已放行（invalid_course/rejected/already_selected 等）
        return True, f"已开放（哨兵响应 {category}：{result.message}）"

    def reconcile_selected(self, proj_ids: list[str], *, timeout: float = REQUEST_TIMEOUT) -> set[str]:
        """核对哪些单项在服务端已是「已选」。

        用途：抢课时教务并发崩溃会大量 Read timeout——**请求其实已被受理，
        只是响应丢了**。只信响应会把成功当失败，反复重复选课。
        以容量/已选接口为权威源核对一次，即可纠正状态。
        """
        if not proj_ids:
            return set()
        selected: set[str] = set()
        for item in self.capacity(proj_ids, timeout=timeout).values():
            if item.get("hasSelected") or item.get("selected"):
                pid = str(item.get("projId") or "")
                if pid:
                    selected.add(pid)
        for item in self.selection_status(timeout=timeout):
            pid = str(item.get("projId") or "")
            if pid and (item.get("selected") or item.get("submitStatus") == 1):
                selected.add(pid)
        return selected


# ── 普通课程通道 ─────────────────────────────────────────────────

class CourseClient(YhxtClient):
    """普通课程（`/register/student-course/*`、`/course-selection/*`）。"""

    def my_courses(self, term_id: str, *, timeout: float = REQUEST_TIMEOUT) -> list[dict[str, Any]]:
        result = self.call_get("/register/student-course/info", {"termId": term_id}, timeout=timeout)
        items = result.data if result.success else []
        return items if isinstance(items, list) else []

    def search(self, teach_id: str, term_id: str, *, timeout: float = REQUEST_TIMEOUT) -> list[dict[str, Any]]:
        """按教学班编号搜索 → 解析真实 teachId（普通课必须两步）。

        与体育不同：普通课用户输入的编号 ≠ 选课接口要的真实编号。
        """
        result = self.call_get("/student-course-list/search",
                               {"teachId": teach_id, "termId": term_id}, timeout=timeout)
        items = result.data if result.success else []
        return items if isinstance(items, list) else []

    def select(self, real_teach_id: str, term_id: str, *,
               ignore_time_conflict: bool = True, timeout: float = REQUEST_TIMEOUT) -> ApiResult:
        body = {
            "termId": term_id,
            "teachId": real_teach_id,
            "ignoreTimeConflict": ignore_time_conflict,
            "courseSelectionClient": "web",
        }
        return self.call_post("/course-selection/select", body, timeout=timeout)

    def capacity(self, teach_ids: list[str], *, batch: int = 100, timeout: float = REQUEST_TIMEOUT) -> dict[str, dict[str, Any]]:
        """批量容量：返回 {teachId: {studentNumber, fullNumber, hasApplied, hasSelected}}。"""
        out: dict[str, dict[str, Any]] = {}
        for i in range(0, len(teach_ids), batch):
            chunk = teach_ids[i:i + batch]
            result = self.call_get("/student-course-list/course-capacity",
                                   {"teachIds": ",".join(chunk)}, timeout=timeout)
            items = result.data if result.success else []
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get("teachId"):
                        out[str(item["teachId"])] = item
        return out


__all__ = [
    "ApiResult",
    "CourseClient",
    "SportClient",
    "YhxtClient",
    "classify_failure",
    "encrypt_params",
    "http_outcome",
    "is_success_response",
    "sm2_available",
    "sm2_encrypt",
]
