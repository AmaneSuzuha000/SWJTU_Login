# SWJTU_Login · `playwright` Branch

This branch provides the browser-driven login implementation.

Instead of trying to reproduce every detail of the CAS flow at the raw HTTP layer, it uses a real Chromium browser through Playwright to complete SWJTU CAS login, MFA, and device-trust steps, then exports the authenticated state as a reusable `requests.Session`.

It covers **both academic systems**:

| System | Host | Auth artifact | `target` value |
| --- | --- | --- | --- |
| Legacy JWC (`vatuu`) | `jwc.swjtu.edu.cn` | session cookie | `"jwc"` (default) |
| **YHXT (`yethan`)** | `yhxt.swjtu.edu.cn` | **`ytoken` (JWT)** | `"yhxt"` |

If you want the repository overview or the pure `requests` implementation, see the default `request` branch.

## Why Use A Real Browser For Enrollment

The 2026 enrollment system sits behind CAS plus a device-trust step that a raw HTTP client cannot satisfy
reliably. This branch completes the genuine flow in Chromium, then hands a normal `requests.Session` to your
business code — so login robustness and request throughput are decoupled.

## What This Branch Solves

Compared with a direct HTTP login flow, this branch is better when:

- CAS frontend logic changes often
- Device trust depends on a real browser context
- The MFA page needs real page-state inspection
- Login should be separated from later high-concurrency `requests` workloads

## Main Features

- Launches a real Chromium persistent context with Playwright
- Automatically fills the username and password
- Detects whether the login page currently requires a picture CAPTCHA
- Prompts the user to complete CAPTCHA or slider challenges in the browser when needed
- Detects whether the flow enters an MFA page
- Lists the currently available MFA methods in the terminal
- Switches the MFA method based on terminal input and triggers code delivery automatically
- Accepts the MFA code from terminal input and submits it automatically
- Automatically chooses "trust this device" when the device-trust prompt appears
- Exports login state as `AuthState` (now including `ytoken` and `target`)
- Restores `AuthState` into a standard `requests.Session`
- Supports saving `auth_state-<target>.json` for reuse by other projects
- `target="yhxt"`: points the CAS service at `yethan`, waits for the `ytoken` cookie, and hands back ready-made
  enrollment clients

## Project Structure

```text
SWJTU_Login/
├─ login.py          # browser login + AuthState -> requests.Session
├─ yhxt.py           # YHXT (yethan) channel client, pure-Python SM2
├─ requirements.txt
└─ README.md
```

Files generated after running:

```text
account/
└─ <username>/
   ├─ auth_state-jwc.json
   ├─ auth_state-yhxt.json
   └─ playwright_profile/
```

State is cached **per target** on purpose: a valid JWC session does not imply a valid `ytoken`, and sharing
one file makes the restore path wrongly report "still valid". A pre-rename `auth_state.json` is still picked
up as a fallback.

## Installation

```bash
git clone -b playwright https://github.com/AmaneSuzuha000/SWJTU_Login.git
cd SWJTU_Login
pip install -r requirements.txt
playwright install chromium
```

Dependencies:

- `requests`
- `playwright`
- `beautifulsoup4`
- `pycryptodome`
- `ddddocr`
- `pillow`
- `gmssl` (SM2 for the YHXT channel — pure Python, no Node.js)

## Quick Start

```bash
# legacy JWC
python login.py your_student_id

# YHXT enrollment channel (prints ytoken, then queries enrollment parameters)
python login.py your_student_id --target yhxt
```

The password is requested interactively (`getpass`), or supplied via `SWJTU_PASSWORD`, so it never has to
appear in source code or shell history.

## Use as a Module

### Option 1: Get a ready-to-use `requests.Session`

```python
from login import login_and_get_session

session = login_and_get_session(
    username="your_student_id",
    password="your_password",
    headless=False,
    save_auth_state=True,
)

resp = session.get("http://jwc.swjtu.edu.cn/vatuu/UserLoadingAction", timeout=10)
print(resp.status_code)
```

### Option 2: Use `SWJTUAssessor`

```python
from login import SWJTUAssessor

client = SWJTUAssessor("your_student_id", "your_password", headless=False)

ok = client.login(save_auth_state=True)
print("Login success:", ok)

session = client.get_session()
auth_state = client.export_auth_state()
```

### Option 3: Restore from saved authenticated state

```python
from login import SWJTUAssessor

client = SWJTUAssessor("your_student_id", "your_password", target="yhxt")

ok = client.restore_session()      # no browser needed if the token is still alive
print("Restore result:", ok)

session = client.get_session()
```

### Option 4: Enroll in PE projects

```python
from login import SWJTUAssessor

client = SWJTUAssessor("your_student_id", "your_password", target="yhxt")
assert client.login()

sport = client.sport_client()          # authenticated with ytoken + cookies

# The window is opened server-side earlier than startTime — never gate on the local clock.
print(sport.probe_selection_open())    # (True/False/None, detail)

# course-list under-reports; full_courses() merges project-list to recover the rest
projects = {(p["projId"], p.get("courseName")) for p in sport.list_projects()}
print(len(sport.full_courses()), "teaching courses")

result = sport.select("<projId>")
print(result.success, result.category, f"{result.latency_ms:.0f}ms")
```

## YHXT-Specific Behaviour

`yhxt.py` documents the full contract. The parts that depend on browser login are:

- **`ytoken` is the only success signal.** Leaving the CAS login page is not enough: device-trust pages and
  ticket-redirect intermediates also live under the same host, and the token has not been written yet.
  `login()` therefore polls the cookie jar (`_wait_for_ytoken`) and revisits the service URL if the browser
  has left CAS without producing a token.
- **Cookies must accompany the token.** YHXT performs a same-domain session check, so `build_requests_session()`
  injects `Origin`/`Referer` plus the `ytoken` header for `target="yhxt"`.
- **Verification is a real call.** `yhxt_session_ready()` probes `common/test-arrange` instead of guessing at
  cookie expiry; JWC and YHXT use completely different readiness endpoints, so `SWJTUAssessor._ready()`
  dispatches on target.
- **SM2 `_j` encryption is pure Python.** It reproduces the frontend layout `04||C1||SM3(x2||M||y2)||C2`
  using only gmssl primitives; calling `CryptSM2.encrypt()` directly yields standard `C1C3C2`, which the
  registrar rejects. It also holds the GIL, so under asyncio run it in a **process pool**, not a thread pool.
- **Read timeouts often mean success.** When the registrar collapses under enrollment load, many accepted
  requests still time out. `reconcile_selected()` re-reads authoritative state from `project-capacity` and
  `project-selection-status` instead of treating them as failures and double-booking.

## Recommended Login Flow

1. The script launches a real browser and opens the CAS login page for the selected `service`.
2. It automatically fills the username and password.
3. If a CAPTCHA or slider appears, complete it manually in the browser.
4. If MFA is triggered, the terminal will show the available methods.
5. Enter the MFA method number in the terminal.
6. The script switches the method and triggers code delivery automatically.
7. If the device-trust prompt appears, the script accepts it automatically.
8. For `--target yhxt`, the script waits until the `ytoken` cookie actually appears.
9. The script exports `requests.Session` plus `account/<username>/auth_state-<target>.json`.

## Integrating with Other Projects

This branch is especially useful if login should be packaged as a standalone tool and reused elsewhere.

Typical workflow:

1. Complete browser login once in this project.
2. Save `account/<username>/auth_state-<target>.json`.
3. Load `AuthState` in another project.
4. Build a new `requests.Session` with `build_requests_session()`.
5. Create one independent Session per thread or worker for concurrent request workloads.

Example:

```python
from login import AuthState, build_requests_session

auth_state = AuthState.load("account/<your_student_id>/auth_state-yhxt.json")
session = build_requests_session(auth_state)
```

## Good Fit For

- Course and PE project enrollment under registrar-scale concurrency
- Login flows that depend on a real browser environment
- Cases where device trust and MFA need to behave more like a real user session
- Projects that want to separate login from business requests
- Tools that need to reuse the authenticated state in other scripts or services

## Notes

- This branch still follows the real school login flow and does not skip actual authentication.
- Picture CAPTCHA or slider challenges may still require manual completion in the browser.
- `playwright_profile/` and `auth_state-*.json` contain live credentials. `.gitignore` excludes `account/` —
  never commit or publish them, and treat any leaked student ID in docs or logs as a credential.
- For concurrent business requests, do not share a single `requests.Session` directly across threads. Build
  one Session per worker instead.
- `SM2_PUBLIC_KEY_HEX` in `yhxt.py` is the frontend-hardcoded enrollment public key; re-extract it if the
  frontend rotates it.
