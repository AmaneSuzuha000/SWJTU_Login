# SWJTU_Login · `playwright` Branch

This branch provides the browser-driven login implementation.

Instead of trying to reproduce every detail of the CAS flow at the raw HTTP layer, it uses a real Chromium browser through Playwright to complete SWJTU CAS login, MFA, and device-trust steps, then exports the authenticated state as a reusable `requests.Session`.

If you want the repository overview or the pure `requests` implementation, see the default `request` branch.

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
- Exports login state as `AuthState`
- Restores `AuthState` into a standard `requests.Session`
- Supports saving `auth_state.json` for reuse by other projects

## Project Structure

```text
SWJTU_Login/
├─ login.py
├─ requirements.txt
└─ README.md
```

Files generated after running:

```text
account/
└─ <username>/
   ├─ auth_state.json
   └─ playwright_profile/
```

Meaning:

- `auth_state.json`: exported authenticated state that can be restored into `requests.Session`
- `playwright_profile/`: persistent Playwright browser profile directory for reusing the browser login environment

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

## Quick Start

Run directly:

```bash
python login.py
```

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

client = SWJTUAssessor(
    username="your_student_id",
    password="your_password",
    headless=False,
)

ok = client.login(save_auth_state=True)
print("Login success:", ok)

session = client.get_session()
auth_state = client.export_auth_state()
```

### Option 3: Restore from saved authenticated state

```python
from login import SWJTUAssessor

client = SWJTUAssessor(
    username="your_student_id",
    password="your_password",
    headless=False,
)

ok = client.restore_session()
print("Restore result:", ok)

session = client.get_session()
```

## Recommended Login Flow

1. The script launches a real browser and opens the CAS login page.
2. It automatically fills the username and password.
3. If a CAPTCHA or slider appears, complete it manually in the browser.
4. If MFA is triggered, the terminal will show the available methods.
5. Enter the MFA method number in the terminal.
6. The script switches the method and triggers code delivery automatically.
7. Enter the received MFA code in the terminal.
8. If the device-trust prompt appears, the script accepts it automatically.
9. The script exports both `requests.Session` and `auth_state.json`.

## Integrating with Other Projects

This branch is especially useful if login should be packaged as a standalone tool and reused elsewhere.

Typical workflow:

1. Complete browser login once in this project.
2. Save `account/<username>/auth_state.json`.
3. Load `AuthState` in another project.
4. Build a new `requests.Session` with `build_requests_session()`.
5. Create one independent Session per thread or worker for concurrent request workloads.

Example:

```python
from login import AuthState, build_requests_session

auth_state = AuthState.load("account/2025110724/auth_state.json")
session = build_requests_session(auth_state)
```

## Good Fit For

- Login flows that depend on a real browser environment
- Cases where device trust and MFA need to behave more like a real user session
- Projects that want to separate login from business requests
- Tools that need to reuse the authenticated state in other scripts or services

## Notes

- This branch still follows the real school login flow and does not skip actual authentication.
- Picture CAPTCHA or slider challenges may still require manual completion in the browser.
- `playwright_profile` and `auth_state.json` contain sensitive login state and should be stored carefully.
- For concurrent business requests, do not share a single `requests.Session` directly across threads. Build one Session per worker instead.
