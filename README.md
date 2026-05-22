# SWJTU_Login

SWJTU CAS and Academic System login toolkit.

This repository currently maintains two implementations with the same goal: complete CAS login for Southwest Jiaotong University and hand the resulting authenticated session state to Python code for later academic-system requests.

## Branch Overview

| Branch | Purpose | Best For |
| --- | --- | --- |
| `request` | Pure `requests` implementation that talks directly to CAS and JWC endpoints | Lightweight HTTP-only login, OCR-based CAPTCHA handling, terminal-based MFA submission |
| `playwright` | Real-browser login that exports a reusable `requests.Session` | Device trust, complex MFA, frontend-heavy login flows, or cross-project session reuse |

The default branch is `request`, so this README serves both as the repository overview and as the usage guide for the `request` branch.

## Which Branch Should You Use?

Choose `request` first if:

- You want a lightweight HTTP-only login flow
- You prefer fewer dependencies and faster startup
- Your project mainly sends direct `requests` calls and does not need a browser

Choose `playwright` first if:

- CAS frontend logic changes frequently
- Device trust or MFA depends on a real browser context
- You want to separate login from later high-concurrency `requests` workloads

## `request` Branch Features

- Automatic CAS and academic-system protocol detection
- Fetches login page fields such as `execution`, `lt`, and `pwdEncryptSalt`
- AES-CBC-PKCS7 password encryption compatible with the school frontend logic
- Automatic CAPTCHA requirement detection
- CAPTCHA recognition using `ddddocr`
- Terminal-based MFA method selection and verification code input
- CAS Ticket redirect handling and academic-system session initialization
- Local cookie reuse through `account/<username>/cookies.pkl`

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
   ├─ cookies.pkl
   └─ config.json
```

## Installation

```bash
git clone -b request https://github.com/AmaneSuzuha000/SWJTU_Login.git
cd SWJTU_Login
pip install -r requirements.txt
```

Dependencies:

- `requests`
- `beautifulsoup4`
- `pycryptodome`
- `ddddocr`
- `pillow`

## Quick Start

Run directly:

```bash
python login.py
```

Or use it as a module:

```python
from login import SWJTUAssessor

client = SWJTUAssessor("your_student_id", "your_password")
success = client.login()
print("Login result:", success)
```

After login succeeds, you can continue using `client.session`:

```python
resp = client.session.get(
    f"{client.JWC_BASE}/vatuu/UserLoadingAction",
    timeout=10,
)
print(resp.status_code)
```

## `request` Branch Login Flow

1. Open the CAS login page and collect hidden fields plus the password encryption salt.
2. Check whether a picture CAPTCHA is required.
3. If needed, download the CAPTCHA image and try OCR recognition.
4. Encrypt the password using the same frontend-compatible AES logic.
5. Submit the login form.
6. If MFA is triggered, choose a method in the terminal and enter the received code.
7. Follow the CAS Ticket redirect and establish the academic-system session.
8. Save cookies for future reuse.

## Good Fit For

- Course enrollment, course query, score query, and other request-driven scripts
- Projects that want to send concurrent HTTP requests directly with `requests`
- Environments where browser automation is unnecessary

## Notes

- CAPTCHA OCR is best-effort and may occasionally require a retry.
- If the university changes CAS fields, frontend encryption, or endpoint behavior, this branch may need updates.
- If device trust or MFA becomes more dependent on a real browser context, switch to the `playwright` branch.

## `playwright` Branch Entry

To use the real-browser implementation:

```bash
git clone -b playwright https://github.com/AmaneSuzuha000/SWJTU_Login.git
```

Or inside an existing clone:

```bash
git checkout playwright
```

That branch completes login in a real browser and exports a reusable `requests.Session`, which is more suitable for cross-project login tooling.
