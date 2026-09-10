# SWJTU_Login

SWJTU CAS and Academic System login toolkit.

This repository maintains login implementations for Southwest Jiaotong University and hands the resulting
authenticated session state to Python code for later academic-system requests.

It now covers **both academic systems**:

| System | Host | Auth artifact | Used for |
| --- | --- | --- | --- |
| Legacy JWC (`vatuu`) | `jwc.swjtu.edu.cn` | session cookie | score query, transcript, legacy `UserLoadingAction` APIs |
| **YHXT (`yethan`)** | `yhxt.swjtu.edu.cn` | **`ytoken` (JWT)** | **2026 course enrollment, including the PE/sport two-level model** |

## Branch Overview

| Branch | Purpose | Best For |
| --- | --- | --- |
| `request` | Pure `requests` implementation that talks directly to CAS / JWC / YHXT endpoints | Lightweight HTTP-only login, OCR-based CAPTCHA handling, terminal-based MFA submission, high-concurrency enrollment |
| `playwright` | Real-browser login that exports a reusable `requests.Session` | Device trust, complex MFA, frontend-heavy login flows, or cross-project session reuse |

The default branch is `request`, so this README serves both as the repository overview and as the usage guide
for the `request` branch.

## Which Branch Should You Use?

Choose `request` first if:

- You want a lightweight HTTP-only login flow
- You prefer fewer dependencies and faster startup
- Your project mainly sends direct `requests` calls and does not need a browser
- You need enrollment traffic that survives the registrar collapsing under concurrency

Choose `playwright` first if:

- CAS frontend logic changes frequently
- Device trust or MFA depends on a real browser context
- You want to separate login from later high-concurrency `requests` workloads

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
- `gmssl` (SM2 for the YHXT channel, pure Python — no Node.js required)

## Quick Start: Legacy JWC

```bash
python login.py your_student_id your_password
```

```python
from login import SWJTUAssessor

client = SWJTUAssessor("your_student_id", "your_password")  # target defaults to "jwc"
assert client.login()

resp = client.session.get(f"{client.JWC_BASE}/vatuu/UserLoadingAction", timeout=10)
print(resp.status_code)
```

## Quick Start: YHXT Enrollment Channel

The enrollment system is a **different backend**. Login must therefore send CAS back to the `yethan`
service, which is what makes the server issue the `ytoken` cookie:

```python
from login import SWJTUAssessor

client = SWJTUAssessor("your_student_id", "your_password", target="yhxt")
assert client.login()

sport = client.sport_client()      # SportClient, already authenticated
course = client.course_client()    # CourseClient

print(sport.parameters())          # term + enrollment window (display only, see caveat below)
for p in sport.list_projects()[:5]:
    print(p["projId"], p.get("courseName"), p.get("staffName"))
```

Command line:

```bash
python login.py your_student_id your_password --target yhxt
```

Credentials may also come from `SWJTU_USERNAME` / `SWJTU_PASSWORD` so they never land in shell history.

## YHXT Channel Notes (field-tested)

These are the behaviours that cost real debugging time during the 2026 enrollment season. The code encodes
all of them; keep them in mind when extending.

### 1. Request encryption: one `_j` field

Every YHXT business request wraps its parameters as:

```json
{"_t": <epoch ms>, "_d": {<params>}}
```

then SM2-encrypts that JSON and sends the ciphertext hex as the single `_j` field
(GET → query string, POST/DELETE → form body).

`sm2_encrypt()` reproduces the frontend's custom ciphertext layout byte for byte:

```
04 || C1 || SM3(x2 || message || y2) || C2      (97 + len(message) bytes)
```

Do **not** shortcut this by calling `gmssl.CryptSM2.encrypt()` directly: gmssl emits standard `C1C3C2` with a
different KDF call site, and the registrar rejects it. Only gmssl's low-level primitives (point multiply
`_kg` plus `sm3_hash`) are used, with the layout assembled by hand. The previous implementation shelled out
to `node sm2_encrypt.js`; the pure-Python port removed that dependency entirely, so a packed binary no
longer needs Node.js on the target machine.

SM2 key material is pure-Python big-integer point multiplication and therefore **holds the GIL**. Running it
in a thread pool still freezes an asyncio event loop (measured 78 ms stalls). If you drive enrollment from
asyncio, run encryption in a **process pool** — that dropped the heartbeat stall to ~21 ms.

### 2. PE/sport is a two-level model

```
teaching course (teachId)  ->  PE project (projId)
```

**Enrollment is keyed by `projId`.** `teachId` is only useful for display and grouping.

### 3. `course-list` under-reports — use `full_courses()`

Measured: `course-list` returned 14 teaching courses while `project-list` covered 22. Eight courses (including
martial arts) simply do not appear in `course-list`, so a UI built on it silently hides selectable options.
`full_courses()` merges both sources and rebuilds missing entries from the course fields that
`project-list` denormalizes onto every project row.

### 4. Batch capacity requests

`project-capacity` takes `projIds` in the query string. Sending all 307 projects at once triggers
`414 URL Too Large`, hence the `batch=150` default in `SportClient.capacity()` and `batch=100` in
`CourseClient.capacity()`.

### 5. Never gate on `startTime` — probe instead

The registrar opens the endpoint **earlier** than the advertised window. Trusting a local clock against
`startTime` means missing the golden moment. `probe_selection_open()` sends a sentinel `projId`
(`SPORT-PROBE-0000`, which cannot match any real project, so it has no side effects) and reads the server's
own answer:

- `not_open` → window still closed
- anything past the time gate (`invalid_course`, `rejected`, `course_full`, …) → open
- `login_expired` / `timeout` / network errors → `None` (undecidable, retry next poll)

When the classifier is unsure, the probe errs toward "open": a false "open" costs a few harmless rejected
sentinel requests, while a false "closed" costs the entire enrollment window.

### 6. Timeouts often mean success — reconcile, don't blindly retry

Under enrollment-season load the registrar collapses and a large share of select calls return
`Read timeout`, yet **many of those requests were already accepted server-side**; only the response was
lost. Acting on the response alone treats them as failures and re-submits, which can double-book.

`reconcile_selected()` fixes the state from authoritative sources instead — `project-capacity.hasSelected`
plus `project-selection-status` — and returns the set of `projId`s the server already considers selected.
The production engine uses the per-round capacity pre-check as this authority: whenever a course comes back
with `hasSelected`/`hasApplied`, it is marked selected and dropped from the queue regardless of whether it
is full, so a timed-out-but-successful request self-heals on the next round with zero extra endpoint pressure.

### 7. Error text is the contract, and matching is order-sensitive

`code`/`success` alone is not enough — the useful semantics live in Chinese `msg` text. Substring matching
must be ordered: the real "window not open" text is `当前不在体育单项选课时间内`, and a shorter pattern
such as `不在选课时间` misses it, silently mis-classifying a retryable condition as a hard rejection.
`classify_failure()` keeps the specific PE wording ahead of the general ones.

### 8. Cookies must travel with the token

YHXT performs a same-domain session check. Presenting `ytoken` without the login-phase cookies gets you back
to the login page (which the client reports as `login_expired` via the HTML-body sniff in `http_outcome`).
`SportClient`/`CourseClient` therefore accept a `cookies=[...]` list, and `client.sport_client()` passes the
live session through so no state is lost.

## API Surface

`yhxt.py`:

| Object | Highlights |
| --- | --- |
| `sm2_encrypt(plaintext)` / `encrypt_params(params)` | SM2 `_j` construction, `sm2_available()` to feature-detect gmssl |
| `classify_failure(msg)` / `http_outcome(status, body, ctype)` / `is_success_response(data)` | response contract layer |
| `YhxtClient` | session + `ytoken` header, encrypted GET/POST/DELETE, `ApiResult` normalization |
| `SportClient` | `parameters`, `list_courses`, `list_projects`, `full_courses`, `capacity`, `selection_status`, `select`, `drop`, `probe_selection_open`, `reconcile_selected` |
| `CourseClient` | `my_courses`, `search`, `select`, `capacity` |

`ApiResult` carries `success`, `message`, `category`, `data`, `http_status`, `latency_ms` — so retries can be
driven by `RETRYABLE_CATEGORIES` instead of by parsing strings again.

## `request` Branch Login Flow

1. Open the CAS login page and collect hidden fields plus the password encryption salt.
2. Check whether a picture CAPTCHA is required.
3. If needed, download the CAPTCHA image and try OCR recognition.
4. Encrypt the password using the same frontend-compatible AES logic.
5. Submit the login form against `service` = JWC `UserLoginForWiseduAction` or YHXT `public/cas/tms`.
6. If MFA is triggered, choose a method in the terminal and enter the received code.
7. Follow the CAS ticket redirect and establish the target system's session.
8. Save cookies per target (`account/<username>/cookies-<target>.pkl`) for reuse; JWC and YHXT session
   validity are not interchangeable, so they never share one cache file.

## Notes

- CAPTCHA OCR is best-effort and may occasionally require a retry.
- If the university changes CAS fields, frontend encryption, or endpoint behaviour, this branch may need updates.
- `SM2_PUBLIC_KEY_HEX` is the frontend-hardcoded enrollment public key; re-extract it if the frontend rotates.
- If device trust or MFA becomes more dependent on a real browser context, switch to the `playwright` branch.

## Good Fit For

- Course enrollment, PE project enrollment, course query, score query, and other request-driven scripts
- Projects that want to send concurrent HTTP requests directly with `requests`
- Environments where browser automation — or Node.js — is unnecessary

## `playwright` Branch Entry

```bash
git clone -b playwright https://github.com/AmaneSuzuha000/SWJTU_Login.git
```

Or inside an existing clone:

```bash
git checkout playwright
```

That branch completes login in a real browser and exports a reusable `requests.Session`, which is more
suitable for cross-project login tooling.
