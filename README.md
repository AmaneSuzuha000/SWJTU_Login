# SWJTU Assessor Login Tool

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)

A Python tool to log in to the **Southwest Jiaotong University (SWJTU) CAS system** and establish a session with the university's academic system (JWC).  

Features:

- Automatic detection of CAS and JWC HTTPS/HTTP protocols
- AES-CBC-PKCS7 password encryption compatible with the front-end CryptoJS
- Dynamic CAPTCHA support using [ddddocr](https://github.com/sml2h3/ddddocr)
- Extracts login error messages automatically

---

## Features

### Core Functionality

1. **CAS Login**
    - Fetch login page parameters (`execution`, `lt`, `pwdEncryptSalt`)
    - Check if CAPTCHA is required
    - Download CAPTCHA image and recognize it automatically with OCR
    - Encrypt password using AES and submit the login form

2. **JWC Academic System Session**
    - Follow CAS Ticket redirect
    - Establish a valid session in the academic system

3. **Error Handling**
    - Automatically extracts error messages from `<span id="showErrorTip">` when login fails

---

## Dependencies

requests

beautifulsoup4

pycryptodome

ddddocr

Pillow

---

## Structrue
├── login.py

├── README.md

├── requirements.txt


---

## Installation

```bash
git clone https://github.com/AmaneSuzuha000/SWJTU_Login.git
cd SWJTU_Login
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt
python login.py


