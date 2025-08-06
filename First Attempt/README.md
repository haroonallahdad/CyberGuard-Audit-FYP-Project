# CyberGuard Penetration Testing Platform - Backend

## Overview
This is the backend for the CyberGuard Automated Penetration Testing Platform. It provides APIs for web vulnerability scanning (using OWASP ZAP), device/network scanning, OSINT, phone number intelligence, and file/report management. Built with Flask for easy deployment and extensibility.

---

## Prerequisites
- **Python 3.8+** (recommended: Python 3.10 or newer)
- **pip** (Python package manager)
- **Kali Linux** (or any Linux with Python 3)
- (Optional) **OWASP ZAP** running locally for web scanning features

---

## Setup Instructions

### 1. Clone or Copy the Project
If you have a zip, extract it. If using git:
```sh
git clone <your-repo-url>
cd "FYP Coding File (ZAP Not working)/First Attempt/backend"
```

### 2. Create a Virtual Environment
```sh
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```sh
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. (Optional) Start OWASP ZAP
- Start ZAP on your machine (default: http://127.0.0.1:8080)
- Make sure the API key in `app.py` matches your ZAP API key (default is set, but you can change it via environment variable `ZAP_API_KEY`)

### 5. Run the Backend
```sh
python app.py
```
- The backend will start on http://127.0.0.1:5000

---

## How to Use
- **Frontend:** Open `mainpage.html` in your browser (usually via Live Server or by double-clicking).
- **API Endpoints:** The backend provides endpoints for:
  - Web scanning (ZAP)
  - Device/network scanning
  - OSINT username checks
  - Phone number intelligence
  - File upload/download/gallery
- **Reports:** Generated reports are saved in the `reports/` folder and visible in the frontend gallery.

---

## Troubleshooting
- **pip install errors:** Make sure you are in the `.venv` (see prompt: `(.venv)`), and using `pip` from the venv.
- **ZAP not working:** Ensure ZAP is running and accessible at `127.0.0.1:8080`.
- **Port conflicts:** If port 5000 is in use, change it in `app.py`.
- **Missing folders:** The backend auto-creates `uploads/`, `reports/`, and `templates/` if missing.
- **API key issues:** Set your ZAP API key as an environment variable: `export ZAP_API_KEY=yourkey` before running.

---

## Credits
- **Authors:** Haroon Allahdad & Khyam Javed
- **University:** International Islamic University Islamabad
- **Project:** Final Year Project

For questions or help, contact the authors or open an issue in your repository. 