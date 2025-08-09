### CyberGuard Penetration Testing Platform - Backend

## Overview

This is the backend for the **CyberGuard Automated Penetration Testing Platform**. It provides a comprehensive suite of APIs for web vulnerability scanning, device/network scanning, OSINT, phone number intelligence, AI chatbot support and file/report management. Built with Flask, the platform is designed for both ease of use and extensibility.

-----

## Key Features

  - **Web Vulnerability Scanning:** Leverages OWASP ZAP to actively identify vulnerabilities in web applications.
  - **Reconnaissance:** Includes OSINT tools for gathering public information based on usernames and phone numbers.
  - **Network Mapping:** Provides device and network scanning functionalities to discover open ports and active hosts.
  - **Audit Gallery:** A secure system for uploading, managing, and downloading security audit documents.
  - **Report Generation:** Creates detailed reports from scan results in multiple formats, including custom dark and light themes.

-----

## Prerequisites

To run the entire application, **Docker** and **Docker Compose** are highly recommended. This setup automates the process of running both the Python backend and the OWASP ZAP daemon.

  - **Docker:** [Installation Guide](https://docs.docker.com/get-docker/)
  - **Docker Compose:** [Installation Guide](https://docs.docker.com/compose/install/)

-----

## Setup & Running the Application

The recommended method for running the application is to use Docker Compose. This single command will handle everything.

### 1\. Clone the Project

To get started, clone the project from the GitHub repository:

```sh
git clone https://github.com/haroonallahdad/CyberGuard-Audit-FYP-Project
cd "FYP Coding File (CyberGuard Audit)"
```

### 2\. Build and Run

From the project's root folder, execute this single command in your terminal. Docker will automatically build your backend image and start both the backend and the ZAP daemon.

```sh
docker compose up
```

### 3\. Access the Application

The application will be live at `http://localhost:5000`. The Flask backend is configured to serve the `mainpage.html` file, so no separate live server is needed for the frontend.

-----

## Troubleshooting

  - **Docker Errors:** Ensure that both Docker and Docker Compose are correctly installed and running.
  - **Port Conflicts:** If ports 5000 or 8080 are already in use, you can modify the port mappings in the `docker-compose.yml` file.
  - **Missing Folders:** The backend is designed to automatically create necessary folders (`uploads/`, `reports/`, and `templates/`) if they are missing on startup.

-----

## Credits

  - **Authors:** Haroon Allahdad
  - **University:** International Islamic University Islamabad
  - **Project:** Final Year Project
