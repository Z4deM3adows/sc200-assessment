# Microsoft Security Operations Platform Master Assessment Engine (SC-200)

![SC-200 Certified](https://img.shields.io/badge/Microsoft_Certification-SC--200-00f0ff?style=for-the-badge&logo=microsoft)
![Questions](https://img.shields.io/badge/Practice_Questions-500_Scenarios-10b981?style=for-the-badge)
![Database](https://img.shields.io/badge/Database-SQLite_Builtin-3b82f6?style=for-the-badge&logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-f97316?style=for-the-badge)
![CI](https://img.shields.io/badge/GitHub_Actions-CI_Verified-a855f7?style=for-the-badge&logo=githubactions)

The **Microsoft Security Operations Platform Master Assessment Engine (SC-200)** is an open-source, enterprise-grade certification practice platform engineered to rival commercial exam simulators like MeasureUp, Whizlabs, and Kaplan IT.

It features **500 scenario-based practice questions (100 per domain)**, a **WebRTC AI Camera Invigilator with Anti-Cheat Tab Lock & Copy Protection**, **SQLite Database persistence**, **User Authentication**, and **Web Speech API audio explanations**.

---

## 🌟 Key Features

- 🎯 **500 High-Yield Scenario Questions** (100 questions per topic for Defender XDR, Security Copilot, Purview, MDE, and MDC).
- 💡 **In-Depth Option Analysis**: Explains **Why the Right Choice is Correct AND What is Wrong with Each Distractor**.
- 📹 **WebRTC AI Camera Invigilator**: Real-time webcam vision HUD with a 3-strike warning system.
- 🔒 **Anti-Cheat Engine**: Prevents tab switching, browser minimizing, right-clicking, and text copying during exam mode.
- 🗄️ **SQLite Persistence**: Stores accounts, sessions, analytics history, and proctoring logs in `sc200_database.sqlite`.
- 🗣️ **Web Speech Audio Engine**: Spoken scenario summaries and rationales.
- 📊 **Multi-Exam Master Hub**: Active SC-200 track with AZ-500 & SC-100 preview cards.

---

## 🚀 Quick Start Guide

### Option 1: Native Windows Launch
```cmd
cd sc200-assessment
start.bat
```
*Or double-click `start.bat` in File Explorer.*

### Option 2: Linux & macOS Launch
```bash
cd sc200-assessment
chmod +x init_backend.sh
./init_backend.sh
# OR run python directly:
python3 server.py
```

### Option 3: Docker Container Launch
```bash
cd sc200-assessment
docker-compose up -d
```
*Open your browser to http://localhost:8080*

---

## 🔑 Pre-Configured Demo Credentials

| Role | Email | Password |
|---|---|---|
| **Student Analyst** | `analyst@soc.microsoft.com` | `SC200Pass2026!` |
| **SOC Admin** | `admin@soc.microsoft.com` | `MasterAdmin2026!` |

---

## 📤 How to Push This Repository to GitHub

To host this repository on GitHub under your account:

```bash
# 1. Initialize Git Repository
git init

# 2. Add files and make initial commit
git add .
git commit -m "Initial commit: Enterprise SC-200 Master Assessment Engine"

# 3. Rename branch to main
git branch -M main

# 4. Connect to your GitHub repository (replace with your repo URL)
git remote add origin https://github.com/YOUR_USERNAME/sc200-master-assessment.git

# 5. Push code to GitHub
git push -u origin main
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
