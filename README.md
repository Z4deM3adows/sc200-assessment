# SC-200 Master Assessment Platform
**Enterprise Scaling & Pearson VUE AI Simulator**

An advanced, dual-mode certification practice platform designed for Security Operations Analysts preparing for the Microsoft SC-200 exam.

## 🚀 Features

The platform operates in two distinct modes to support both foundational learning and high-pressure exam simulation:

### 1. Active Revision Mode (Triage)
* **Targeted Practice**: Select specific domains (e.g., Defender XDR, Copilot for Security) to focus your study.
* **Instant Feedback**: Get immediate results after answering a question.
* **KQL Deep Dives**: Expandable drawers show exactly why an answer is correct, with KQL queries and real-world SoC scenarios.
* **Read Aloud Assist**: Use the built-in Text-to-Speech engine to listen to long explanations.

### 2. Pearson VUE Real Exam Simulator
* **Authentic Experience**: A strict 50-question simulation pulled from a strictly segregated 500-question databank (100 questions per domain).
* **AI Webcam Invigilator**: Simulates WebRTC-based test center proctoring. Tracks tab-switching, gaze, and issues "strikes" to simulate testing rules.
* **Anti-Cheat Lock**: Disables copy-pasting, right-clicking, and text selection.
* **Post-Exam Diagnostics**: Only provides answers and deep analysis *after* the exam is submitted, grading you on a 1000-point scale.

## 📦 Prerequisites

* Python 3.9+ 
* A modern web browser (Edge/Chrome recommended for WebRTC camera & Speech API support).
* Camera/Webcam (required for Pearson VUE Simulation mode).

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Z4deM3adows/sc200-assessment.git
   cd sc200-assessment
   ```

2. **Start the backend server:**
   You can either run the Python server directly or use the provided batch file (Windows).
   ```bash
   # Option 1 (Windows)
   start.bat

   # Option 2 (Manual)
   python server.py
   ```
   *The server will initialize the SQLite database (`sc200_database.sqlite`) on first run.*

3. **Open the platform:**
   Navigate to `http://localhost:8080` in your browser.

4. **Login:**
   Use the default test account:
   * **Email**: `analyst@soc.microsoft.com`
   * **Password**: `SC200Pass2026!`

## 📊 Question Bank Architecture

The system ships with a massive, strictly categorized 500-question bank (`sc200_questions.js`). There is absolutely no mix-matching; each domain contains exactly 100 unique scenario-based questions:
* Microsoft Defender XDR (100)
* Microsoft Copilot for Security (100)
* Microsoft Purview (100)
* Microsoft Defender for Endpoint (100)
* Microsoft Defender for Cloud (100)

## 🔍 Architecture Notes

* **Frontend**: Vanilla HTML/JS/CSS. No complex build tools required.
* **Backend**: Python 3 standard library `http.server` with an SQLite3 data layer.
* **Analytics**: All diagnostic scores, times, and AI proctor strikes are persisted locally in `sc200_database.sqlite` for review on the Master Hub dashboard.
