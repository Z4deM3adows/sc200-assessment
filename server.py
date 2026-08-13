import http.server
import socketserver
import webbrowser
import os
import sys
import signal
import sqlite3
import json
import urllib.parse
import hashlib
import re
import time
import uuid
import random

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(DIRECTORY, "sc200_database.sqlite")

# Blueprint-weighted module distribution for the 50-question Pearson VUE exam.
# These are placeholder proportions -- Microsoft doesn't publish per-product
# weights under the current SC-200 blueprint, so this approximates emphasis.
MODULE_WEIGHTS = {
    "xdr": 0.30,      # Defender XDR
    "mde": 0.25,      # Defender for Endpoint
    "mdc": 0.20,      # Defender for Cloud
    "purview": 0.15,  # Microsoft Purview
    "copilot": 0.10,  # Copilot for Security
}

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def init_sqlite_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Questions Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS questions (
            id TEXT PRIMARY KEY,
            exam_code TEXT NOT NULL,
            module TEXT NOT NULL,
            topic TEXT NOT NULL,
            scenario TEXT NOT NULL,
            question TEXT NOT NULL,
            options TEXT NOT NULL,
            correct_index INTEGER NOT NULL,
            audio_summary TEXT NOT NULL,
            explanation TEXT NOT NULL
        )
    ''')

    # Practice Sessions Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS exam_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            exam_code TEXT NOT NULL,
            mode TEXT NOT NULL,
            score INTEGER NOT NULL,
            passed INTEGER NOT NULL,
            total_questions INTEGER NOT NULL,
            correct_questions INTEGER NOT NULL,
            domain_stats TEXT NOT NULL,
            proctor_strikes INTEGER DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Pearson VUE Real Exam Simulation Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pearson_exams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            exam_code TEXT NOT NULL,
            score INTEGER NOT NULL,
            passed INTEGER NOT NULL,
            total_questions INTEGER NOT NULL,
            correct_questions INTEGER NOT NULL,
            domain_stats TEXT NOT NULL,
            user_answers TEXT NOT NULL,
            proctor_strikes INTEGER DEFAULT 0,
            time_spent_seconds INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Pearson VUE Live Session Table (server-side answer key never sent to client)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pearson_sessions (
            session_id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            exam_code TEXT NOT NULL,
            question_ids TEXT NOT NULL,
            answer_key TEXT NOT NULL,
            explanation_key TEXT NOT NULL,
            module_key TEXT NOT NULL,
            duration_seconds INTEGER NOT NULL,
            started_at INTEGER NOT NULL,
            submitted INTEGER DEFAULT 0
        )
    ''')

    # Proctor Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS proctor_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # System Meta Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')

    # Default Users
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
                       ("analyst@soc.microsoft.com", hash_password("SC200Pass2026!"), "Security Analyst", "student"))
        cursor.execute("INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
                       ("admin@soc.microsoft.com", hash_password("MasterAdmin2026!"), "SOC Lead Administrator", "admin"))
        print("[+] Created default user & admin accounts in SQLite.")

    # Rebuild questions table from sc200_questions.js ONLY if modified
    js_file = os.path.join(DIRECTORY, "sc200_questions.js")
    if os.path.exists(js_file):
        current_mtime = str(os.path.getmtime(js_file))
        cursor.execute("SELECT value FROM system_meta WHERE key = 'questions_js_mtime'")
        row = cursor.fetchone()
        stored_mtime = row[0] if row else None

        if stored_mtime != current_mtime:
            print("[+] sc200_questions.js has changed (or first run). Rebuilding SQLite questions table...")
            cursor.execute("DELETE FROM questions")
            try:
                with open(js_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    match = re.search(r"const\s+SC200_QUESTIONS\s*=\s*(\[[\s\S]*?\]);\s*const", content)
                    if not match:
                        match = re.search(r"const\s+SC200_QUESTIONS\s*=\s*(\[[\s\S]*?\]);", content)
                    if match:
                        json_str = match.group(1)
                        questions_data = json.loads(json_str)
                        
                        for q in questions_data:
                            cursor.execute('''
                                INSERT INTO questions (id, exam_code, module, topic, scenario, question, options, correct_index, audio_summary, explanation)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                q.get('id', ''), 'SC-200', q.get('module', ''), q.get('topic', ''), q.get('scenario', ''), q.get('question', ''),
                                json.dumps(q.get('options', [])), q.get('correctIndex', 0), q.get('audioSummary', ''), json.dumps(q.get('explanation', {}))
                            ))
                        
                        cursor.execute("INSERT OR REPLACE INTO system_meta (key, value) VALUES (?, ?)", ('questions_js_mtime', current_mtime))
                        print(f"[+] Successfully loaded {len(questions_data)} questions into SQLite database.")
            except Exception as e:
                print(f"[!] Warning: Could not auto-populate SQLite questions: {e}")
        else:
            print("[+] Question bank is up to date (no JS changes detected). Skipping rebuild.")

    conn.commit()
    conn.close()

def build_weighted_question_set(total_questions=50):
    """Samples questions per MODULE_WEIGHTS using the largest-remainder method
    so a 50-question exam lands on an authentic blueprint-weighted split."""
    raw = {mod: w * total_questions for mod, w in MODULE_WEIGHTS.items()}
    base = {mod: int(v) for mod, v in raw.items()}
    remainder = total_questions - sum(base.values())
    by_remainder = sorted(raw.items(), key=lambda kv: kv[1] - int(kv[1]), reverse=True)
    for i in range(remainder):
        base[by_remainder[i % len(by_remainder)][0]] += 1

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    selected = []
    for mod, count in base.items():
        if count <= 0:
            continue
        cursor.execute('''
            SELECT id, exam_code, module, topic, scenario, question, options, correct_index, audio_summary, explanation
            FROM questions WHERE module = ? ORDER BY RANDOM() LIMIT ?
        ''', (mod, count))
        for r in cursor.fetchall():
            selected.append({
                "id": r[0], "examCode": r[1], "module": r[2], "topic": r[3],
                "scenario": r[4], "question": r[5], "options": json.loads(r[6]),
                "correctIndex": r[7], "audioSummary": r[8], "explanation": json.loads(r[9])
            })
    conn.close()
    random.shuffle(selected)
    return selected

init_sqlite_db()

class RESTHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        
        try:
            body = json.loads(post_data.decode('utf-8'))
        except Exception:
            body = {}

        path = self.path

        if path == '/api/login':
            email = body.get('email', '').strip().lower()
            password = body.get('password', '')
            pwd_hash = hash_password(password)

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT email, full_name, role FROM users WHERE LOWER(email) = ? AND password_hash = ?", (email, pwd_hash))
            user = cursor.fetchone()
            conn.close()

            if user:
                token = f"token_{int(time.time())}_{user[0]}"
                self._send_json({
                    "success": True,
                    "user": {"email": user[0], "fullName": user[1], "role": user[2]},
                    "token": token
                })
            else:
                self._send_json({"success": False, "error": "Invalid email or password."}, status=401)
            return

        elif path == '/api/register':
            email = body.get('email', '').strip().lower()
            password = body.get('password', '')
            full_name = body.get('fullName', 'Security Practitioner')

            if not email or not password:
                self._send_json({"success": False, "error": "Email and password are required."}, status=400)
                return

            pwd_hash = hash_password(password)
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, 'student')",
                               (email, pwd_hash, full_name))
                conn.commit()
                conn.close()
                token = f"token_{int(time.time())}_{email}"
                self._send_json({
                    "success": True,
                    "user": {"email": email, "fullName": full_name, "role": "student"},
                    "token": token
                })
            except sqlite3.IntegrityError:
                conn.close()
                self._send_json({"success": False, "error": "An account with this email already exists."}, status=400)
            return

        elif path == '/api/session/submit':
            email = body.get('userEmail', 'guest@soc.microsoft.com')
            exam_code = body.get('examCode', 'SC-200')
            mode = body.get('mode', 'practice')
            score = body.get('score', 0)
            passed = 1 if score >= 700 else 0
            total_q = body.get('totalQuestions', 0)
            correct_q = body.get('correctQuestions', 0)
            domain_stats = json.dumps(body.get('domainStats', {}))
            strikes = body.get('proctorStrikes', 0)

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO exam_sessions (user_email, exam_code, mode, score, passed, total_questions, correct_questions, domain_stats, proctor_strikes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (email, exam_code, mode, score, passed, total_q, correct_q, domain_stats, strikes))
            conn.commit()
            conn.close()

            self._send_json({"success": True, "message": "Practice session saved to SQLite."})
            return

        elif path == '/api/pearson/start':
            email = body.get('userEmail', 'guest@soc.microsoft.com')
            exam_code = body.get('examCode', 'SC-200')
            total_q = body.get('totalQuestions', 50)

            full_questions = build_weighted_question_set(total_q)
            if not full_questions:
                self._send_json({"success": False, "error": "Question bank is empty or not loaded yet."}, status=400)
                return

            session_id = str(uuid.uuid4())
            question_ids = [q['id'] for q in full_questions]
            answer_key = {q['id']: q['correctIndex'] for q in full_questions}
            explanation_key = {q['id']: q['explanation'] for q in full_questions}
            module_key = {q['id']: q['module'] for q in full_questions}
            duration_seconds = 100 * 60
            started_at = int(time.time())

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO pearson_sessions (session_id, user_email, exam_code, question_ids, answer_key, explanation_key, module_key, duration_seconds, started_at, submitted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            ''', (session_id, email, exam_code, json.dumps(question_ids), json.dumps(answer_key),
                  json.dumps(explanation_key), json.dumps(module_key), duration_seconds, started_at))
            conn.commit()
            conn.close()

            # Strip correctIndex/explanation -- the client never sees the answer key.
            sanitized = [{k: v for k, v in q.items() if k not in ('correctIndex', 'explanation')} for q in full_questions]

            self._send_json({
                "success": True,
                "sessionId": session_id,
                "questions": sanitized,
                "serverStartTime": started_at,
                "durationSeconds": duration_seconds
            })
            return

        elif path == '/api/pearson/submit':
            session_id = body.get('sessionId', '')
            email = body.get('userEmail', 'guest@soc.microsoft.com')
            user_answers = body.get('userAnswers', {})
            strikes = body.get('proctorStrikes', 0)

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_email, exam_code, question_ids, answer_key, explanation_key, module_key, duration_seconds, started_at, submitted
                FROM pearson_sessions WHERE session_id = ?
            ''', (session_id,))
            row = cursor.fetchone()

            if not row or row[0] != email:
                conn.close()
                self._send_json({"success": False, "error": "Exam session not found."}, status=404)
                return

            _, exam_code, question_ids_json, answer_key_json, explanation_key_json, module_key_json, duration_seconds, started_at, submitted = row

            if submitted:
                conn.close()
                self._send_json({"success": False, "error": "This exam has already been submitted."}, status=400)
                return

            question_ids = json.loads(question_ids_json)
            answer_key = json.loads(answer_key_json)
            explanation_key = json.loads(explanation_key_json)
            module_key = json.loads(module_key_json)

            time_spent = max(0, min(int(time.time()) - started_at, duration_seconds))

            correct_count = 0
            domain_stats = {}
            review = {}
            for qid in question_ids:
                mod = module_key.get(qid, 'unknown')
                domain_stats.setdefault(mod, {"correct": 0, "total": 0})
                domain_stats[mod]["total"] += 1

                correct_idx = answer_key.get(qid)
                user_idx = user_answers.get(qid)
                if user_idx is not None and user_idx == correct_idx:
                    correct_count += 1
                    domain_stats[mod]["correct"] += 1

                review[qid] = {"correctIndex": correct_idx, "explanation": explanation_key.get(qid, {})}

            total_q = len(question_ids)
            score = round((correct_count / total_q) * 1000) if total_q else 0
            passed = 1 if score >= 700 else 0

            cursor.execute("UPDATE pearson_sessions SET submitted = 1 WHERE session_id = ?", (session_id,))
            cursor.execute('''
                INSERT INTO pearson_exams (user_email, exam_code, score, passed, total_questions, correct_questions, domain_stats, user_answers, proctor_strikes, time_spent_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (email, exam_code, score, passed, total_q, correct_count, json.dumps(domain_stats),
                  json.dumps(user_answers), strikes, time_spent))
            conn.commit()
            conn.close()

            self._send_json({
                "success": True,
                "score": score,
                "passed": bool(passed),
                "totalQuestions": total_q,
                "correctQuestions": correct_count,
                "timeSpentSeconds": time_spent,
                "domainStats": domain_stats,
                "review": review
            })
            return

        elif path == '/api/proctor/log':
            email = body.get('userEmail', 'guest@soc.microsoft.com')
            event_type = body.get('eventType', 'WARNING')
            details = body.get('details', '')

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO proctor_logs (user_email, event_type, details) VALUES (?, ?, ?)",
                           (email, event_type, details))
            conn.commit()
            conn.close()

            self._send_json({"success": True})
            return

        super().do_POST()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == '/api/user/analytics':
            email = query.get('email', ['guest@soc.microsoft.com'])[0]
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT score, passed, total_questions, correct_questions, proctor_strikes, timestamp
                FROM exam_sessions WHERE user_email = ? ORDER BY id DESC LIMIT 10
            ''', (email,))
            rows = cursor.fetchall()
            conn.close()

            history = []
            for r in rows:
                history.append({
                    "score": r[0], "passed": bool(r[1]), "total": r[2], "correct": r[3],
                    "strikes": r[4], "timestamp": r[5]
                })

            self._send_json({"success": True, "history": history})
            return

        elif path == '/api/pearson/history':
            email = query.get('email', ['guest@soc.microsoft.com'])[0]
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT score, passed, total_questions, correct_questions, proctor_strikes, time_spent_seconds, timestamp
                FROM pearson_exams WHERE user_email = ? ORDER BY id DESC LIMIT 10
            ''', (email,))
            rows = cursor.fetchall()
            conn.close()

            history = []
            for r in rows:
                history.append({
                    "score": r[0], "passed": bool(r[1]), "total": r[2], "correct": r[3],
                    "strikes": r[4], "timeSpent": r[5], "timestamp": r[6]
                })

            self._send_json({"success": True, "history": history})
            return

        elif path == '/api/pearson/session':
            session_id = query.get('sessionId', [''])[0]
            email = query.get('email', [''])[0]

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_email, question_ids, duration_seconds, started_at, submitted
                FROM pearson_sessions WHERE session_id = ?
            ''', (session_id,))
            row = cursor.fetchone()

            if not row or row[0] != email:
                conn.close()
                self._send_json({"success": False, "error": "Session not found."}, status=404)
                return

            _, question_ids_json, duration_seconds, started_at, submitted = row
            if submitted:
                conn.close()
                self._send_json({"success": True, "submitted": True})
                return

            question_ids = json.loads(question_ids_json)
            placeholders = ','.join(['?'] * len(question_ids))
            cursor.execute(f'''
                SELECT id, exam_code, module, topic, scenario, question, options, audio_summary
                FROM questions WHERE id IN ({placeholders})
            ''', question_ids)
            by_id = {r[0]: r for r in cursor.fetchall()}
            conn.close()

            questions = []
            for qid in question_ids:
                r = by_id.get(qid)
                if not r:
                    continue
                questions.append({
                    "id": r[0], "examCode": r[1], "module": r[2], "topic": r[3],
                    "scenario": r[4], "question": r[5], "options": json.loads(r[6]),
                    "audioSummary": r[7]
                })

            elapsed = int(time.time()) - started_at
            remaining = max(0, duration_seconds - elapsed)

            self._send_json({
                "success": True,
                "submitted": False,
                "questions": questions,
                "durationSeconds": duration_seconds,
                "remainingSeconds": remaining
            })
            return

        elif path == '/api/questions/random':
            modules = query.get('modules', ['xdr'])
            limit = int(query.get('limit', ['10'])[0])
            
            placeholders = ','.join(['?'] * len(modules))
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(f'''
                SELECT id, exam_code, module, topic, scenario, question, options, correct_index, audio_summary, explanation
                FROM questions WHERE module IN ({placeholders}) ORDER BY RANDOM() LIMIT ?
            ''', (*modules, limit))
            rows = cursor.fetchall()
            conn.close()

            questions = []
            for r in rows:
                questions.append({
                    "id": r[0], "examCode": r[1], "module": r[2], "topic": r[3],
                    "scenario": r[4], "question": r[5], "options": json.loads(r[6]),
                    "correctIndex": r[7], "audioSummary": r[8], "explanation": json.loads(r[9])
                })

            self._send_json({"success": True, "questions": questions})
            return

        super().do_GET()

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

print(f"==========================================================================")
print(f"      Microsoft Security Operations Platform Master Assessment (SC-200)   ")
print(f"==========================================================================")
print(f"[+] SQLite Database initialized at: {DB_FILE}")
print(f"[+] Pearson VUE Real Exam Simulation API Active")
print(f"[+] Starting local HTTP server on http://localhost:{PORT}")
print(f"[+] Default User:  analyst@soc.microsoft.com  / SC200Pass2026!")
print(f"[+] Default Admin: admin@soc.microsoft.com    / MasterAdmin2026!")
print(f"[+] Press Ctrl+C at any time to STOP the server cleanly.")

webbrowser.open(f"http://localhost:{PORT}")

httpd = ReusableTCPServer(("", PORT), RESTHandler)

def signal_handler(sig, frame):
    print("\n[+] Stopping server cleanly...")
    try:
        httpd.shutdown()
        httpd.server_close()
    except Exception:
        pass
    print("[+] Server closed. Exiting.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

try:
    httpd.serve_forever()
except Exception:
    signal_handler(None, None)