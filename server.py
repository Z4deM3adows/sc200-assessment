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
import time

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(DIRECTORY, "sc200_database.sqlite")

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def init_sqlite_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS proctor_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
                       ("analyst@soc.microsoft.com", hash_password("SC200Pass2026!"), "Security Analyst", "student"))
        cursor.execute("INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
                       ("admin@soc.microsoft.com", hash_password("MasterAdmin2026!"), "SOC Lead Administrator", "admin"))
        print("[+] Created default user & admin accounts in SQLite.")

    cursor.execute("SELECT COUNT(*) FROM questions")
    if cursor.fetchone()[0] == 0:
        js_file = os.path.join(DIRECTORY, "sc200_questions.js")
        if os.path.exists(js_file):
            try:
                with open(js_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    json_str = content.split('const SC200_QUESTIONS = ')[1].split(';\n\nif (typeof window')[0]
                    questions_data = json.loads(json_str)
                    
                    for q in questions_data:
                        cursor.execute('''
                            INSERT INTO questions (id, exam_code, module, topic, scenario, question, options, correct_index, audio_summary, explanation)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            q['id'], 'SC-200', q['module'], q['topic'], q['scenario'], q['question'],
                            json.dumps(q['options']), q['correctIndex'], q['audioSummary'], json.dumps(q['explanation'])
                        ))
                    print(f"[+] Successfully loaded {len(questions_data)} questions into SQLite database.")
            except Exception as e:
                print(f"[!] Warning: Could not auto-populate SQLite questions: {e}")

    conn.commit()
    conn.close()

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

            self._send_json({"success": True, "message": "Exam session saved to SQLite."})
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

        elif path == '/api/questions/random':
            modules = query.get('modules', ['xdr'])
            limit = int(query.get('limit', ['10'])[0])
            
            # STRICT DOMAIN ISOLATION AT DATABASE LEVEL
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
