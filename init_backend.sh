#!/usr/bin/env bash
# SC-200 Master Assessment Backend Initializer & Web Server Launcher

echo "=========================================================================="
echo "      Microsoft Security Operations Platform Master Assessment (SC-200)   "
echo "=========================================================================="
echo ""

PORT=8080
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[+] Initializing backend server in: ${APP_DIR}"
echo "[+] Starting local HTTP server on port ${PORT}..."

if command -v python3 &>/dev/null; then
    echo "[+] Using Python 3 HTTP Server..."
    (sleep 1 && (xdg-open "http://localhost:${PORT}" 2>/dev/null || open "http://localhost:${PORT}" 2>/dev/null || start "http://localhost:${PORT}" 2>/dev/null)) &
    python3 -m http.server ${PORT} --directory "${APP_DIR}"
elif command -v python &>/dev/null; then
    echo "[+] Using Python HTTP Server..."
    (sleep 1 && (xdg-open "http://localhost:${PORT}" 2>/dev/null || open "http://localhost:${PORT}" 2>/dev/null || start "http://localhost:${PORT}" 2>/dev/null)) &
    python -m http.server ${PORT} --directory "${APP_DIR}"
elif command -v npx &>/dev/null; then
    echo "[+] Using Node npx serve..."
    npx -y serve "${APP_DIR}" -l ${PORT}
else
    echo "[-] Error: Neither Python nor Node.js found in PATH."
    echo "[!] You can open index.html directly in your web browser:"
    echo "    file://${APP_DIR}/index.html"
fi
