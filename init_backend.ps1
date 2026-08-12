# SC-200 Master Assessment Console - PowerShell Initializer
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "      Microsoft Security Operations Platform Master Assessment (SC-200)   " -ForegroundColor Cyber
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptPath

Write-Host "[+] Starting server at $scriptPath ..." -ForegroundColor Green

if (Get-Command python -ErrorAction SilentlyContinue) {
    python server.py
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    python3 server.py
} else {
    Write-Host "[!] Python not found. Opening index.html directly in browser..." -ForegroundColor Yellow
    Start-Process "index.html"
}
