# Stop SC-200 Server PowerShell Script
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "               Stopping SC-200 Master Assessment Server                    " -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

$connections = Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue

if ($connections) {
    foreach ($conn in $connections) {
        $pidToKill = $conn.OwningProcess
        Write-Host "[+] Terminating process PID $pidToKill listening on port 8080..." -ForegroundColor Green
        Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[+] SC-200 Server stopped successfully." -ForegroundColor Green
} else {
    Write-Host "[!] No active server found listening on port 8080." -ForegroundColor Yellow
}
