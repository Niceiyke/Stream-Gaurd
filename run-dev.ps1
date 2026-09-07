# StreamGuard local dev run: opens two (or three) windows and starts everything.
# Usage (from the repo root):  .\run-dev.ps1
# Add -Shell and -Token to also launch the visual status window with the
# bootstrap ticket printed by the service, e.g.:
#   .\run-dev.ps1 -Shell -Token eyJ...    (first run shows you the ticket)

param([switch]$Shell, [string]$Token)

$secret  = 'dev-secret'
$certDir = Join-Path $env:TEMP 'sgcert-test'
$root    = Split-Path -Parent $MyInvocation.MyCommand.Path

# Shared env prefix injected into each window.
$envPrefix = "`$env:STREAMGUARD_DEV='1'; `$env:STREAMGUARD_SECRET='$secret'; " +
             "`$env:STREAMGUARD_CERT_DIR='$certDir'; `$env:RUST_LOG='info'; "

# Terminal 1 - gateway (first, so it mints the cert.der the service needs).
$gateCmd = "$envPrefix cargo run -p streamguard-gateway"
Start-Process powershell -WorkingDirectory $root -ArgumentList '-NoExit', '-Command', $gateCmd | Out-Null
"Gateway window opened - waiting for it to mint certs... "
Start-Sleep -Seconds 8

# Terminal 2 - service.
$svcCmd = "$envPrefix `$env:STREAMGUARD_ADDR='127.0.0.1:12423'; cargo run -p streamguard-service"
Start-Process powershell -WorkingDirectory $root -ArgumentList '-NoExit', '-Command', $svcCmd | Out-Null
"Service window opened."
"Note: the service prints 'dev status-shell ticket: <ticket>' - use it for the -Shell window."

# Terminal 3 - optional visual status shell.
if ($Shell) {
    if ([string]::IsNullOrWhiteSpace($Token)) {
        "Shell requested but no -Token given. Re-run with -Token <ticket> from the service window."
    }
    else {
        Start-Process powershell -WorkingDirectory (Join-Path $root 'desktop') -ArgumentList '-NoExit', '-Command',
            "cargo tauri dev -- --pipe \\.\pipe\streamguard-status --token $Token" | Out-Null
        "Status shell window opened (token: $Token)."
    }
}

"Done. Windows are filling build logs; to stop, Ctrl-C in each window."