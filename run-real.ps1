# StreamGuard REAL run: real NICs, real per-path binding, real Wintun adapters.
# This is the opposite of run-dev.ps1 - no STREAMGUARD_DEV, no loopback:
#   - per-NIC QUIC sockets (IP_UNICAST_IF on the default-route interface)
#   - real TUN adapters on both ends (Wintun, loaded from wintun.dll)
#   - the service dials STREAMGUARD_ADDR over your LAN / the internet, so the
#     reported kbps is the real bandwidth-delay estimate over that NIC
# Usage (from the repo root):
#   .\run-real.ps1                same-host real test (gateway + client here)
#   .\run-real.ps1 -Shell         also open the status dashboard window
#   .\run-real.ps1 -GatewayAddr 203.0.113.5:12423      remote gateway (VPS)
#   .\run-real.ps1 -NoFirewall    skip adding the inbound UDP firewall rule
#
# Requirements / notes:
#   - Needs ADMIN (UAC prompt): per-NIC socket binding and Wintun both require
#     elevation. The script re-launches itself elevated automatically.
#   - wintun.dll comes from the gitignored wintun-0.14.1.zip in the repo root
#     (download from https://www.wintun.net/builds/wintun-0.14.1.zip if missing).
#   - SAME-HOST caveat: traffic to your own LAN IP is delivered internally by
#     Windows, so kbps on a same-host run will NOT reflect your ISP uplink.
#     For real per-interface kbps + failover run the gateway on a SEPARATE host
#     (a Linux VPS is the spec topology) and pass -GatewayAddr <vps>:12423,
#     with STREAMGUARD_CERT_DIR on the client pointing at sgcerts/cert.der.
#   - Repeated runs leave old "streamguard" Wintun adapters in Network
#     Connections; remove them from time to time (Remove-NetAdapter).
#   - A real deployment uses a strong STREAMGUARD_SECRET, not 'dev-secret'.

param(
    [switch]$Shell,
    [string]$Token,
    [string]$GatewayAddr = '',
    [switch]$NoFirewall
)

$ErrorActionPreference = 'Stop'
$root    = Split-Path -Parent $MyInvocation.MyCommand.Path
$secret  = 'dev-secret'
$certDir = Join-Path $root 'sgcerts'
$wintunZip = Join-Path $root 'wintun-0.14.1.zip'
$wintunDll = Join-Path $root 'wintun.dll'

# --- Elevate: IP_UNICAST_IF binding + Wintun need an admin shell. ----------
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($id)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    "run-real.ps1 needs Administrator (per-NIC socket binding + Wintun). Re-launching elevated..."
    $invoke = @('-NoExit', '-ExecutionPolicy', 'Bypass', '-File', $MyInvocation.MyCommand.Path)
    if ($Shell)    { $invoke += '-Shell' }
    if ($Token)    { $invoke += @('-Token', $Token) }
    if ($GatewayAddr) { $invoke += @('-GatewayAddr', $GatewayAddr) }
    if ($NoFirewall)   { $invoke += '-NoFirewall' }
    Start-Process powershell -Verb RunAs -WorkingDirectory $root -ArgumentList $invoke
    exit
}

# --- wintun.dll (gitignored artifact committed only as the zip) ------------
if (-not (Test-Path -LiteralPath $wintunDll)) {
    if (-not (Test-Path -LiteralPath $wintunZip)) {
        "wintun-0.14.1.zip missing; download it from https://www.wintun.net/builds/wintun-0.14.1.zip into $root"
        exit 1
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($wintunZip)
    try {
        $entry = $zip.Entries | Where-Object { $_.FullName -eq 'wintun/bin/amd64/wintun.dll' }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $wintunDll, $true)
    } finally { $zip.Dispose() }
    "extracted $wintunDll"
}

# --- Build both binaries with the real TUN backend --------------------------
"Building gateway + service with sg-tun/native-tun (Wintun)..."
Push-Location $root
try {
    cargo build -p streamguard-gateway -p streamguard-service --features sg-tun/native-tun 2>&1 | ForEach-Object { $_ }
    if ($LASTEXITCODE -ne 0) { "build failed (see errors above)"; exit 1 }
} finally { Pop-Location }

# --- Default gateway address = this host's LAN IP (overridable) -------------
if ([string]::IsNullOrWhiteSpace($GatewayAddr)) {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1
    if ($route) {
        $ip = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($ip) { $GatewayAddr = $ip.IPAddress }
    }
}
if ([string]::IsNullOrWhiteSpace($GatewayAddr)) {
    "cannot determine the gateway address; pass -GatewayAddr <host>:<port> (e.g. -GatewayAddr 192.168.1.5:12423)"
    exit 1
}
if ($GatewayAddr -notmatch ':') { $GatewayAddr = "$GatewayAddr`:12423" }

# --- Inbound UDP rule for remote clients (same-host packets also pass) ------
$port = [int](($GatewayAddr -split ':')[-1])
if (-not $NoFirewall) {
    $existing = Get-NetFirewallRule -DisplayName 'StreamGuard gateway QUIC' -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName 'StreamGuard gateway QUIC' -Direction Inbound -Protocol UDP -LocalPort $port -Action Allow | Out-Null
        "firewall: allowed inbound UDP $port"
    }
}

"Gateway address: $GatewayAddr  (same-host real test; real uplink kbps needs a remote gateway)"

# Shared env prefix - NOTE there is deliberately NO STREAMGUARD_DEV here.
$envPrefix = "`$env:STREAMGUARD_SECRET='$secret'; `$env:STREAMGUARD_CERT_DIR='$certDir'; " +
             "`$env:STREAMGUARD_TUN_ADDR='10.0.85.1'; `$env:STREAMGUARD_PRINT_TICKET='1'; " +
             "`$env:WINTUN_DLL='$wintunDll'; `$env:RUST_LOG='info'; "

# Terminal 1 - gateway (first: mints sgcerts/cert.der + key.der on first run).
$gateCmd = "$envPrefix cargo run -p streamguard-gateway"
Start-Process powershell -WorkingDirectory $root -ArgumentList '-NoExit', '-Command', $gateCmd | Out-Null
"Gateway window opened - waiting for it to mint certs... "
Start-Sleep -Seconds 10

# Terminal 2 - service: dials the gateway over the real NIC, its own TUN side.
$svcCmd = "$envPrefix `$env:STREAMGUARD_TUN_ADDR='10.0.85.2'; " +
          "`$env:STREAMGUARD_ADDR='$GatewayAddr'; cargo run -p streamguard-service"
Start-Process powershell -WorkingDirectory $root -ArgumentList '-NoExit', '-Command', $svcCmd | Out-Null
"Service window opened (bound paths, real TUN, real kbps)."

# Terminal 3 - optional status shell (reads the TEMP ticket the service drops
# because STREAMGUARD_PRINT_TICKET=1; identical to run-dev.ps1 -Shell).
if ($Shell) {
    $tf = Join-Path $env:TEMP 'streamguard-dev-ticket.txt'
    $ticket = ''; $prefix = ''
    if ((Test-Path -LiteralPath $tf) -and -not [string]::IsNullOrWhiteSpace($Token)) {
        $ticket = $Token
    }
    elseif (Test-Path -LiteralPath $tf) {
        $parts = @((Get-Content -LiteralPath $tf -Raw) -split "`r?`n")
        $ticket = $parts[0].Trim()
        $prefix = $parts[1].Trim()
    }
    if ([string]::IsNullOrWhiteSpace($ticket)) {
        "Shell requested but no ticket found - start the service first, then re-run with -Shell."
    }
    else {
        if ([string]::IsNullOrWhiteSpace($prefix)) { $prefix = '0x00000000' }
        Start-Process powershell -WorkingDirectory (Join-Path $root 'desktop') -ArgumentList '-NoExit', '-Command',
            "`$env:STREAMGUARD_STATUS_PIPE='\\.\pipe\streamguard-status'; " +
            "`$env:STREAMGUARD_TOKEN='$ticket'; " +
            "`$env:STREAMGUARD_SESSION_PREFIX='0x$prefix'; tauri dev" | Out-Null
        "Status shell window opened."
    }
}

"Done. Windows are filling build logs; to stop, Ctrl-C in each window."
"Remember: same-host runs loop packets internally - for real per-NIC kbps and live unplug failover, point -GatewayAddr at a separate host (Linux VPS) and copy sgcerts/cert.der to it."