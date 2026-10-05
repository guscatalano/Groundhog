# Groundhog bootstrap: fetch the agent and apply a Groundhogfile, in one line.
#
#   & ([scriptblock]::Create((irm https://github.com/guscatalano/Groundhog/releases/latest/download/apply.ps1))) https://example.com/dev.groundhog.yaml
#
# Everything after the script goes to `groundhog-agent apply` as it is: the Groundhogfile
# (a path, URL, zip or groundhog:NAME) and any options, such as --reboot, --var NAME=VALUE or
# --sha256 <hash>. The script:
#   - picks the agent for this machine's architecture (x64 or ARM64),
#   - downloads it from the release this script belongs to and checks its SHA-256 against
#     that release's agent.json before running it,
#   - asks for elevation if it doesn't have it (the agent changes machine-wide settings),
#   - runs the apply and exits with the agent's exit code (3010: a restart is needed; add
#     --reboot to restart and continue by itself).

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Stamped by the release workflow, so this script always fetches its own release's agent.
$version = '__GROUNDHOG_VERSION__'
$release = "https://github.com/guscatalano/Groundhog/releases/download/v$version"

# Set when this script relaunched itself elevated in a window of its own.
$relaunched = $args.Count -gt 0 -and $args[0] -eq '--groundhog-relaunched'
if ($relaunched) { $args = @($args | Select-Object -Skip 1) }

# In its own window, an error would vanish with the window; show it first.
trap {
    if ($relaunched) {
        Write-Host "error: $_" -ForegroundColor Red
        Read-Host 'Press Enter to close' | Out-Null
        exit 1
    }
    break
}

# Hand back an exit code without closing the caller's console: `exit` inside a script block
# run from an interactive prompt would end that whole PowerShell session.
function Finish([int]$code) {
    if ($relaunched) {
        Read-Host 'Done. Press Enter to close' | Out-Null
        exit $code
    }
    $global:LASTEXITCODE = $code
}

if ($args.Count -eq 0) {
    Write-Host "usage: & ([scriptblock]::Create((irm $release/apply.ps1))) <Groundhogfile path, URL or groundhog:NAME> [agent options]"
    return
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    # Run this same script elevated (it arrived as text, so save it first) and wait for it.
    $self = Join-Path $env:TEMP "groundhog-apply-$version.ps1"
    Set-Content -Path $self -Value $MyInvocation.MyCommand.ScriptBlock.ToString() -Encoding UTF8
    $quoted = $args | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }
    Write-Host 'Groundhog needs administrator rights; asking for them...'
    $p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList (
        @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$self`"", '--groundhog-relaunched') + $quoted)
    Finish $p.ExitCode
    return
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$arch = switch ($arch) { 'ARM64' { 'arm64' } 'AMD64' { 'x64' } default { throw "Groundhog has no agent for $arch" } }

$manifest = Invoke-RestMethod "$release/agent.json"
$entry = $manifest.agents.$arch
if (-not $entry) { throw "release v$version has no $arch agent" }

$exe = Join-Path $env:TEMP "groundhog-agent-$version-$arch.exe"
Invoke-WebRequest "$release/$($entry.file)" -OutFile $exe -UseBasicParsing
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $entry.sha256.ToLowerInvariant()) {
    Remove-Item $exe -Force
    throw "the downloaded agent doesn't match release v${version}: SHA-256 $hash, expected $($entry.sha256)"
}

Write-Host "groundhog-agent $version ($arch), SHA-256 checked"
& $exe apply @args
Finish $LASTEXITCODE
