<#
.SYNOPSIS
    Starts the KryptonFS demo: 3 storage nodes, an encrypted volume, and the
    Krypton Console in your browser, inside Docker. Usually run through run.cmd.

.EXAMPLE
    .\run.cmd             start (or restart) the demo and open the console in the browser
    .\run.cmd -Console    open the console again
    .\run.cmd -Dashboard  open the terminal dashboard instead
    .\run.cmd -Shell      open a Linux shell in the running demo (files: /mnt/krypton)
    .\run.cmd -Stop       stop the demo
    .\run.cmd -Port 8090  publish the console on another port
#>
param([switch]$Shell, [switch]$Dashboard, [switch]$Console, [switch]$Stop, [switch]$NoAttach,
      [int]$Port = 8080)

# No $ErrorActionPreference = 'Stop': Windows PowerShell 5.1 then turns any
# stderr line from docker into a fatal error. Exit codes are checked instead.
$Name = 'kryptonfs-demo'
$Image = 'kryptonfs-dev'
Set-Location $PSScriptRoot

function Test-Docker { docker info *> $null; return $LASTEXITCODE -eq 0 }

function Start-DockerDesktop {
    if (Test-Docker) { return }
    $exe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (-not (Test-Path $exe)) {
        throw 'Docker is not running and Docker Desktop was not found. Install it from https://www.docker.com/products/docker-desktop/ and try again.'
    }
    Write-Host 'Starting Docker Desktop...'
    Start-Process $exe
    for ($i = 0; $i -lt 90; $i++) {
        Start-Sleep -Seconds 2
        if (Test-Docker) { return }
    }
    throw 'Docker Desktop did not become ready within 3 minutes.'
}

# Windows can refuse a port nothing is using: Hyper-V and WSL reserve
# blocks of ports (often hundreds around 8080), and the blocks move after a
# reboot. The console takes the first port from $Port that binds, and
# otherwise any free port the system hands out.
function Find-FreePort([int]$from) {
    for ($p = $from; $p -lt $from + 20; $p++) {
        try {
            $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $p)
            $l.Start(); $l.Stop()
            return $p
        } catch { }
    }
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start()
    $p = $l.LocalEndpoint.Port
    $l.Stop()
    return $p
}

function Test-Running { (docker ps --filter "name=^$Name$" --format '{{.Names}}') -eq $Name }

function Show-Hints {
    Write-Host ''
    Write-Host 'The demo is running:'
    Write-Host '  .\run.cmd -Console     open the console in the browser again'
    Write-Host '  .\run.cmd -Dashboard   terminal dashboard'
    Write-Host '  .\run.cmd -Shell       Linux shell; your files are in /mnt/krypton'
    Write-Host '  .\run.cmd -Stop        stop everything'
}

function Open-Console {
    # Look the published port up, in case the demo was started with -Port.
    $hostPort = ((docker port $Name 8080) | Select-Object -First 1) -replace '.*:', ''
    $token = docker exec $Name cat /demo/web.token
    if ($LASTEXITCODE -ne 0 -or -not $token -or -not $hostPort) {
        throw "The console is not available. Log: docker exec $Name cat /demo/web.log"
    }
    Write-Host "Opening the Krypton Console: http://localhost:$hostPort"
    Write-Host '(The link holds a private access token; it is swapped for a cookie as soon as it opens.)'
    Start-Process "http://localhost:${hostPort}/?token=$token"
}

function Open-Dashboard {
    Write-Host 'Opening the dashboard. Press q to close it; the demo keeps running.'
    docker exec -it $Name tmux attach -t dash
}

if ($Stop) {
    if (Test-Docker) { docker rm -f $Name *> $null }
    Write-Host 'KryptonFS demo stopped.'
    return
}

Start-DockerDesktop

if ($Shell -or $Dashboard -or $Console) {
    if (-not (Test-Running)) { throw 'The demo is not running. Start it with .\run.cmd' }
    if ($Shell) { docker exec -it -w /mnt/krypton $Name bash }
    elseif ($Dashboard) { Open-Dashboard; Show-Hints }
    else { Open-Console }
    return
}

Write-Host 'Preparing the Linux environment (slow the first time only)...'
docker build -q -f docker/dev.Dockerfile -t $Image . | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Building the Docker image failed.' }

# The console is published on this computer only (127.0.0.1), never on the
# network. node_modules lives in a named volume, outside your folder.
docker rm -f $Name *> $null
$Port = Find-FreePort $Port
docker run -d --init --name $Name --device /dev/fuse --cap-add SYS_ADMIN --cap-add IPC_LOCK `
    -p "127.0.0.1:${Port}:8080" -v "${PSScriptRoot}:/src" `
    -v kryptonfs-node-modules:/src/webui/frontend/node_modules `
    -w /src $Image bash scripts/demo-cluster.sh | Out-Null
if ($LASTEXITCODE -ne 0) {
    docker rm -f $Name *> $null
    throw "Starting the demo container failed. If port $Port is taken, try .\run.cmd -Port 18080"
}

Write-Host 'Building KryptonFS and starting the cluster...'
$shown = 0
for ($i = 0; $i -lt 300; $i++) {
    Start-Sleep -Seconds 1
    $logs = @(docker logs $Name 2>&1 | ForEach-Object { "$_" })
    # Print only new lines (a PowerShell range runs backwards when empty).
    if ($logs.Count -gt $shown) {
        $logs[$shown..($logs.Count - 1)] | Where-Object { $_ -and $_ -notmatch 'READY' } | ForEach-Object { Write-Host "  $_" }
        $shown = $logs.Count
    }
    if ($logs -match 'FAILED') { throw "The demo failed to start. Full log: docker logs $Name" }
    if ($logs -match '\[demo\] READY') { break }
    if (-not (Test-Running)) { throw "The demo stopped unexpectedly. Log: docker logs $Name" }
}
if (-not ($logs -match '\[demo\] READY')) { throw 'The demo did not start within 5 minutes.' }

Write-Host ''
Write-Host 'KryptonFS is running: 3 storage nodes, encrypted volume at /mnt/krypton.'
if ($NoAttach) { return }
Open-Console
Show-Hints
