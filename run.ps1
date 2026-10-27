<#
.SYNOPSIS
    Starts the KryptonFS demo: 3 storage nodes, an encrypted volume and the
    live dashboard, inside Docker. Usually run through run.cmd.

.EXAMPLE
    .\run.cmd             start (or restart) the demo and open the dashboard
    .\run.cmd -Shell      open a Linux shell in the running demo (files: /mnt/krypton)
    .\run.cmd -Dashboard  reopen the dashboard
    .\run.cmd -Stop       stop the demo
#>
param([switch]$Shell, [switch]$Dashboard, [switch]$Stop, [switch]$NoAttach)

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

function Test-Running { (docker ps --filter "name=^$Name$" --format '{{.Names}}') -eq $Name }

function Open-Dashboard {
    Write-Host 'Opening the dashboard. Press q to close it; the demo keeps running.'
    docker exec -it $Name tmux attach -t dash
    Write-Host ''
    Write-Host 'The demo is still running:'
    Write-Host '  .\run.cmd -Dashboard   reopen the dashboard'
    Write-Host '  .\run.cmd -Shell       Linux shell; your files are in /mnt/krypton'
    Write-Host '  .\run.cmd -Stop        stop everything'
}

if ($Stop) {
    if (Test-Docker) { docker rm -f $Name *> $null }
    Write-Host 'KryptonFS demo stopped.'
    return
}

Start-DockerDesktop

if ($Shell -or $Dashboard) {
    if (-not (Test-Running)) { throw 'The demo is not running. Start it with .\run.cmd' }
    if ($Shell) { docker exec -it -w /mnt/krypton $Name bash } else { Open-Dashboard }
    return
}

Write-Host 'Preparing the Linux environment (slow the first time only)...'
docker build -q -f docker/dev.Dockerfile -t $Image . | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Building the Docker image failed.' }

docker rm -f $Name *> $null
docker run -d --name $Name --device /dev/fuse --cap-add SYS_ADMIN --cap-add IPC_LOCK `
    -v "${PSScriptRoot}:/src" -w /src $Image bash scripts/demo-cluster.sh | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Starting the demo container failed.' }

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
Open-Dashboard
