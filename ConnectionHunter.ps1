#   _____                            _   _               
#  / ____|                          | | (_)              
# | |     ___  _ __  _ __   ___  ___| |_ _  ___  _ __    
# | |    / _ \| '_ \| '_ \ / _ \/ __| __| |/ _ \| '_ \   
# | |___| (_) | | | | | | |  __/ (__| |_| | (_) | | | |  
#  \_____\___/|_| |_|_| |_|\___|\___|\__|_|\___/|_| |_|  
#         | |  | |           | |                         
#         | |__| |_   _ _ __ | |_ ___ _ __               
#         |  __  | | | | '_ \| __/ _ \ '__|              
#         | |  | | |_| | | | | ||  __/ |                 
#         |_|  |_|\__,_|_| |_|\__\___|_|                 
#
# ConnectionHunter - An IP Connection Threat Scanner for Windows machines
# Created by Michael Byrne

param(
    [string]$RemoteComputer  # Optional: Specify a remote computer name or IP address
)

function Show-Banner {
    # Display the script banner in the terminal
    Write-Host ""  
    Write-Host "   _____                            _   _               " -ForegroundColor Cyan
    Write-Host "  / ____|                          | | (_)              " -ForegroundColor Cyan
    Write-Host " | |     ___  _ __  _ __   ___  ___| |_ _  ___  _ __    " -ForegroundColor Cyan
    Write-Host " | |    / _ \| '_ \| '_ \ / _ \/ __| __| |/ _ \| '_ \   " -ForegroundColor Cyan
    Write-Host " | |___| (_) | | | | | | |  __/ (__| |_| | (_) | | | |  " -ForegroundColor Cyan
    Write-Host "  \_____\___/|_| |_|_| |_|\___|\___|\__|_|\___/|_| |_|  " -ForegroundColor Cyan
    Write-Host "         | |  | |           | |                         " -ForegroundColor Cyan
    Write-Host "         | |__| |_   _ _ __ | |_ ___ _ __               " -ForegroundColor Cyan
    Write-Host "         |  __  | | | | '_ \| __/ _ \ '__|              " -ForegroundColor Cyan
    Write-Host "         | |  | | |_| | | | | ||  __/ |                 " -ForegroundColor Cyan
    Write-Host "         |_|  |_|\__,_|_| |_|\__\___|_|                 " -ForegroundColor Cyan
    Write-Host ""
    Write-Host " ConnectionHunter - An IP Connection Threat Scanner " -ForegroundColor Yellow
    Write-Host ""
}

Show-Banner

# Ensure PowerShell uses modern TLS protocols
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Define file paths and URLs
$ScriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$BadIPsURL = "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/ip-list.txt"
$PersistentFile = Join-Path $ScriptFolder "large_bad_ips.txt"
$LogFile = Join-Path $ScriptFolder "bad_ip_hits.log"

function Compare-FileContents {
    param(
        [string]$LocalFilePath,
        [string]$RemoteFilePath
    )

    # Check if both files exist, return false if either is missing
    if (!(Test-Path $LocalFilePath) -or !(Test-Path $RemoteFilePath)) {
        return $false
    }

    # Compare file sizes first for a quick check
    $SizeLocal = (Get-Item $LocalFilePath).Length
    $SizeRemote = (Get-Item $RemoteFilePath).Length
    if ($SizeLocal -ne $SizeRemote) {
        return $false
    }

    # If sizes match, compute SHA256 hashes for final verification
    $HashLocal = Get-FileHash -Path $LocalFilePath -Algorithm SHA256
    $HashRemote = Get-FileHash -Path $RemoteFilePath -Algorithm SHA256
    return $HashLocal.Hash -eq $HashRemote.Hash
}

try {
    Write-Host "Fetching IP list from $BadIPsURL..."
    $Headers = @{}
    
    # Use 'If-Modified-Since' to check for updates before downloading
    if (Test-Path $PersistentFile) {
        $LastModified = (Get-Item $PersistentFile).LastWriteTime.ToUniversalTime().ToString("R")
        $Headers["If-Modified-Since"] = $LastModified
    }

    # Get remote file size without downloading the file
    $Response = Invoke-WebRequest -Uri $BadIPsURL -Method Head -Headers $Headers -TimeoutSec 10 -ErrorAction Stop
    $RemoteFileSize = [int]$Response.Headers["Content-Length"]
    $LocalFileSize = if (Test-Path $PersistentFile) { (Get-Item $PersistentFile).Length } else { 0 }

    # Download the file only if it has changed
    if ($RemoteFileSize -ne $LocalFileSize) {
        Write-Host "Changes detected! Downloading updated IP list..."
        Invoke-WebRequest -Uri $BadIPsURL -OutFile $PersistentFile -Headers $Headers -TimeoutSec 10 -ErrorAction Stop
    } else {
        Write-Host "No changes detected. Using cached version."
    }

    # Load IP list into memory
    $BadIPs = Get-Content -Path $PersistentFile
    Write-Host "IP list loaded into memory."

} catch {
    Write-Host "Error: Unable to download or process IP list. Using cached version if available."
    if (Test-Path $PersistentFile) {
        $BadIPs = Get-Content -Path $PersistentFile
    } else {
        Write-Host "No cached file available. Exiting."
        exit 1
    }
}

# Run netstat to get network connections 
function Get-NetworkConnections {
    param (
        [string]$ComputerName
    )
    if ($ComputerName) {
        Write-Host "Remote execution not supported in this version."
        exit 1
    }
    try {
        Write-Host "Running netstat locally on Windows..."
        return netstat -ano | Select-String "ESTABLISHED"
    } catch {
        Write-Host "Error: Unable to retrieve network connections"
        exit 1
    }
}

$NetworkOutput = Get-NetworkConnections -ComputerName $RemoteComputer
$Connections = @()

# Retrieve all process information including owner
$ProcessInfo = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, @{Name='Owner';Expression={(Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User}}

foreach ($Line in $NetworkOutput) {
    $Parts = $Line -split '\s+'
    if ($Parts.Count -ge 6) {
        $ForeignIP = $Parts[2] -replace ":\d+$", ""
        $ProcessID = $Parts[5]
        $ProcessDetails = $ProcessInfo | Where-Object { $_.ProcessId -eq $ProcessID }
        $ProcessName = if ($ProcessDetails) { $ProcessDetails.Name } else { "Unknown" }
        $Owner = if ($ProcessDetails -and $ProcessDetails.Owner) { $ProcessDetails.Owner } else { "N/A" }

        $Connections += [PSCustomObject]@{
            ForeignIP = $ForeignIP
            ProcessID = $ProcessID
            ProcessName = $ProcessName
            Owner = $Owner
        }
    }
}

$MatchedConnections = $Connections | Where-Object { $_.ForeignIP -in $BadIPs }

if ($MatchedConnections.Count -gt 0) {
    Write-Host "ALERT: Found matching bad IPs."
    foreach ($Match in $MatchedConnections) {
        Write-Host "BAD IP: $($Match.ForeignIP) | ProcessID: $($Match.ProcessID) | Process Name: $($Match.ProcessName) | Owner: $($Match.Owner)"
    }
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = @("[$Timestamp] ALERT: The following bad IPs were detected:")
    $MatchedConnections | ForEach-Object { $LogEntry += "BAD IP: $($_.ForeignIP) | ProcessID: $($_.ProcessID) | Process Name: $($_.ProcessName) | Owner: $($_.Owner)" }
    $LogEntry | Out-File -FilePath $LogFile -Append
} else {
    Write-Host "OK: No bad IPs found in current connections."
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Timestamp] OK: No bad IPs detected in current connections." | Out-File -FilePath $LogFile -Append
}

Write-Host "Script execution complete. Results logged to $LogFile"
