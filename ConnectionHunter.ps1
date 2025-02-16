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
        return netstat -ano -n -o | Select-String "ESTABLISHED"
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
