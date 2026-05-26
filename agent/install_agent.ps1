# RealSIEM Agent Installer for Windows

param(
    [string]$ServerIP = "127.0.0.1",
    [string]$AgentGroup = "windows-workstations"
)

# Requires Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run Windows PowerShell as an Administrator."
    exit
}

$InstallDir = "C:\Program Files\RealSIEM Agent"

Write-Host "Installing RealSIEM Agent..."
Write-Host "Server IP: $ServerIP"
Write-Host "Group: $AgentGroup"

# Check Python Python3
if (!(Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3 is not installed or not in PATH."
    exit
}

# Create directories
New-Item -ItemType Directory -Force -Path "$InstallDir"
New-Item -ItemType Directory -Force -Path "$InstallDir\collectors"
New-Item -ItemType Directory -Force -Path "$InstallDir\core"
New-Item -ItemType Directory -Force -Path "$InstallDir\config"

# Copy files (assuming running from source dir)
Copy-Item "core\agent.py" -Destination "$InstallDir\core" -Force
Copy-Item "collectors\*" -Destination "$InstallDir\collectors" -Recurse -Force
Copy-Item "config\*" -Destination "$InstallDir\config" -Recurse -Force
Copy-Item "requirements.txt" -Destination $InstallDir -Force

# Update config
$ConfigPath = "$InstallDir\config\agent.conf"
(Get-Content $ConfigPath) -replace 'host: "127.0.0.1"', "host: `"$ServerIP`"" | Set-Content $ConfigPath
(Get-Content $ConfigPath) -replace 'group: "default"', "group: `"$AgentGroup`"" | Set-Content $ConfigPath

# Setup virtual environment and install reqs
Set-Location $InstallDir
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt

# Create Windows Service using NSSM (if available) or setup as scheduled task
try {
    # Simple Scheduled task for persistence
    $Action = New-ScheduledTaskAction -Execute "$InstallDir\venv\Scripts\python.exe" -Argument "$InstallDir\core\agent.py" -WorkingDirectory $InstallDir
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "RealSIEM Agent" -Action $Action -Trigger $Trigger -Principal $Principal -Force
    Start-ScheduledTask -TaskName "RealSIEM Agent"
    Write-Host "RealSIEM Agent installed and started successfully via Scheduled Task."
} catch {
    Write-Error "Failed to create service/task: $_"
}
