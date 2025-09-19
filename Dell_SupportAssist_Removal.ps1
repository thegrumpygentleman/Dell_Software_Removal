#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Complete Dell SupportAssist Removal Script
.DESCRIPTION
    Thoroughly removes all Dell SupportAssist components including:
    - SupportAssist Agent and Client
    - Related services and drivers
    - Registry entries and folders
    - Scheduled tasks and startup entries
    - OS Recovery and remediation tools
.NOTES
    Must be run as Administrator/System user
    Version: 1.0
#>

# Enable verbose output
$VerbosePreference = "Continue"

# Log file path
$LogPath = "$env:TEMP\Dell_SupportAssist_Removal_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Output $LogEntry
    Add-Content -Path $LogPath -Value $LogEntry
}

Write-Log "Starting Dell SupportAssist complete removal process"

# Dell SupportAssist UWP/Store Applications
$SupportAssistApps = @(
    "Dell.SupportAssist",
    "Dell.SupportAssistAgent",
    "Dell.SupportAssistforHomePC",
    "Dell.SupportAssistforBusinessPCs",
    "Dell.SupportAssistOSRecovery",
    "Dell.SupportAssistRemediation",
    "DellInc.DellSupportAssistforPCs",
    "DellInc.DellSupportAssistforBusinessPCs",
    "*SupportAssist*"
)

# Traditional SupportAssist Programs
$SupportAssistPrograms = @(
    "Dell SupportAssist",
    "Dell SupportAssist Agent",
    "Dell SupportAssist for Home PCs",
    "Dell SupportAssist for Business PCs",
    "Dell SupportAssist OS Recovery",
    "Dell SupportAssist Remediation",
    "SupportAssist",
    "Dell SupportAssist for PCs",
    "PC-Doctor for Dell"
)

# SupportAssist Services
$SupportAssistServices = @(
    "DellClientManagementService",
    "Dell SupportAssist Agent",
    "Dell SupportAssist Remediation",
    "SupportAssistAgent",
    "DDVCollectorSvcApi",
    "DDVDataCollector",
    "DDVRulesProcessor",
    "DellProSupport"
)

# Function to stop and remove SupportAssist processes
function Stop-SupportAssistProcesses {
    Write-Log "Stopping SupportAssist processes..."
    
    $processNames = @(
        "SupportAssist*",
        "Dell.SupportAssist*",
        "PCDr*",
        "DDVCollectorSvcApi",
        "DDVDataCollector",
        "DDVRulesProcessor"
    )
    
    foreach ($processPattern in $processNames) {
        try {
            $processes = Get-Process -Name $processPattern -ErrorAction SilentlyContinue
            foreach ($process in $processes) {
                Write-Log "Stopping process: $($process.ProcessName)"
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log "Error stopping process $processPattern : $($_.Exception.Message)" "WARNING"
        }
    }
}

# Function to remove SupportAssist UWP applications
function Remove-SupportAssistUWP {
    Write-Log "Removing SupportAssist UWP/Store applications..."
    
    foreach ($app in $SupportAssistApps) {
        try {
            # Remove for all users
            $packages = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
            foreach ($package in $packages) {
                Write-Log "Removing UWP package: $($package.Name)"
                Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            }
            
            # Remove provisioned packages
            $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app
            foreach ($provPackage in $provisionedPackages) {
                Write-Log "Removing provisioned package: $($provPackage.DisplayName)"
                Remove-AppxProvisionedPackage -Online -PackageName $provPackage.PackageName -ErrorAction SilentlyContinue
            }
            
            # Aggressive removal for stubborn packages
            $allPackages = Get-AppxPackage -AllUsers | Where-Object { 
                $_.Name -like $app -or $_.PackageFullName -like "*$app*" 
            }
            foreach ($package in $allPackages) {
                Write-Log "Force removing: $($package.Name)"
                try {
                    Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
                }
                catch {
                    # Use DISM as fallback
                    & dism.exe /Online /Remove-ProvisionedAppxPackage /PackageName:$($package.PackageFullName) 2>$null
                }
            }
        }
        catch {
            Write-Log "Error removing UWP app $app : $($_.Exception.Message)" "ERROR"
        }
    }
}

# Function to remove traditional SupportAssist programs
function Remove-SupportAssistPrograms {
    Write-Log "Removing traditional SupportAssist programs..."
    
    foreach ($program in $SupportAssistPrograms) {
        try {
            # Search in both 32-bit and 64-bit uninstall keys
            $uninstallKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            
            foreach ($key in $uninstallKeys) {
                $apps = Get-ItemProperty $key -ErrorAction SilentlyContinue | 
                        Where-Object { 
                            $_.DisplayName -like "*$program*" -or 
                            $_.Publisher -like "*Dell*" -and $_.DisplayName -like "*Support*"
                        }
                
                foreach ($app in $apps) {
                    if ($app.UninstallString) {
                        Write-Log "Uninstalling: $($app.DisplayName)"
                        
                        $uninstallString = $app.UninstallString
                        if ($uninstallString -like "*msiexec*") {
                            # MSI installer
                            $productCode = ($uninstallString -replace '.*{','{' -replace '}.*','}')
                            if ($productCode -match '^\{[A-F0-9\-]+\}$') {
                                Write-Log "Using MSI uninstall for product code: $productCode"
                                Start-Process "msiexec.exe" -ArgumentList "/x `"$productCode`" /quiet /norestart /L*V `"$env:TEMP\SA_Uninstall.log`"" -Wait -NoNewWindow
                            }
                        }
                        elseif ($uninstallString -like "*.exe*") {
                            # Standard executable uninstaller
                            $uninstallPath = ($uninstallString -replace '"','').Split(' ')[0]
                            if (Test-Path $uninstallPath) {
                                Write-Log "Using EXE uninstall: $uninstallPath"
                                # Try multiple silent parameters
                                $silentArgs = @("/S", "/silent", "/quiet", "/uninstall", "-uninstall", "/x")
                                foreach ($arg in $silentArgs) {
                                    try {
                                        Start-Process $uninstallPath -ArgumentList $arg -Wait -NoNewWindow -ErrorAction Stop
                                        break
                                    }
                                    catch {
                                        continue
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "Error removing program $program : $($_.Exception.Message)" "ERROR"
        }
    }
}

# Function to remove SupportAssist services
function Remove-SupportAssistServices {
    Write-Log "Stopping and removing SupportAssist services..."
    
    # First, stop all related services
    foreach ($serviceName in $SupportAssistServices) {
        try {
            $services = Get-Service -DisplayName "*$serviceName*" -ErrorAction SilentlyContinue
            $services += Get-Service -Name "*$serviceName*" -ErrorAction SilentlyContinue
            
            foreach ($service in $services) {
                Write-Log "Stopping service: $($service.Name)"
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                
                # Wait for service to stop
                $timeout = 30
                while ((Get-Service -Name $service.Name -ErrorAction SilentlyContinue).Status -eq 'Running' -and $timeout -gt 0) {
                    Start-Sleep -Seconds 1
                    $timeout--
                }
                
                # Delete the service
                Write-Log "Deleting service: $($service.Name)"
                & sc.exe delete $service.Name 2>$null
            }
        }
        catch {
            Write-Log "Error removing service $serviceName : $($_.Exception.Message)" "ERROR"
        }
    }
    
    # Additional service cleanup using WMI
    try {
        $wmiServices = Get-WmiObject -Class Win32_Service | Where-Object { 
            $_.Name -like "*SupportAssist*" -or 
            $_.DisplayName -like "*SupportAssist*" -or
            $_.PathName -like "*SupportAssist*"
        }
        
        foreach ($service in $wmiServices) {
            Write-Log "WMI removing service: $($service.Name)"
            $service.StopService() | Out-Null
            $service.Delete() | Out-Null
        }
    }
    catch {
        Write-Log "Error in WMI service cleanup: $($_.Exception.Message)" "WARNING"
    }
}

# Function to remove SupportAssist scheduled tasks
function Remove-SupportAssistScheduledTasks {
    Write-Log "Removing SupportAssist scheduled tasks..."
    
    try {
        $tasks = Get-ScheduledTask | Where-Object { 
            $_.TaskName -like "*SupportAssist*" -or 
            $_.TaskName -like "*Dell*" -or
            $_.Author -like "*Dell*" -or
            $_.Description -like "*SupportAssist*"
        }
        
        foreach ($task in $tasks) {
            Write-Log "Removing scheduled task: $($task.TaskName)"
            Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "Error removing scheduled tasks: $($_.Exception.Message)" "ERROR"
    }
}

# Function to clean SupportAssist registry entries
function Remove-SupportAssistRegistry {
    Write-Log "Cleaning SupportAssist registry entries..."
    
    $registryPaths = @(
        "HKLM:\SOFTWARE\Dell\SupportAssist",
        "HKLM:\SOFTWARE\WOW6432Node\Dell\SupportAssist",
        "HKCU:\SOFTWARE\Dell\SupportAssist",
        "HKLM:\SOFTWARE\Dell\UpdateService",
        "HKLM:\SOFTWARE\WOW6432Node\Dell\UpdateService",
        "HKLM:\SOFTWARE\PC-Doctor",
        "HKLM:\SOFTWARE\WOW6432Node\PC-Doctor",
        "HKLM:\SYSTEM\CurrentControlSet\Services\SupportAssistAgent",
        "HKLM:\SYSTEM\CurrentControlSet\Services\DellClientManagementService"
    )
    
    foreach ($path in $registryPaths) {
        try {
            if (Test-Path $path) {
                Write-Log "Removing registry path: $path"
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log "Error removing registry path $path : $($_.Exception.Message)" "ERROR"
        }
    }
    
    # Remove SupportAssist from startup
    try {
        $startupKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        
        foreach ($startupKey in $startupKeys) {
            if (Test-Path $startupKey) {
                $values = Get-ItemProperty $startupKey -ErrorAction SilentlyContinue
                foreach ($property in $values.PSObject.Properties) {
                    if ($property.Value -like "*SupportAssist*" -or $property.Name -like "*SupportAssist*") {
                        Write-Log "Removing startup entry: $($property.Name)"
                        Remove-ItemProperty -Path $startupKey -Name $property.Name -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Error removing startup entries: $($_.Exception.Message)" "WARNING"
    }
}

# Function to remove SupportAssist folders
function Remove-SupportAssistFolders {
    Write-Log "Removing SupportAssist folders..."
    
    $folders = @(
        "$env:ProgramFiles\Dell\SupportAssist",
        "$env:ProgramFiles (x86)\Dell\SupportAssist",
        "$env:ProgramData\Dell\SupportAssist",
        "$env:LOCALAPPDATA\Dell\SupportAssist",
        "$env:ProgramFiles\Dell\UpdateService",
        "$env:ProgramFiles (x86)\Dell\UpdateService",
        "$env:ProgramFiles\PC-Doctor",
        "$env:ProgramFiles (x86)\PC-Doctor",
        "$env:ProgramData\PC-Doctor",
        "$env:ProgramData\PCDr",
        "$env:LOCALAPPDATA\PC-Doctor",
        "$env:TEMP\Dell",
        "$env:TEMP\SupportAssist"
    )
    
    foreach ($folder in $folders) {
        try {
            if (Test-Path $folder) {
                Write-Log "Removing folder: $folder"
                # Take ownership first
                & takeown.exe /f "$folder" /r /d y 2>$null
                & icacls.exe "$folder" /grant administrators:F /t 2>$null
                Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log "Error removing folder $folder : $($_.Exception.Message)" "ERROR"
        }
    }
    
    # Remove SupportAssist from WindowsApps
    try {
        $windowsAppsPath = "$env:ProgramFiles\WindowsApps"
        if (Test-Path $windowsAppsPath) {
            & takeown.exe /f $windowsAppsPath /r /d y 2>$null
            & icacls.exe $windowsAppsPath /grant administrators:F /t 2>$null
            
            $saFolders = Get-ChildItem -Path $windowsAppsPath -Directory -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Name -like "*SupportAssist*" -or $_.Name -like "*Dell.Support*" }
            
            foreach ($folder in $saFolders) {
                Write-Log "Removing WindowsApps folder: $($folder.Name)"
                & takeown.exe /f $folder.FullName /r /d y 2>$null
                & icacls.exe $folder.FullName /grant administrators:F /t 2>$null
                Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Log "Error removing WindowsApps SupportAssist folders: $($_.Exception.Message)" "WARNING"
    }
}

# Function to remove SupportAssist drivers
function Remove-SupportAssistDrivers {
    Write-Log "Removing SupportAssist related drivers..."
    
    try {
        # Get Dell/SupportAssist related drivers
        $drivers = Get-WmiObject -Class Win32_PnPSignedDriver | Where-Object {
            $_.DeviceName -like "*Dell*" -and (
                $_.DriverDescription -like "*SupportAssist*" -or
                $_.DriverDescription -like "*PC-Doctor*" -or
                $_.InfName -like "*dell*support*"
            )
        }
        
        foreach ($driver in $drivers) {
            Write-Log "Found SupportAssist driver: $($driver.DeviceName)"
            try {
                # Use pnputil to remove driver
                & pnputil.exe /delete-driver $driver.InfName /uninstall /force 2>$null
                Write-Log "Removed driver: $($driver.InfName)"
            }
            catch {
                Write-Log "Could not remove driver: $($driver.InfName)" "WARNING"
            }
        }
    }
    catch {
        Write-Log "Error in driver removal: $($_.Exception.Message)" "WARNING"
    }
}

# Function to clean up Windows Features and Capabilities
function Remove-SupportAssistCapabilities {
    Write-Log "Removing SupportAssist Windows capabilities..."
    
    try {
        # Remove any Dell-related optional features
        $capabilities = Get-WindowsCapability -Online | Where-Object {
            $_.Name -like "*Dell*" -or $_.Name -like "*SupportAssist*"
        }
        
        foreach ($capability in $capabilities) {
            if ($capability.State -eq "Installed") {
                Write-Log "Removing Windows capability: $($capability.Name)"
                Remove-WindowsCapability -Online -Name $capability.Name -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Log "Error removing Windows capabilities: $($_.Exception.Message)" "WARNING"
    }
}

# Main execution
try {
    Write-Log "Dell SupportAssist Complete Removal Started"
    
    # Execute removal in specific order
    Stop-SupportAssistProcesses
    Remove-SupportAssistServices
    Remove-SupportAssistScheduledTasks
    Remove-SupportAssistUWP
    Remove-SupportAssistPrograms
    Remove-SupportAssistDrivers
    Remove-SupportAssistRegistry
    Remove-SupportAssistFolders
    Remove-SupportAssistCapabilities
    
    Write-Log "Dell SupportAssist removal completed successfully"
    Write-Log "Log file saved to: $LogPath"
    
    # Final cleanup
    Write-Log "Performing final cleanup..."
    
    # Clear temp files
    Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $_.Name -like "*Dell*" -or $_.Name -like "*SupportAssist*" } | 
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    
    # Suggest reboot
    Write-Log "CRITICAL: Restart the computer to complete SupportAssist removal"
    Write-Output "`n=========================================="
    Write-Output "DELL SUPPORTASSIST REMOVAL COMPLETED"
    Write-Output "=========================================="
    Write-Output "Please restart your computer to finalize removal."
    Write-Output "Log file: $LogPath"
    
}
catch {
    Write-Log "Critical error during execution: $($_.Exception.Message)" "ERROR"
    exit 1
}
