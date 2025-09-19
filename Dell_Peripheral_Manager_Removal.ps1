# PowerShell Script to Force Uninstall Dell Peripheral Manager
# Optimized for SYSTEM user context (Action1, SCCM, etc.)

Write-Host "Starting Dell Peripheral Manager removal process (SYSTEM context)..." -ForegroundColor Green

# Function to get all user profiles
function Get-AllUserProfiles {
    $profiles = @()
    $profileList = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue
    foreach ($profile in $profileList) {
        if ($profile.ProfileImagePath -and (Test-Path $profile.ProfileImagePath)) {
            $profiles += @{
                SID = $profile.PSChildName
                Path = $profile.ProfileImagePath
                Username = Split-Path $profile.ProfileImagePath -Leaf
            }
        }
    }
    return $profiles
}

# Stop any running Dell Peripheral Manager processes for all users
Write-Host "Stopping Dell Peripheral Manager processes..." -ForegroundColor Yellow
$processes = @("DellPeripheralManager", "Dell.PeripheralManager", "DPM.exe", "DellPM.exe", "DellPeripheral*")
foreach ($processPattern in $processes) {
    Get-Process -Name $processPattern -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# Method 1: Uninstall via WMI (works in SYSTEM context)
Write-Host "Attempting uninstall via WMI..." -ForegroundColor Yellow
try {
    $apps = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Dell Peripheral Manager*" -or $_.Name -like "*Dell*Peripheral*" }
    foreach ($app in $apps) {
        Write-Host "Found WMI application: $($app.Name)" -ForegroundColor Cyan
        $result = $app.Uninstall()
        if ($result.ReturnValue -eq 0) {
            Write-Host "Successfully uninstalled: $($app.Name)" -ForegroundColor Green
        } else {
            Write-Host "WMI uninstall failed with code: $($result.ReturnValue)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "WMI uninstall error: $($_.Exception.Message)" -ForegroundColor Red
}

# Method 2: Registry-based uninstallation and cleanup (SYSTEM has full access)
Write-Host "Processing registry uninstallers and cleanup..." -ForegroundColor Yellow
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$keysToRemove = @()

foreach ($basePath in $registryPaths) {
    try {
        $uninstallKeys = Get-ChildItem $basePath -ErrorAction SilentlyContinue
        foreach ($key in $uninstallKeys) {
            $displayName = $key.GetValue("DisplayName")
            if ($displayName -like "*Dell Peripheral Manager*" -or $displayName -like "*Dell*Peripheral*") {
                Write-Host "Found registry entry: $displayName" -ForegroundColor Cyan
                $keyPath = $key.PSPath
                $keysToRemove += $keyPath
                
                $uninstallString = $key.GetValue("UninstallString")
                $quietUninstallString = $key.GetValue("QuietUninstallString")
                
                # Prefer quiet uninstall if available
                $uninstaller = if ($quietUninstallString) { $quietUninstallString } else { $uninstallString }
                
                if ($uninstaller) {
                    Write-Host "Running uninstaller: $uninstaller" -ForegroundColor Cyan
                    try {
                        if ($uninstaller -like "*msiexec*") {
                            # Extract MSI product code
                            $msiCode = ""
                            if ($uninstaller -match "\{[A-F0-9\-]+\}") {
                                $msiCode = $matches[0]
                                $arguments = "/X$msiCode /quiet /norestart /L*v `"$env:TEMP\DellPM_Uninstall.log`""
                                Start-Process "msiexec.exe" -ArgumentList $arguments -Wait -NoNewWindow -WindowStyle Hidden
                                Write-Host "MSI uninstaller completed" -ForegroundColor Green
                            }
                        } else {
                            # Handle other installer types
                            $exe = ($uninstaller -split '"')[1]
                            if (-not $exe) { $exe = $uninstaller.Split(' ')[0] }
                            
                            if (Test-Path $exe) {
                                $arguments = "/S /silent /quiet /norestart"
                                Start-Process -FilePath $exe -ArgumentList $arguments -Wait -NoNewWindow -WindowStyle Hidden -ErrorAction SilentlyContinue
                                Write-Host "Standard uninstaller completed" -ForegroundColor Green
                            }
                        }
                    } catch {
                        Write-Host "Uninstaller execution failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
    } catch {
        Write-Host "Registry processing error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Force remove the uninstall registry entries
Write-Host "Force removing Add/Remove Programs entries..." -ForegroundColor Yellow
foreach ($keyPath in $keysToRemove) {
    try {
        Write-Host "Removing registry key: $keyPath" -ForegroundColor Cyan
        Remove-Item $keyPath -Recurse -Force -ErrorAction Stop
        Write-Host "Successfully removed registry key: $keyPath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to remove registry key: $keyPath - $($_.Exception.Message)" -ForegroundColor Red
        # Try alternative method using reg.exe
        $regKeyPath = $keyPath -replace "Microsoft.PowerShell.Core\\Registry::", ""
        $regKeyPath = $regKeyPath -replace "HKEY_LOCAL_MACHINE", "HKLM"
        Write-Host "Trying alternative removal method for: $regKeyPath" -ForegroundColor Cyan
        & reg delete "$regKeyPath" /f 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully removed via reg.exe: $regKeyPath" -ForegroundColor Green
        }
    }
}

# Method 3: Remove installation directories (SYSTEM context)
Write-Host "Removing installation directories..." -ForegroundColor Yellow
$systemPaths = @(
    "$env:ProgramFiles\Dell\Dell Peripheral Manager",
    "$env:ProgramFiles\Dell Peripheral Manager",
    "${env:ProgramFiles(x86)}\Dell\Dell Peripheral Manager",
    "${env:ProgramFiles(x86)}\Dell Peripheral Manager",
    "$env:ProgramData\Dell\Dell Peripheral Manager",
    "$env:ALLUSERSPROFILE\Dell\Dell Peripheral Manager"
)

foreach ($path in $systemPaths) {
    if (Test-Path $path) {
        Write-Host "Removing directory: $path" -ForegroundColor Cyan
        try {
            # Force remove with takeown for stubborn files
            takeown /f "$path" /r /d y 2>$null
            icacls "$path" /grant Administrators:F /t 2>$null
            Remove-Item $path -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully removed: $path" -ForegroundColor Green
        } catch {
            Write-Host "Failed to remove: $path - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Remove from all user profiles
$userProfiles = Get-AllUserProfiles
foreach ($profile in $userProfiles) {
    $userPaths = @(
        "$($profile.Path)\AppData\Local\Dell\Dell Peripheral Manager",
        "$($profile.Path)\AppData\Roaming\Dell\Dell Peripheral Manager"
    )
    
    foreach ($userPath in $userPaths) {
        if (Test-Path $userPath) {
            Write-Host "Removing user directory: $userPath" -ForegroundColor Cyan
            try {
                Remove-Item $userPath -Recurse -Force -ErrorAction Stop
                Write-Host "Successfully removed: $userPath" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove: $userPath - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# Method 4: Registry cleanup (SYSTEM has full HKLM access)
Write-Host "Cleaning Dell Peripheral Manager registry entries..." -ForegroundColor Yellow
$regPaths = @(
    "HKLM:\SOFTWARE\Dell\Dell Peripheral Manager",
    "HKLM:\SOFTWARE\WOW6432Node\Dell\Dell Peripheral Manager"
)

foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        Write-Host "Removing registry path: $regPath" -ForegroundColor Cyan
        try {
            Remove-Item $regPath -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully removed registry path: $regPath" -ForegroundColor Green
        } catch {
            Write-Host "Failed to remove registry path: $regPath - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Clean user-specific registry entries by loading user hives
foreach ($profile in $userProfiles) {
    if ($profile.SID -and $profile.SID -ne "S-1-5-18" -and $profile.SID -ne "S-1-5-19" -and $profile.SID -ne "S-1-5-20") {
        $userRegPath = "HKU:\$($profile.SID)"
        try {
            # Load user hive if not already loaded
            if (!(Test-Path $userRegPath)) {
                reg load "HKU\$($profile.SID)" "$($profile.Path)\NTUSER.DAT" 2>$null
                Start-Sleep 1
            }
            
            $userDellPath = "$userRegPath\SOFTWARE\Dell\Dell Peripheral Manager"
            if (Test-Path $userDellPath) {
                Write-Host "Removing user registry for $($profile.Username): $userDellPath" -ForegroundColor Cyan
                Remove-Item $userDellPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Host "User registry cleanup error for $($profile.Username): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Method 5: Remove from startup (system-wide)
Write-Host "Removing from system startup..." -ForegroundColor Yellow
$startupPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($startupPath in $startupPaths) {
    try {
        $runKeys = Get-ItemProperty $startupPath -ErrorAction SilentlyContinue
        if ($runKeys) {
            $runKeys.PSObject.Properties | Where-Object { 
                $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and
                ($_.Value -like "*Dell*Peripheral*Manager*" -or $_.Name -like "*Dell*Peripheral*")
            } | ForEach-Object {
                Write-Host "Removing startup entry: $($_.Name)" -ForegroundColor Cyan
                Remove-ItemProperty -Path $startupPath -Name $_.Name -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-Host "Startup cleanup error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Method 6: Services cleanup
Write-Host "Processing Dell Peripheral Manager services..." -ForegroundColor Yellow
$services = Get-Service | Where-Object { 
    $_.DisplayName -like "*Dell Peripheral Manager*" -or 
    $_.ServiceName -like "*Dell*Peripheral*" -or
    $_.DisplayName -like "*Dell*Peripheral*"
}

foreach ($service in $services) {
    Write-Host "Processing service: $($service.DisplayName)" -ForegroundColor Cyan
    try {
        Stop-Service $service.ServiceName -Force -ErrorAction SilentlyContinue
        Set-Service $service.ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
        
        # Try to delete the service
        sc.exe delete $service.ServiceName 2>$null
        Write-Host "Service $($service.DisplayName) processed" -ForegroundColor Green
    } catch {
        Write-Host "Service processing error: $($service.DisplayName) - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Method 7: Windows Apps/Store packages (if applicable)
Write-Host "Checking for Windows Store packages..." -ForegroundColor Yellow
try {
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*Dell*Peripheral*" } | ForEach-Object {
        Write-Host "Removing Windows App: $($_.Name)" -ForegroundColor Cyan
        Remove-AppxPackage $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "Windows Apps cleanup error: $($_.Exception.Message)" -ForegroundColor Red
}

# Final cleanup - Scheduled tasks
Write-Host "Removing scheduled tasks..." -ForegroundColor Yellow
try {
    Get-ScheduledTask | Where-Object { $_.TaskName -like "*Dell*Peripheral*" -or $_.TaskPath -like "*Dell*Peripheral*" } | ForEach-Object {
        Write-Host "Removing scheduled task: $($_.TaskName)" -ForegroundColor Cyan
        Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "Scheduled task cleanup error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nDell Peripheral Manager removal process completed!" -ForegroundColor Green
Write-Host "SYSTEM context cleanup finished. Changes will take effect immediately." -ForegroundColor Yellow

# Create a completion flag for Action1 monitoring
$flagPath = "$env:TEMP\DellPM_Removal_Complete.txt"
"Dell Peripheral Manager removal completed at $(Get-Date)" | Out-File $flagPath -Force

Write-Host "Completion flag created at: $flagPath" -ForegroundColor Cyan

# Additional cleanup - Force remove any remaining Dell Peripheral Manager entries
Write-Host "`nPerforming final Add/Remove Programs cleanup..." -ForegroundColor Yellow

# Search for any remaining entries that might use different naming patterns
$additionalPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($path in $additionalPaths) {
    try {
        Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
            $displayName = $_.GetValue("DisplayName")
            $publisher = $_.GetValue("Publisher")
            
            # Check for Dell Peripheral Manager with various naming patterns
            if (($displayName -like "*Dell*Peripheral*" -and $displayName -like "*Manager*") -or
                ($displayName -like "*DellPeripheral*") -or
                ($publisher -like "*Dell*" -and $displayName -like "*Peripheral*") -or
                ($_.PSChildName -like "*Dell*" -and $displayName -like "*Peripheral*")) {
                
                Write-Host "Found additional entry to remove: $displayName" -ForegroundColor Cyan
                try {
                    Remove-Item $_.PSPath -Recurse -Force -ErrorAction Stop
                    Write-Host "Successfully removed: $displayName" -ForegroundColor Green
                } catch {
                    # Fallback to reg.exe
                    $regPath = $_.PSPath -replace "Microsoft.PowerShell.Core\\Registry::", "" -replace "HKEY_LOCAL_MACHINE", "HKLM"
                    & reg delete "$regPath" /f 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "Successfully removed via reg.exe: $displayName" -ForegroundColor Green
                    } else {
                        Write-Host "Failed to remove: $displayName" -ForegroundColor Red
                    }
                }
            }
        }
    } catch {
        Write-Host "Additional cleanup error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nAdd/Remove Programs cleanup completed!" -ForegroundColor Green
