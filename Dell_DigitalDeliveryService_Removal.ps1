# PowerShell Script to Force Uninstall Dell Digital Delivery Service
# Optimized for SYSTEM user context (Action1, SCCM, etc.)

Write-Host "Starting Dell Digital Delivery Service removal process (SYSTEM context)..." -ForegroundColor Green

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

# Stop any running Dell Digital Delivery processes for all users
Write-Host "Stopping Dell Digital Delivery processes..." -ForegroundColor Yellow
$processes = @("DellDigitalDelivery", "Dell.DigitalDelivery", "DellDigitalDeliveryService", "Dell Digital Delivery", "DellDDS", "DellDigitalDelivery*", "DigitalDelivery*", "DellDD*")
foreach ($processPattern in $processes) {
    Get-Process -Name $processPattern -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# Method 1: Uninstall via WMI (works in SYSTEM context)
Write-Host "Attempting uninstall via WMI..." -ForegroundColor Yellow
try {
    $apps = Get-WmiObject -Class Win32_Product | Where-Object { 
        $_.Name -like "*Dell Digital Delivery*" -or 
        $_.Name -like "*DellDigitalDelivery*" -or
        $_.Name -like "*Dell*Digital*Delivery*" -or
        $_.Name -like "*Digital Delivery*" -and $_.Vendor -like "*Dell*"
    }
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
            $publisher = $key.GetValue("Publisher")
            if (($displayName -like "*Dell Digital Delivery*") -or 
                ($displayName -like "*DellDigitalDelivery*") -or
                ($displayName -like "*Dell*Digital*Delivery*") -or
                ($displayName -like "*Digital Delivery*" -and $publisher -like "*Dell*")) {
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
                                $arguments = "/X$msiCode /quiet /norestart /L*v `"$env:TEMP\DellDigitalDelivery_Uninstall.log`""
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
    "$env:ProgramFiles\Dell\Dell Digital Delivery",
    "$env:ProgramFiles\Dell\DellDigitalDelivery",
    "$env:ProgramFiles\Dell Digital Delivery",
    "$env:ProgramFiles\DellDigitalDelivery",
    "$env:ProgramFiles\Dell\Digital Delivery",
    "$env:ProgramFiles\Digital Delivery",
    "${env:ProgramFiles(x86)}\Dell\Dell Digital Delivery",
    "${env:ProgramFiles(x86)}\Dell\DellDigitalDelivery",
    "${env:ProgramFiles(x86)}\Dell Digital Delivery",
    "${env:ProgramFiles(x86)}\DellDigitalDelivery",
    "${env:ProgramFiles(x86)}\Dell\Digital Delivery",
    "${env:ProgramFiles(x86)}\Digital Delivery",
    "$env:ProgramData\Dell\Dell Digital Delivery",
    "$env:ProgramData\Dell\DellDigitalDelivery",
    "$env:ProgramData\Dell Digital Delivery",
    "$env:ProgramData\DellDigitalDelivery",
    "$env:ALLUSERSPROFILE\Dell\Dell Digital Delivery",
    "$env:ALLUSERSPROFILE\Dell\DellDigitalDelivery",
    "$env:ALLUSERSPROFILE\Dell Digital Delivery",
    "$env:ALLUSERSPROFILE\DellDigitalDelivery"
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
        "$($profile.Path)\AppData\Local\Dell\Dell Digital Delivery",
        "$($profile.Path)\AppData\Local\Dell\DellDigitalDelivery",
        "$($profile.Path)\AppData\Local\Dell Digital Delivery",
        "$($profile.Path)\AppData\Local\DellDigitalDelivery",
        "$($profile.Path)\AppData\Roaming\Dell\Dell Digital Delivery",
        "$($profile.Path)\AppData\Roaming\Dell\DellDigitalDelivery",
        "$($profile.Path)\AppData\Roaming\Dell Digital Delivery",
        "$($profile.Path)\AppData\Roaming\DellDigitalDelivery"
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
Write-Host "Cleaning Dell Digital Delivery registry entries..." -ForegroundColor Yellow
$regPaths = @(
    "HKLM:\SOFTWARE\Dell\Dell Digital Delivery",
    "HKLM:\SOFTWARE\Dell\DellDigitalDelivery",
    "HKLM:\SOFTWARE\Dell Digital Delivery",
    "HKLM:\SOFTWARE\DellDigitalDelivery",
    "HKLM:\SOFTWARE\Dell\Digital Delivery",
    "HKLM:\SOFTWARE\WOW6432Node\Dell\Dell Digital Delivery",
    "HKLM:\SOFTWARE\WOW6432Node\Dell\DellDigitalDelivery",
    "HKLM:\SOFTWARE\WOW6432Node\Dell Digital Delivery",
    "HKLM:\SOFTWARE\WOW6432Node\DellDigitalDelivery",
    "HKLM:\SOFTWARE\WOW6432Node\Dell\Digital Delivery"
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
            
            $userDellPaths = @(
                "$userRegPath\SOFTWARE\Dell\Dell Digital Delivery",
                "$userRegPath\SOFTWARE\Dell\DellDigitalDelivery",
                "$userRegPath\SOFTWARE\Dell Digital Delivery",
                "$userRegPath\SOFTWARE\DellDigitalDelivery"
            )
            
            foreach ($userDellPath in $userDellPaths) {
                if (Test-Path $userDellPath) {
                    Write-Host "Removing user registry for $($profile.Username): $userDellPath" -ForegroundColor Cyan
                    Remove-Item $userDellPath -Recurse -Force -ErrorAction SilentlyContinue
                }
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
                ($_.Value -like "*Dell*Digital*Delivery*" -or $_.Name -like "*Dell*Digital*Delivery*" -or $_.Name -like "*DellDigitalDelivery*")
            } | ForEach-Object {
                Write-Host "Removing startup entry: $($_.Name)" -ForegroundColor Cyan
                Remove-ItemProperty -Path $startupPath -Name $_.Name -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-Host "Startup cleanup error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Method 6: Services cleanup (Enhanced for Dell Digital Delivery services)
Write-Host "Processing Dell Digital Delivery services..." -ForegroundColor Yellow
$services = Get-Service | Where-Object { 
    $_.DisplayName -like "*Dell Digital Delivery*" -or 
    $_.DisplayName -like "*DellDigitalDelivery*" -or
    $_.DisplayName -like "*Digital Delivery*" -or
    $_.ServiceName -like "*Dell*Digital*Delivery*" -or
    $_.ServiceName -like "*DellDigitalDelivery*" -or
    $_.ServiceName -like "*DellDDS*" -or
    $_.ServiceName -like "*DigitalDelivery*"
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

# Additional service cleanup using WMI
Write-Host "Additional service cleanup via WMI..." -ForegroundColor Yellow
try {
    Get-WmiObject -Class Win32_Service | Where-Object {
        $_.DisplayName -like "*Dell Digital Delivery*" -or
        $_.DisplayName -like "*Digital Delivery*" -or
        $_.Name -like "*Dell*Digital*Delivery*" -or
        $_.Name -like "*DellDigitalDelivery*" -or
        $_.Name -like "*DellDDS*"
    } | ForEach-Object {
        Write-Host "Stopping and deleting WMI service: $($_.DisplayName)" -ForegroundColor Cyan
        try {
            $_.StopService() | Out-Null
            $_.Delete() | Out-Null
            Write-Host "WMI service deleted: $($_.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Host "WMI service deletion failed: $($_.DisplayName)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "WMI service cleanup error: $($_.Exception.Message)" -ForegroundColor Red
}

# Method 7: Windows Apps/Store packages (if applicable)
Write-Host "Checking for Windows Store packages..." -ForegroundColor Yellow
try {
    Get-AppxPackage -AllUsers | Where-Object { 
        $_.Name -like "*Dell*Digital*Delivery*" -or 
        $_.Name -like "*DellDigitalDelivery*" -or
        $_.Name -like "*DigitalDelivery*" -and $_.Publisher -like "*Dell*"
    } | ForEach-Object {
        Write-Host "Removing Windows App: $($_.Name)" -ForegroundColor Cyan
        Remove-AppxPackage $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "Windows Apps cleanup error: $($_.Exception.Message)" -ForegroundColor Red
}

# Method 8: Scheduled tasks cleanup
Write-Host "Removing scheduled tasks..." -ForegroundColor Yellow
try {
    Get-ScheduledTask | Where-Object { 
        $_.TaskName -like "*Dell*Digital*Delivery*" -or 
        $_.TaskName -like "*DellDigitalDelivery*" -or
        $_.TaskName -like "*DigitalDelivery*" -or
        $_.TaskPath -like "*Dell*Digital*Delivery*" -or
        $_.TaskPath -like "*DellDigitalDelivery*"
    } | ForEach-Object {
        Write-Host "Removing scheduled task: $($_.TaskName)" -ForegroundColor Cyan
        Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "Scheduled task cleanup error: $($_.Exception.Message)" -ForegroundColor Red
}

# Method 9: COM Objects cleanup (Dell Digital Delivery may register COM objects)
Write-Host "Checking for Dell Digital Delivery COM objects..." -ForegroundColor Yellow
try {
    $comKeys = @(
        "HKLM:\SOFTWARE\Classes\CLSID",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID"
    )
    
    foreach ($comPath in $comKeys) {
        if (Test-Path $comPath) {
            Get-ChildItem $comPath -ErrorAction SilentlyContinue | ForEach-Object {
                $defaultValue = $_.GetValue("", "")
                if ($defaultValue -like "*Dell*Digital*Delivery*" -or $defaultValue -like "*DellDigitalDelivery*") {
                    Write-Host "Found COM object: $defaultValue" -ForegroundColor Cyan
                    try {
                        Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "Removed COM object: $defaultValue" -ForegroundColor Green
                    } catch {
                        Write-Host "Failed to remove COM object: $defaultValue" -ForegroundColor Red
                    }
                }
            }
        }
    }
} catch {
    Write-Host "COM object cleanup error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nDell Digital Delivery Service removal process completed!" -ForegroundColor Green
Write-Host "SYSTEM context cleanup finished. Changes will take effect immediately." -ForegroundColor Yellow

# Create a completion flag for Action1 monitoring
$flagPath = "$env:TEMP\DellDigitalDelivery_Removal_Complete.txt"
"Dell Digital Delivery Service removal completed at $(Get-Date)" | Out-File $flagPath -Force

Write-Host "Completion flag created at: $flagPath" -ForegroundColor Cyan

# Additional cleanup - Force remove any remaining Dell Digital Delivery entries
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
            
            # Check for Dell Digital Delivery with various naming patterns
            if (($displayName -like "*Dell*" -and $displayName -like "*Digital*" -and $displayName -like "*Delivery*") -or
                ($displayName -like "*DellDigitalDelivery*") -or
                ($publisher -like "*Dell*" -and $displayName -like "*Digital*Delivery*") -or
                ($_.PSChildName -like "*Dell*" -and $displayName -like "*Digital*Delivery*") -or
                ($displayName -like "*Digital Delivery*" -and $publisher -like "*Dell*")) {
                
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
