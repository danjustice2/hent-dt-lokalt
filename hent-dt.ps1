﻿try {

    #--- Log Setup ---
    function Write-Log {
        param ([string]$message, [string]$type = 'INFO')
        Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$type] - $message"
    }


    #--- Robust User Context Retrieval ---
    try {
        $loggedOnUserFull = (Get-CimInstance -ClassName Win32_ComputerSystem).Username
        if ([string]::IsNullOrWhiteSpace($loggedOnUserFull)) {
            throw "No logged-in user found. Ensure a user is logged into the system."
        }

        $username = $loggedOnUserFull.Split('\')[-1]  # Extract Username portion

        # Get the exact user profile path of the logged-in and loaded user
        $userProfilePath = (Get-CimInstance -Class Win32_UserProfile | 
                             Where-Object { $_.LocalPath -like "*\$username" -and $_.Loaded -eq $true } |
                             Select-Object -ExpandProperty LocalPath -First 1)

        if ([string]::IsNullOrEmpty($userProfilePath)) {
            throw "Unable to locate the profile path for user $username. Ensure the user's profile is loaded."
        }

        # Construct the Roaming AppData Path reliably
        $CurrentUserProfilePath = Join-Path $userProfilePath "AppData\Roaming"

        Write-Log "Currently logged-in user's profile resolved: $CurrentUserProfilePath"
    }
    catch {
        Write-Log "An error occurred attempting to resolve current user's path: $_" "ERROR"
        exit 1
    }

    #--- Variables Setup ---
    $LogonUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName).Split('\')[1]
    $UserSID = (New-Object System.Security.Principal.NTAccount($LogonUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value

    $sourcePath          = "Q:\DynamicTemplate"
    $destinationPath = Join-Path $CurrentUserProfilePath "dynamictemplate\lokaltest"
    $configFilePath = Join-Path $CurrentUserProfilePath "dania software\ConfigSolution\Setup.xml"
    $backupFilePath = "$configFilePath.$(Get-Date -Format 'yyyyMMddHHmmss').bak"
    $registryValue  = Join-Path $CurrentUserProfilePath "dynamictemplate\lokaltest"
    $registryValue       = Join-Path $CurrentUserProfilePath "dynamictemplate\lokaltest"
    $excludedFolder      = "Q:\dynamictemplate\Fraser"
    $registryPath = 'HKLM:\SOFTWARE\WOW6432Node\dania software'


    #--- Functions ---
    function Test-IsElevated {
        $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }

    function Ensure-Elevation {
        if (-not (Test-IsElevated)) {
            Write-Log "Elevation required. Attempting to restart script as administrator." "INFO"
            try {
                Start-Process -FilePath "powershell.exe" `
                              -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`"" `
                              -Verb RunAs `
                              -Wait
                Exit
            }
            catch {
                Write-Log "Failed to restart with elevated privileges. $_" "ERROR"
                Read-Host "Press Enter to exit..."
                Exit 1
            }
        } else {
            Write-Log "Already running with elevated privileges." "INFO"
        }
    }

    function Map-NetworkDrive {
        param ($driveLetter, $networkPath)
        if (-not (Test-Path "$driveLetter`:\")) {
            Write-Log "Mapping drive $driveLetter to $networkPath." "INFO"
            net use "$driveLetter`:" $networkPath /persistent:no | Out-Null
            Start-Sleep -Seconds 3
            if (-not (Test-Path "$driveLetter`:\")) {
                throw "Failed to map drive $driveLetter to $networkPath."
            } else {
                Write-Log "Drive $driveLetter mapped successfully." "INFO"
            }
        } else {
            Write-Log "Drive $driveLetter already mapped." "INFO"
        }
    }

    function Ensure-Directory {
        param ($path)
        if (-not(Test-Path -Path $path)) {
            Write-Log "Creating directory: $path" "INFO"
            New-Item -Path $path -ItemType Directory -Force | Out-Null
        }
    }

    function Copy-Files {
        param ($source, $destination, $exclude)
        Write-Log "Starting file copy from '$source' to '$destination', excluding '$exclude'." "INFO"
        Get-ChildItem -Path $source -Recurse |
        Where-Object { $_.FullName -notlike "$exclude*" } |
        ForEach-Object {
            if (-not $_.PSIsContainer) {
                $destFile = Join-Path $destination $_.FullName.Substring($source.Length).TrimStart('\')
                $destDir = Split-Path $destFile
                Ensure-Directory $destDir

                if (-not(Test-Path -Path $destFile)) {
                    Copy-Item $_.FullName $destFile -Force
                    Write-Log "Copied: $($_.FullName) to $destFile" "INFO"
                } else {
                    Write-Log "Skipped existing file: $destFile" "INFO"
                }
            }
        }
    }

    function Backup-XML {
        param ($xmlPath, $backupPath)
        if (Test-Path $xmlPath) {
            Copy-Item -Path $xmlPath -Destination $backupPath -Force
            Write-Log "XML backup created at '$backupPath'." "INFO"
        } else {
            Write-Log "XML file not found at '$xmlPath'. Backup skipped." "WARN"
        }
    }

    function Update-XML {
        param ($xmlPath)
        [xml]$xml = Get-Content -Path $xmlPath

        if (-not $xml.Setup.LocationsOnline) {
            $locationsOnline = $xml.CreateElement("LocationsOnline")
            $xml.Setup.AppendChild($locationsOnline) | Out-Null
        }

        $pathsToSet = @{
            TemplatePath   = "$destinationPath\Skabeloner"
            PhrasePath     = "$excludedFolder"
            ResourcePath   = "$destinationPath\Ressourcer"
            XmlPath        = "$destinationPath\XML"
            SignaturePath  = "$destinationPath\Signaturer"
            ProfilePath    = "$destinationPath\Profiler"
        }

        foreach ($node in $pathsToSet.Keys) {
            if (-not $xml.Setup.LocationsOnline.$node) {
                $newNode = $xml.CreateElement($node)
                $xml.Setup.LocationsOnline.AppendChild($newNode) | Out-Null
            }
            $xml.Setup.LocationsOnline.$node = $pathsToSet[$node]
        }

        $xml.Save($xmlPath)
        Write-Log "XML file '$xmlPath' updated successfully." "INFO"
    }

    function Update-Registry {
        param ($path, $name, $value)
        if (-not(Test-Path -Path $path)) {
            Write-Log "Registry path '$path' missing. Creating." "INFO"
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name $name -Value $value -Force
        Write-Log "Registry value '$name' set to '$value'." "INFO"
    }

    #--- Main Script Execution ---
    try {
        Ensure-Elevation  # Restart script as admin if not already elevated.

        Write-Log "Starting script execution as user: $LogonUser"

        Map-NetworkDrive -driveLetter 'Q' -networkPath '\\srafil01v\prog'

        # Ensure required directories
        Ensure-Directory $destinationPath

        # Copy necessary files
        Copy-Files -source $sourcePath -destination $destinationPath -exclude $excludedFolder

        # Backup and update XML configuration
        Backup-XML -xmlPath $configFilePath -backupPath $backupFilePath
        Update-XML -xmlPath $configFilePath

        # Copy updated XML to destination
        Copy-Item -Path $configFilePath -Destination "$destinationPath\Setup.xml" -Force
        Write-Log "Copied updated Setup.xml to '$destinationPath'." "INFO"

        # Update Registry
        Update-Registry -path $registryPath -name 'SystemPath' -value $registryValue

        Write-Log "Script execution completed successfully." "INFO"
    }
    catch {
        Write-Log "An error occurred: $_" "ERROR"
        exit 1
    }
}
catch {
    Write-Log "An unexpected error occurred: $_" "ERROR"
    Read-Host "Press Enter to close the window and exit..."
    Exit 1
}

Read-Host "Script execution completed. Press Enter to close this window." 