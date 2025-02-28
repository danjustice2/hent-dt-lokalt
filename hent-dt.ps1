# Define source and destination paths
$sourcePath = "Q:\DynamicTemplate"
$destinationPath = "$env:APPDATA\dynamictemplate\lokaltest"
$configFilePath = "$env:APPDATA\dania software\ConfigSolution\Setup.xml"
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$backupFilePath = "$configFilePath.$timestamp.bak"

# Function to log messages
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$timestamp - $message"
}

# Function to check for elevated access
function Test-Elevated {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Request elevation if not running with elevated privileges
if (-Not (Test-Elevated)) {
    Log-Message "Script is not running with elevated privileges. Requesting elevation."
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Start logging
Log-Message "Starting script execution."

# Ensure the destination directory exists
if (-Not (Test-Path -Path $destinationPath)) {
    Log-Message "Destination directory '$destinationPath' does not exist. Creating directory."
    New-Item -Path $destinationPath -ItemType Directory
    Log-Message "Directory created."
} else {
    Log-Message "Destination directory '$destinationPath' already exists."
}

# Copy the contents of the source directory to the destination directory, excluding Q:\dynamictemplate\Fraser and skipping existing files
Log-Message "Copying contents from '$sourcePath' to '$destinationPath', excluding 'Q:\dynamictemplate\Fraser' and skipping existing files."
Get-ChildItem -Path $sourcePath -Recurse | Where-Object { $_.FullName -notlike "Q:\dynamictemplate\Fraser*" -and $_.FullName -notlike "Q:\dynamictemplate\Fraser\*" } | ForEach-Object {
    $sourceFile = $_.FullName
    $destinationFile = $destinationPath + $_.FullName.Substring($sourcePath.Length)
    if (-Not (Test-Path -Path $destinationFile)) {
        Log-Message "Copying '$sourceFile' to '$destinationFile'."
        Copy-Item -Path $sourceFile -Destination $destinationFile -Force
    } else {
        Log-Message "Skipping '$sourceFile' as it already exists at '$destinationFile'."
    }
}
Log-Message "Copy operation completed."

# Create a backup of the current Setup.xml file with a timestamp
Log-Message "Creating a backup of the current Setup.xml file with a timestamp."
Copy-Item -Path $configFilePath -Destination $backupFilePath -Force
Log-Message "Backup created at '$backupFilePath'."

# Load the XML file
Log-Message "Loading the XML file from '$configFilePath'."
[xml]$xml = Get-Content -Path $configFilePath

# Update the <LocationsOnline> section
Log-Message "Updating the <LocationsOnline> section in the XML file."
$xml.Setup.LocationsOnline.TemplatePath = "$env:APPDATA\dynamictemplate\lokaltest\Skabeloner"
$xml.Setup.LocationsOnline.PhrasePath = "Q:\dynamictemplate\Fraser"
$xml.Setup.LocationsOnline.ResourcePath = "$env:APPDATA\dynamictemplate\lokaltest\Ressourcer"
$xml.Setup.LocationsOnline.XmlPath = "$env:APPDATA\dynamictemplate\lokaltest\XML"
$xml.Setup.LocationsOnline.SignaturePath = "$env:APPDATA\dynamictemplate\lokaltest\Signaturer"
$xml.Setup.LocationsOnline.ProfilePath = "$env:APPDATA\dynamictemplate\Profiler"

# Save the updated XML file
Log-Message "Saving the updated XML file."
$xml.Save($configFilePath)
Log-Message "XML file saved successfully."

# Copy the modified Setup.xml from the ConfigSolution directory to the lokaltest directory, overwriting if it exists
Log-Message "Copying the modified Setup.xml from the ConfigSolution directory to the lokaltest directory, overwriting if it exists."
Copy-Item -Path $configFilePath -Destination "$destinationPath\Setup.xml" -Force
Log-Message "Modified Setup.xml copied successfully."

# Change the registry value
Log-Message "Changing the registry value for SystemPath."
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\dania software" -Name "SystemPath" -Value "$env:APPDATA\dynamictemplate\lokaltest"
Log-Message "Registry value changed successfully."

Log-Message "Script executed successfully."