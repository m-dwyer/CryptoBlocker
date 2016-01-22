# DeployCryptoBlocker.ps1
#
# This script performs the following actions:
# 1) Checks for network shares
# 2) Install File Server Resource Manager (FSRM) if missing
# 3) Creates Batch and PowerShell scripts used by FSRM
# 4) Creates a File Group within FSRM containing malicious extensions to screen on
# 5) Creates a File Screen Template utilising this File Group, with an Event notification and Command notification
#    to run the scripts created in Step 3)
# 6) Creates File Screens utilising this template for each drive containing network shares

################################ Functions ################################

Function PurgeNonAdminDirectoryPermissions([string] $directory)
{
    $acl = Get-Acl $directory

    if ($acl.AreAccessRulesProtected)
    {
        $acl.Access | % { $acl.PurgeAccessRules($_.IdentityReference) }
    }
    else
    {
        $acl.SetAccessRuleProtection($true, $true)
    }

    $ar = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
    $acl.AddAccessRule($ar)
    $ar = $ar = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","Allow")
    $acl.AddAccessRule($ar)
    Set-Acl -AclObject $acl -Path $directory
}


################################ Functions ################################

# Add to all drives
$drivesContainingShares = Get-WmiObject Win32_Share | Select Name,Path,Type | Where-Object { $_.Type -eq 0 } | Select -ExpandProperty Path | % { "$((Get-Item -ErrorAction SilentlyContinue $_).Root)" } | Select -Unique
if ($drivesContainingShares -eq $null -or $drivesContainingShares.Length -eq 0)
{
    Write-Host "No drives containing shares were found. Exiting.."
    exit
}

Write-Host "The following shares needing to be protected: $($drivesContainingShares -Join ",")"

$majorVer = [System.Environment]::OSVersion.Version.Major
$minorVer = [System.Environment]::OSVersion.Version.Minor

Write-Host "Checking File Server Resource Manager.."

Import-Module ServerManager

if ($majorVer -ge 6)
{
    $checkFSRM = Get-WindowsFeature -Name FS-Resource-Manager

    if ($minorVer -ge 2 -and $checkFSRM.Installed -ne "True")
    {
        # Server 2012
        Write-Host "FSRM not found.. Installing (2012).."
        Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
    }
    elseif ($minorVer -ge 1 -and $checkFSRM.Installed -ne "True")
    {
        # Server 2008 R2
        Write-Host "FSRM not found.. Installing (2008 R2).."
        Add-WindowsFeature FS-FileServer, FS-Resource-Manager
    }
    elseif ($checkFSRM.Installed -ne "True")
    {
        # Server 2008
        Write-Host "FSRM not found.. Installing (2008).."
        &servermanagercmd -Install FS-FileServer FS-Resource-Manager
    }
}
else
{
    # Assume Server 2003
    Write-Host "Other version of Windows detected! Quitting.."
    return
}

$fileGroupName = "CryptoBlockerGroup"
$fileTemplateName = "CryptoBlockerTemplate"
$fileScreenName = "CryptoBlockerScreen"

$monitoredExtensions = @(
    "*.cryptotorlocker*",
    "*.encrypted",
    "*.frtrss",
    "*.vault",
    "*want your files back.*",
    "confirmation.key",
    "cryptolocker.*",
    "*decrypt_instruct*",
    "enc_files.txt",
    "*help_decrypt*",
    "help_restore*.*",
    "how to decrypt*.*",
    "how_to_decrypt*",
    "how_to_recover*",
    "howtodecrypt*",
    "install_tor*.*",
    "last_chance.txt",
    "recovery_file.txt",
    "recovery_key.txt",
    "vault.hta",
    "vault.key",
    "vault.txt",
    "HOW_TO_RECOVER_FILES.*",
    "HELP_YOUR_FILES*"
)

$scriptFilename = "C:\FSRMScripts\KillUserSession.ps1"
$batchFilename = "C:\FSRMScripts\KillUserSession.bat"
$eventConfFilename = "$env:Temp\cryptoblocker-eventnotify.txt"
$cmdConfFilename = "$env:Temp\cryptoblocker-cmdnotify.txt"

$scriptConf = @'
param([string] $DomainUser)

Function DenySharePermission ([string] $ShareName, [string] $DomainUser)
{
    $domainUserSplit = $DomainUser.Split("\")

    $trusteeClass = [wmiclass] "ROOT\CIMV2:Win32_Trustee"
    $trustee = $trusteeClass.CreateInstance()
    $trustee.Domain = $domainUserSplit[0]
    $trustee.Name = $domainUserSplit[1]

    $aceClass = [wmiclass] "ROOT\CIMV2:Win32_ACE"
    $ace = $aceClass.CreateInstance()
    $ace.AccessMask = 2032127
    $ace.AceType = 1
    $ace.Trustee = $trustee

    $shss = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$ShareName'"
    $sd = Invoke-WmiMethod -InputObject $shss -Name GetSecurityDescriptor | Select -ExpandProperty Descriptor

    $sclass = [wmiclass] "ROOT\CIMV2:Win32_SecurityDescriptor"
    $newsd = $sclass.CreateInstance()
    $newsd.ControlFlags = $sd.ControlFlags

    foreach ($oace in $sd.DACL)
    {
        $newsd.DACL +=  [System.Management.ManagementBaseObject] $oace
    }

    $newsd.DACL += [System.Management.ManagementBaseObject] $ace

    $share = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$ShareName'"
    $setResult = $share.SetSecurityDescriptor($newsd)

    return $setResult.ReturnValue
}


# Let's try altering share permissions..
$Username = $DomainUser.Split("\")[1]

$affectedShares = Get-WmiObject -Class Win32_Share |
                    Select Name, Path, Type |
                    Where { $_.Type -eq 0 }

$affectedShares | % {
    Write-Host "Denying [$DomainUser] access to share [$($_.Name)].."
    DenySharePermission -ShareName $_.Name -DomainUser $DomainUser
}

Write-Host $affectedShares
'@

$batchConf = @"
@echo off
powershell.exe -ExecutionPolicy Bypass -File "$scriptFilename" -DomainUser %1
"@

$scriptDirectory = Split-Path -Parent $scriptFilename
$batchDirectory = Split-Path -Parent $batchFilename

if (-not (Test-Path $scriptDirectory))
{
    Write-Host "Script directory [$scriptDirectory] not found. Creating.."
    New-Item -Path $scriptDirectory -ItemType Directory
}

if (-not (Test-Path $batchDirectory))
{
    Write-Host "Batch directory [$batchDirectory] not found. Creating.."
    New-Item -Path $batchDirectory -ItemType Directory
}

# FSRM stipulates that the command directories/files can only be accessible by SYSTEM or Administrators
# As a result, we lock down permissions for SYSTEM and local admin only
Write-Host "Purging Non-Admin NTFS permissions on script directory [$scriptDirectory].."
PurgeNonAdminDirectoryPermissions($scriptDirectory)
Write-Host "Purging Non-Admin NTFS permissions on batch directory [$batchDirectory].."
PurgeNonAdminDirectoryPermissions($batchDirectory)

Write-Host "Writing defensive PowerShell script to location [$scriptFilename].."
$scriptConf | Out-File -Encoding ASCII $scriptFilename
Write-Host "Writing batch script launcher to location [$batchFilename].."
$batchConf | Out-File -Encoding ASCII $batchFilename

$eventConf = @"
Notification=E
RunLimitInterval=0
EventType=Warning
Message=User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server.  An attempt has been made at blocking this user.
"@

$cmdConf = @"
Notification=C
RunLimitInterval=0
Command=$batchFilename
Arguments=[Source Io Owner]
MonitorCommand=Enable
Account=LocalSystem
"@

Write-Host "Writing temporary FSRM Event Viewer configuration to location [$eventConfFilename].."
$eventConf | Out-File $eventConfFilename
Write-Host "Writing temporary FSRM Command configuration to location [$cmdConfFilename].."
$cmdConf | Out-File $cmdConfFilename

Write-Host "Adding/replacing File Group [$fileGroupName] with monitored file [$($monitoredExtensions -Join ",")].."
&filescrn.exe filegroup Delete /Filegroup:$fileGroupName /Quiet
&filescrn.exe Filegroup Add "/Filegroup:$fileGroupName" "/Members:$($monitoredExtensions -Join "|")"

Write-Host "Adding/replacing File Screen Template [$fileTemplateName] with Event Notification [$eventConfFilename] and Command Notification [$cmdConfFilename].."
&filescrn.exe Template Delete /Template:$fileTemplateName /Quiet
&filescrn.exe Template Add "/Template:$fileTemplateName" "/Add-Filegroup:$fileGroupName" "/Add-Notification:E,$eventConfFilename" "/Add-Notification:C,$cmdConfFilename" /Type:Passive

Write-Host "Adding/replacing File Screens.."
$drivesContainingShares | % {
    Write-Host "`tAdding/replacing File Screen for [$_] with Source Template [$fileTemplateName].."
    &filescrn.exe Screen Delete "/Path:$_" /Quiet
    &filescrn.exe Screen Add "/Path:$_" "/SourceTemplate:$fileTemplateName"
}

Write-Host "Removing temporary FSRM Event Viewer configuration file [$eventConfFilename].."
Write-Host "Removing temporary FSRM Event Viewer configuration file [$cmdConfFilename].."
Remove-Item $eventConfFilename
Remove-Item $cmdConfFilename
