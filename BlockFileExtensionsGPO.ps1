# --------------------------------------------------
# BlockFileExtensionsGPO.ps1
# --------------------------------------------------
# This script creates a GPO to block certain questionable file extensions using a software restriction policy
# GPO Name and extensions to block can be modified below.  By default, the GPO is linked to the domain

$blockedFileExtensions = "VBS,JS,COM,BAT,SCR,PIF"

Import-Module ActiveDirectory

Function ConvertTo-WmiFilter([Microsoft.ActiveDirectory.Management.ADObject[]] $ADObject)
{
    $gpDomain = New-Object -Type Microsoft.GroupPolicy.GPDomain
    $ADObject | ForEach-Object { 
        $path = 'MSFT_SomFilter.Domain="' + $gpDomain.DomainName + '",ID="' + $_.Name + '"'

        try
        {
            $filter = $gpDomain.GetWmiFilter($path)
        }
        catch { }

        if ($filter)
        {
            [Guid]$guid = $_.Name.Substring(1, $_.Name.Length - 2)
            $filter | Add-Member -MemberType NoteProperty -Name Guid -Value $Guid -PassThru | Add-Member -MemberType NoteProperty -Name Content -Value $_."msWMI-Parm2" -PassThru
        }
    }
}

Function New-SoftwareRestrictionGPO($GpoName, $ParanoidExtensions, $WmiFilter)
{
    Set-StrictMode -Version 2

    # Just in case GPMC modules are missing..
    Import-Module ServerManager
    Add-WindowsFeature GPMC
    Import-Module GroupPolicy

    $existingGpo = Get-GPO -Name $GpoName

    if ($existingGPO -ne $null)
    {
        Remove-GPO -Name $GpoName
    }

    $newGPO = New-GPO -Name $GpoName

    $newGPO.WmiFilter = $WmiFilter
    
    $nLevel = 0
    $settingsKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"

    $fileTimeNow = (Get-Date).ToFileTime()

    # Set global parameters
    Set-GPRegistryValue -Name $GpoName -Key "$settingsKey" `
    -Type MultiString -ValueName "ExecutableTypes" -Value "" | Out-Null

    Set-GPRegistryValue -Name $GpoName -Key "$settingsKey" `
    -Type DWord -ValueName "DefaultLevel" -Value 262144 | Out-Null

    Set-GPRegistryValue -Name $GpoName -Key "$settingsKey" `
    -Type DWord -ValueName "PolicyScope" -Value 0 | Out-Null

    Set-GPRegistryValue -Name $GpoName -Key "$settingsKey" `
    -Type DWord -ValueName "TransparentEnabled" -Value 1 | Out-Null

    Set-GPRegistryValue -Name $GpoName -Key "$settingsKey" `
    -Type DWord -ValueName "AuthenticodeEnabled" -Value 0 | Out-Null

    Set-GPRegistryValue -Name $GpoName -Key "$settingsKey" `
    -Type QWord -ValueName "LastModified" -Value $fileTimeNow | Out-Null

    $ParanoidExtensionsSplit = $ParanoidExtensions.Split(",")
    foreach ($paranoidExtension in $ParanoidExtensionsSplit)
    {
        $newPathGUID = [System.Guid]::NewGuid()
        $newPathGUID = "{$newPathGUID}"

        Set-GPRegistryValue -Name $GpoName -Key "$settingsKey\$nLevel\Paths\$newPathGUID" `
        -Type String -ValueName "ItemData" -Value "*.$paranoidExtension" | Out-Null

        Set-GPRegistryValue -Name $GpoName -Key "$settingsKey\$nLevel\Paths\$newPathGUID" `
        -Type DWord -ValueName "SaferFlags" -Value 0 | Out-Null

        Set-GPRegistryValue -Name $GpoName -Key "$settingsKey\$nLevel\Paths\$newPathGUID" `
        -Type QWord -ValueName "LastModified" -Value $fileTimeNow | Out-Null
    }
    
    $domain = (Get-ADDomain).DistinguishedName
    New-GPLink -Name "$GpoName" -Target "$domain"
}

Function New-WMIFilter($FilterName, $FilterDescription, $FilterNamespace, $FilterExpression)
{
    $guid = [System.Guid]::NewGuid()
    $defaultNamingContext = (Get-ADRootDSE).DefaultNamingContext
    $msWMIAuthor = (Get-ADUser $env:USERNAME).UserPrincipleName
    $msWMICreationDate = (Get-Date).ToUniversalTime().ToString("yyyyMMddhhmmss.ffffff-000")
    $wmiGUID = "{$guid}"
    $wmiDistinguishedName = "CN=$wmiGUID,CN=SOM,CN=WMIPolicy,CN=System,$defaultNamingContext"
    $msWMIParm1 = "$FilterDescription "
    $msWMIParm2 = $FilterExpression.Count.ToString() + ";"

    $FilterExpression | ForEach-Object {
        $msWMIParm2 += "3;" + $FilterNamespace.Length + ";" + $_.Length + ";WQL;" + $FilterNamespace + ";" + $_ + ";"
    }

    $existingWmiFilter = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties "msWMI-Name", "msWMI-Parm1" | Where-Object { $_."msWMI-Name" -eq $FilterName } | Select -First 1


    if ($existingWmiFilter -ne $null)
    {
        Remove-ADObject -Identity $existingWmiFilter -Confirm:$false
    }

    $attributes = @{
        "msWMI-Name" = $FilterName;
        "msWMI-Parm1" = $msWMIParm1;
        "msWMI-Parm2" = $msWMIParm2;
        "msWMI-Author" = $msWMIAuthor;
        "instanceType" = 4;
        "msWMI-ID" = $wmiGUID;
        "showInAdvancedViewOnly" = "TRUE";
        "distinguishedname" = $wmiDistinguishedName;
        "msWMI-ChangeDate" = $msWMICreationDate;
        "msWMI-CreationDate" = $msWMICreationDate;
    }

    $wmiPath = ("CN=SOM,CN=WMIPolicy,CN=System,$defaultNamingContext")

    $adObject = New-ADObject -Name $wmiGUID -Type "msWMI-Som" -Path $wmiPath -OtherAttributes $attributes -PassThru

    ConvertTo-WmiFilter $adObject | Write-Output
}

$workstationFilterName = "Workstations"
$2K3TSFilterName = "2003 Terminal Servers"
$2K8TSFilterName = "2008+ Terminal Servers"

# Create WMI filters for workstations, and 200
$workstationFilter = New-WMIFilter -FilterName $workstationFilterName -FilterDescription "Filter on workstations" `
-FilterNamespace "ROOT\CIMV2" -FilterExpression "SELECT * FROM Win32_ComputerSystem WHERE DomainRole = 0 OR DomainRole = 1"

$2K3TSFilter = New-WMIFilter -FilterName $2K3TSFilterName -FilterDescription "Filter on 2003 terminal servers" `
-FilterNamespace 'ROOT\CIMV2' -FilterExpression 'SELECT * FROM Win32_TerminalServiceSetting WHERE LicensingType > 1'

$2K8TSFilter = New-WMIFilter -FilterName $2K8TSFilterName -FilterDescription "Filter on 2008+ terminal servers" `
-FilterNamespace 'ROOT\CIMV2\TerminalServices' -FilterExpression 'SELECT * FROM Win32_TerminalServiceSetting WHERE LicensingType > 1'

New-SoftwareRestrictionGPO -GpoName "Block File Extensions - Workstations" -ParanoidExtensions $blockedFileExtensions -WmiFilter $workstationFilter
New-SoftwareRestrictionGPO -GpoName "Block File Extensions - 2K3 TS" -ParanoidExtensions $blockedFileExtensions -WmiFilter $2K3TSFilter
New-SoftwareRestrictionGPO -GpoName "Block File Extensions - 2K8+ TS" -ParanoidExtensions $blockedFileExtensions -WmiFilter $2K8TSFilter
