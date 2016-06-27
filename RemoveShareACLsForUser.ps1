Param([string]$userName)

Function RemoveSharePermission ([string] $ShareName, [string] $DomainUser)
{
    $domainUserSplit = $DomainUser.Split("\")

    $shss = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$ShareName'"
    $sd = Invoke-WmiMethod -InputObject $shss -Name GetSecurityDescriptor | Select -ExpandProperty Descriptor

    $sclass = [wmiclass] "ROOT\CIMV2:Win32_SecurityDescriptor"
    $newsd = $sclass.CreateInstance()
    $newsd.ControlFlags = $sd.ControlFlags

    foreach ($oace in $sd.DACL)
    {
        if ($oace.Trustee.Domain -eq $domainUserSplit[0] -and `
            $oace.Trustee.Name -eq $domainUserSplit[1] -and `
            $oace.AceType -eq 1) {
            # Remove Deny ACLs only - we simply don't copy it to the new ACL.
            Write-Host "Removing ACL for [$DomainUser] on share [$ShareName]..."
        } else {
            # Copy this ACE to the new ACL.
            $newsd.DACL +=  [System.Management.ManagementBaseObject] $oace
        }
    }

    $share = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$ShareName'"
    $setResult = $share.SetSecurityDescriptor($newsd)

    #return $setResult.ReturnValue
}

# Verify the script is being run as an administrator
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] “Administrator”))
{
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}

if ($userName -eq "") {
	# Request the username
	Write-Host "This script will remove the Deny ACLs that were created on shares`nto protect against crypto virus infection.`n"
	$DomainUser = Read-Host -Prompt "User account (DOMAIN\User)"
} else {
	$DomainUser = $userName
}

# Let's try altering share permissions..
$Username = $DomainUser.Split("\")[1]

$affectedShares = Get-WmiObject -Class Win32_Share |
                    Select Name, Path, Type |
                    Where { $_.Type -eq 0 }

$affectedShares | % { RemoveSharePermission -ShareName $_.Name -DomainUser $DomainUser }

#Write-Host $affectedShares
