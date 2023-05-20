<#
  .SYNOPSIS
  Checks for any administrative roles a given user holds or returns all admins.

  .DESCRIPTION
  Checks for any administrative roles a given user holds or returns all admins.

  .OUTPUTS
  User(s) and the administrative roles held.

  .PARAMETER
  Email

  .PARAMETER
  UserPrincipalName

  .PARAMETER
  DisplayName

  .PARAMETER
  All

  .EXAMPLE
  PS> .\Get-Admins -All

  .EXAMPLE
  PS> .\Get-Admins -Email user@company.com
  
  .EXAMPLE
  PS> .\Get-Admins -UserPrincipalName user@company.onmicrosoft.com
  
  .EXAMPLE
  PS> .\Get-Admins -DisplayName 'First Last'
#>

param (
    [Parameter(Mandatory = $false,
        HelpMessage = 'Search by email address')]
    [string] $Email,
    [Parameter(Mandatory = $false,
        HelpMessage = 'Search by userprincipalname')]
    [string]$UserPrincipalName,
    [Parameter(Mandatory = $false,
        HelpMessage = 'Search by display name')]
    [string]$DisplayName,
    [Parameter(Mandatory = $false,
        HelpMessage = 'Return all users with admin rights')]
    [switch]$All
)

# Connect to the Tenant
Write-Host "Connecting to Microsoft Graph" -ForegroundColor Yellow
Connect-MgGraph -ContextScope Process -Scopes "Directory.Read.All", "User.Read.All", "RoleManagement.Read.Directory", "RoleManagement.Read.All" | Out-Null
Select-MgProfile -Name beta
Write-Host "[+] " -ForegroundColor Green
Write-Host "Connected via Graph to $((Get-MgOrganization).DisplayName)`n`n" -ForegroundColor Yellow

# Get all administrative roles
$adminRoles = (Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/directoryRoles").Value | Where-Object {$_.displayName -match "Administrator"}


If ($All.IsPresent -eq $true){
    $allAdmins = @()

    foreach ($role in $adminRoles){
        $members = (Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/directoryRoles/$($role.id)/members").Value
        
        foreach ($user in $members){
            $allAdmins += "Member: $($user.displayName); MemberType: $((($user.'@odata.type') -split '#microsoft.graph.')[1]); Role: $($role.displayName)"
        }
    }

    Return $allAdmins
}
Else {
    If ($Email){
        $userRoles = @()

        $user = (Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/users?filter=mail eq '$email'").Value

        foreach ($role in $adminRoles){
            $members = (Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/directoryRoles/$($role.id)/members").Value
        
            If ($members.userPrincipalName -eq $user.userPrincipalName){
                $userRoles += $role.displayName
            }
        }

        Return "$($user.displayName) is a member of the following roles: $(($userRoles) -join ',')"
    }
    If ($UserPrincipalName){
        $userRoles = @()

        $user = (Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/users/$UserPrincipalName")

        foreach ($role in $adminRoles){
            $members = (Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/directoryRoles/$($role.id)/members").Value
        
            If ($members.userPrincipalName -eq $user.userPrincipalName){
                $userRoles += $role.displayName
            }
        }

        Return "$($user.displayName) is a member of the following roles: $(($userRoles) -join ',')"
    }
    If ($DisplayName){
        $userRoles = @()

        $user = (Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/users?filter=displayName eq '$DisplayName'").Value

        foreach ($role in $adminRoles){
            $members = (Invoke-GraphRequest -method get -uri "https://graph.microsoft.com/beta/directoryRoles/$($role.id)/members").Value
        
            If ($members.userPrincipalName -eq $user.userPrincipalName){
                $userRoles += $role.displayName
            }
        }

        Return "$($user.displayName) is a member of the following roles: $(($userRoles) -join ',')"
    }
}