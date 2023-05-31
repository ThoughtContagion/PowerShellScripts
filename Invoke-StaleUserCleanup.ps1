[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Int32]
    $range
)
# Import the Active Directory Module
Import-module activedirectory

$admin = $env:USERNAME

$date = Get-Date -Format "yyyy-MM-dd"

If (Test-Path "$psscriptroot\Disabled_Users_$date.log") {
    Start-Transcript -IncludeInvocationHeader -Path "$psscriptroot\Disabled_Users_$date.log" -Append
}
Else {
    Start-Transcript -IncludeInvocationHeader -Path "$psscriptroot\Disabled_Users_$date.log"
}

$stale_accounts = Get-ADUser -filter { Enabled -eq $true } -properties LastLogonDate | Where-Object { ($_.samaccountname -notlike "krbtgt*") -and ($_.lastlogondate -lt (Get-Date).adddays(-$range)) }

$serviceAccts = $stale_accounts | Where-Object { ($_.ServicePrincipalNames -like "*") -and ($_.samaccountname -notlike "krbtgt") }

If ($serviceAccts.count -gt 0) {
    $serviceAccts | Export-Csv "$psscriptroot\Potential_Service_Accounts.csv" -NoTypeInformation
}

$toDisable = $stale_accounts | Where-Object { $_ -notin $serviceAccts }

Write-Host "$($stale_accounts.count) stale accounts were found. $($serviceAccts.Count) possible Service Accounts were found.`nPotential Service Accounts will not be modified and can be reviewed in the output file $psscriptroot\Potential_Service_Accounts.csv. $($toDisable.count) accounts will be disabled.`nA log of all activity will be recorded in $psscriptroot\Disabled_Users_$date.log`n`n"

$total = 0

Foreach ($account in $toDisable) {
    Disable-ADAccount -identity $account
    Set-ADUser $account -Description "Disabled by $admin $date"
    #Write-Host "$account disabled by $admin on $date"
    $total++
    Write-Progress -Activity "Processing and disabling users" -Status "$total of $($toDisable.Count) accounts processed" -PercentComplete (($total / $toDisable.Count) * 100)
}

Stop-Transcript