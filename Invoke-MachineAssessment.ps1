<#
.Synopsis
    Machine hardening Security Assessment
.Description
    Evaluate the security of a given machine or image per OS hardening best practices
    Author: Carl Littrell 
    GitHub: https://github.com/ThoughtContagion
    Company: Soteria LLC
.Example
    .\Invoke-MachineAssessment.ps1 -OutPath C:\Reports -Organization Big Company, Inc.
#>

param (
	[Parameter(Mandatory = $true,
		HelpMessage = 'Report Destination Path')]
	[string] $OutPath,
    [Parameter(Mandatory = $true,
		HelpMessage = 'Company name')]
	[string] $Organization
)

Try {
    New-Item -ItemType Directory -Force -Path $OutPath | Out-Null
    If ((Test-Path $OutPath) -eq $true){
        $path = Resolve-Path $OutPath
        Write-Output "$($path.Path) created successfully."
    }
}
Catch {
    Write-Error "Directory not created. Please check permissions."
    Exit
}

#CSS codes
$header = @"
<style>

    h1 {
        font-family: "Source Sans Pro";
        color: #4290EB;
        font-size: 28px;
    }
    
    h2 {
        font-family: "Source Sans Pro";
        color: #000099;
        font-size: 16px;
    }
    
   table {
		font-size: 12px;
		border: 0px; 
		font-family: "Source Sans Pro";
	} 
	
    td {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
	
    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }
    
    #CreationDate {

        font-family: "Source Sans Pro";
        color: #ff3300;
        font-size: 12px;

    }

    .StopStatus {

        color: #ff0000;
    }
      
    .RunningStatus {

        color: #008000;
    }

</style>
"@

$compName = $env:computername

<#$reportDetails = @(
    $ComputerName
    $OSinfo
    $TPM
    $HVCI
    $SystemGuard
    $CredentialGuard
    $VBS
    $SecureBoot
    $DMA
    $LoggedinUser
    $AllUsers
    $ProcessInfo
    $BiosInfo
    $DiscInfo
    $ServicesInfo
    $SoftwareInfo
    $ASRStatus
    $FirewallProfiles
    $FirewallRules
    $RSOP
    $LocalAdmins
    $AllLocalGroups
    $AVExclusions
    $Patches
    )#>

#The command below will get the name of the computer
$ComputerName = "<h1>Computer name: $compName</h1>"

#The command below will get the Operating System information
$OSinfo = Get-CimInstance -Class Win32_OperatingSystem -ComputerName $compName | ConvertTo-Html -As List -Property Description,Version,Caption,BuildNumber,OSArchitecture,Manufacturer,ServicePackMajorVersion -Fragment -PreContent "<h2>Operating System Information</h2>"

#TPM Info
Try {
    $TPM = Get-WmiObject -Namespace 'root\cimv2\security\microsofttpm' -query 'select specversion from win32_tpm'
    $TPM = "Trusted Platform Module (TPM) improves the security of a device and is used to securely create and store cryptographic keys and other information used to validate the OS and firmware of a device has not been tampered with.`nExpected Value: '2.0'`nReturned Value: $(($tpm.specversion -split ',')[0])" | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>TPM Module Information</h2>"
}
Catch {
    $exception = $_.Exception
    If ($exception -like "*Access Denied*"){
        $TPM = "Access Denied. Insufficient rights to run query." | ConvertTo-Html -Property -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>TPM Module Information</h2>"
    }
}

#HVCI Info
Try {
    If (Test-Path "HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\"){
        $HVCI = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\")
        If ($null -ne $HVCI){
            $HVCI = "Hypervisor Enforced Code Integrity (HVCI) is enabled.`nHVCI stengthens a devices security by protectiing against malware attempting to exploit the Windows kernel.`nExpected Value: '1'`nReturned Value: $(($HVCI).Enabled)" | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>Hypervisor Enforced Code Integrity (HVCI) Information</h2>"
        }
        Else {
            $HVCI = "Hypervisor Enforced Code Integrity (HVCI) is not enabled.`nHypervisor Enforced Code Integrity (HVCI) stengthens a devices security by protectiing against malware attempting to exploit the Windows kernel.`nExpected Value: '1'`nReturned Value: $(($HVCI).Enabled)" | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>Hypervisor Enforced Code Integrity (HVCI) Information</h2>"
        }
    }
    Else {
        $HVCI = "Hypervisor Enforced Code Integrity (HVCI) registry path not found. HVCI is not enabled." | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>Hypervisor Enforced Code Integrity (HVCI) Information</h2>"
    }
}
Catch {
    $exception = $_.Exception
    If ($exception -like "*Access Denied*"){
        $HVCI = "Access Denied. Insufficient rights to run query." | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>Hypervisor Enforced Code Integrity (HVCI) Information</h2>"
    }
}


#System Guard Info
Try {
    If (Test-Path "HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"){
        $SystemGuard = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard
        If (($null -ne $SystemGuard) -or ($SystemGuard -gt 0)){
            $SystemGuard = "System Guard validates the integrity of the system as it starts up through local and remote attestation.`nExpected Value: '1'`nReturned Value: $(($SystemGuard).Enabled)" | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>System Guard Information</h2>"
        }
        Else {
            $SystemGuard = "System Guard is not enabled.`nSystem Guard validates the integrity of the system as it starts up through local and remote attestation.`nExpected Value: '1'`nReturned Value: $(($SystemGuard).Enabled)" | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>System Guard Information</h2>"
        }
    }
    Else{
        $SystemGuard = "System Guard registry path not found. System Guard is not enabled." | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>System Guard Information</h2>"
    }
}
Catch {
    $exception = $_.Exception
    If ($exception -like "*Access Denied*"){
        $SystemGuard = "Access Denied. Insufficient rights to run query." | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>System Guard Information</h2>"
    }
}

#Credential Guard Info
Try {
    If (Test-Path "HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"){
        $CredentialGuard = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard
        If (($null -ne $CredentialGuard) -or ($CredentialGuard -gt 0)){
            $CredentialGuard = "Credential Guard creates and stores system and user secrets in a hardened virtual container, helping to minimize the risk and impact of Pass the Hash style attacks.`nExpected Value: '1'`nReturned Value: $(($CredentialGuard).Enabled)" | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>Credential Guard Information</h2>"
        }
        Else {
            $CredentialGuard = "Credential Guard is not enabled.`nCredential Guard creates and stores system and user secrets in a hardened virtual container, helping to minimize the risk and impact of Pass the Hash style attacks.`nExpected Value: '1'`nReturned Value: $(($CredentialGuard).Enabled)" | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>Credential Guard Information</h2>"
        }
    }
    Else{
        $CredentialGuard = "Credential Guard registry path not found. Credential Guard is not enabled." | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>Credential Guard Information</h2>"
    }
    
}
Catch {
    $exception = $_.Exception
    If ($exception -like "*Access Denied*"){
        $CredentialGuard = "Access Denied. Insufficient rights to run query." | ConvertTo-Html -Property @{l='Status';e={$_}} -Fragment -PreContent "<h2>Credential Guard Information</h2>"
    }
}


#Virtualization-based Security
Try {
        If (Test-Path "HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\"){
        $VBS = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\
        If (($null -ne $VBS) -or ($VBS -gt 0)) {
            $VBS = "Virtualization-based Security (VBS) is enabled.`nVirtualization-based Security (VBS) uses hardware virtualization to create and isolate a secure region of memory separate from the normal operating system. This feature helps reduce the risk and impact of exploitation of critical in-memory functions like anti-virus and certain protected operations. When possible via hardware and system support, this feature is enabled by default as of Windows 10 version 1903/`nExpected Value: '1'`nReturned Value: $(($).EnableVirtualizationBasedSecurity)" | ConvertTo-Html -Property @{l='VBS Status';e={$_}} -Fragment -PreContent "<h2>Virtualization-based Security Information</h2>"
        }
        Else {
            $VBS = "Virtualization-based Security (VBS) is not enabled.`nVirtualization-based Security (VBS) uses hardware virtualization to create and isolate a secure region of memory separate from the normal operating system. This feature helps reduce the risk and impact of exploitation of critical in-memory functions like anti-virus and certain protected operations. When possible via hardware and system support, this feature is enabled by default as of Windows 10 version 1903/`nExpected Value: '1'`nReturned Value: $(($).EnableVirtualizationBasedSecurity)" | ConvertTo-Html -Property @{l='VBS Status';e={$_}} -Fragment -PreContent "<h2>Virtualization-based Security Information</h2>"
        }
    }
    Else{
        $VBS = "Virtualization-based Security (VBS) registry path not found. VBS is not enabled." | ConvertTo-Html -Property @{l='VBS Status';e={$_}} -Fragment -PreContent "<h2>Virtualization-based Security Information</h2>"
    }
}
Catch {
    $exception = $_.Exception
    If ($exception -like "*Access Denied*"){
        $VBS = "Access Denied. Insufficient rights to run query." | ConvertTo-Html -Property @{l='VBS Status';e={$_}} -Fragment -PreContent "<h2>Virtualization-based Security Information</h2>"
    }
}


#Secure Boot Info
Try {
    $SecureBoot = Confirm-SecureBootUEFI
		If ($SecureBoot -eq $true) {
			$SecureBoot = "Secure Boot is enabled.`nSecure boot is a security standard developed by members of the PC industry to help make sure that a device boots using only software that is trusted by the Original Equipment Manufacturer (OEM). When the PC starts, the firmware checks the signature of each piece of boot software, including UEFI firmware drivers (also known as Option ROMs), EFI applications, and the operating system. If the signatures are valid, the PC boots, and the firmware gives control to the operating system.`nExpected Value: '1'`nReturned Value: $($SecureBoot)" | ConvertTo-Html -Property @{l='Secure Boot Status';e={$_}} -Fragment -PreContent "<h2>Secure Boot Information</h2>"
			}
		Else{
			$SecureBoot = "Secure Boot is not enabled.`nSecure boot is a security standard developed by members of the PC industry to help make sure that a device boots using only software that is trusted by the Original Equipment Manufacturer (OEM). When the PC starts, the firmware checks the signature of each piece of boot software, including UEFI firmware drivers (also known as Option ROMs), EFI applications, and the operating system. If the signatures are valid, the PC boots, and the firmware gives control to the operating system.`nExpected Value: '1'`nReturned Value: $($SecureBoot)" | ConvertTo-Html -Property @{l='Secure Boot Status';e={$_}} -Fragment -PreContent "<h2>Secure Boot Information</h2>"
		}
}
Catch {
    $exception = $_.Exception
    If ($exception -like "*Access Denied*"){
        $SecureBoot = "Access Denied. Insufficient rights to run query." | ConvertTo-Html -Property @{l='Secure Boot Status';e={$_}} -Fragment -PreContent "<h2>Secure Boot Information</h2>"
    }
}

#DMA Kernel Protection
##Credit to @SharmaKartikay for the scripted process of checking BootDMA - https://github.com/MicrosoftDocs/windows-itpro-docs/issues/6878
# bootDMAProtection check
$bootDMAProtectionCheck =
@"
  namespace SystemInfo
    {
      using System;
      using System.Runtime.InteropServices;

      public static class NativeMethods
      {
        internal enum SYSTEM_DMA_GUARD_POLICY_INFORMATION : int
        {
            /// </summary>
            SystemDmaGuardPolicyInformation = 202
        }

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtQuerySystemInformation(
          SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
          IntPtr SystemInformation,
          Int32 SystemInformationLength,
          out Int32 ReturnLength);

        public static byte BootDmaCheck() {
          Int32 result;
          Int32 SystemInformationLength = 1;
          IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
          Int32 ReturnLength;

          result = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
                    SystemInformation,
                    SystemInformationLength,
                    out ReturnLength);

          if (result == 0) {
            byte info = Marshal.ReadByte(SystemInformation, 0);
            return info;
          }

          return 0;
        }
      }
    }
"@

Add-Type -TypeDefinition $bootDMAProtectionCheck

# returns true or false depending on whether Kernel DMA Protection is on or off
$bootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0

If($bootDMAProtection -eq $true){
    $DMA = "Direct Memory Access (DMA) protection is enabled.`nIn Windows 10 version 1803, Microsoft introduced a new feature called Kernel DMA Protection to protect PCs against drive-by Direct Memory Access (DMA) attacks using PCI hot plug devices connected to externally accessible PCIe ports (for example, Thunderbolt 3 ports and CFexpress). In Windows 10 version 1903, Microsoft expanded the Kernel DMA Protection support to cover internal PCIe ports (for example, M.2 slots) Drive-by DMA attacks can lead to disclosure of sensitive information residing on a PC, or even injection of malware that allows attackers to bypass the lock screen or control PCs remotely. This feature doesn't protect against DMA attacks via 1394/FireWire, PCMCIA, CardBus, ExpressCard, and so on.`nExpected Value: 'True'`nReturned Value: $bootDMAProtection" | ConvertTo-Html -Property @{l='DMA Status';e={$_}} -Fragment -PreContent "<h2>Kernel Direct Memory Access (DMA) Protection Information</h2>"
}
Else {
    $DMA = "Direct Memory Access (DMA) protection is not enabled.`nIn Windows 10 version 1803, Microsoft introduced a new feature called Kernel DMA Protection to protect PCs against drive-by Direct Memory Access (DMA) attacks using PCI hot plug devices connected to externally accessible PCIe ports (for example, Thunderbolt 3 ports and CFexpress). In Windows 10 version 1903, Microsoft expanded the Kernel DMA Protection support to cover internal PCIe ports (for example, M.2 slots) Drive-by DMA attacks can lead to disclosure of sensitive information residing on a PC, or even injection of malware that allows attackers to bypass the lock screen or control PCs remotely. This feature doesn't protect against DMA attacks via 1394/FireWire, PCMCIA, CardBus, ExpressCard, and so on.`nExpected Value: 'True'`nReturned Value: $bootDMAProtection" | ConvertTo-Html -Property @{l='DMA Status';e={$_}} -Fragment -PreContent "<h2>Kernel Direct Memory Access (DMA) Protection Information</h2>"
}


#The command below will get the Currently logged on user
$LoggedinUser = Get-WmiObject -Class Win32_ComputerSystem -Property UserName -ComputerName $compName | ConvertTo-Html -As List -Property UserName -Fragment -PreContent "<h2>Current User</h2>"

#The command below lists all user profiles on the machine
$AllUsers = Get-ChildItem "\\$compName\c$\Users\" -Attributes directory | ConvertTo-Html -As Table -Property Name -Fragment -PreContent "<h2>All User Profiles</h2>"

#The command below will get the Processor information
$ProcessInfo = Get-CimInstance -ClassName Win32_Processor -ComputerName $compName | ConvertTo-Html -As Table -Property DeviceID,Name,Caption,MaxClockSpeed,SocketDesignation,Manufacturer -Fragment -PreContent "<h2>Processor Information</h2>"

#The command below will get the BIOS information
$BiosInfo = Get-CimInstance -ClassName Win32_BIOS -ComputerName $compName | ConvertTo-Html -As Table -Property SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber -Fragment -PreContent "<h2>BIOS Information</h2>"

#The command below will get the details of Disk
$DiscInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $compName | ConvertTo-Html -As Table -Property DeviceID,DriveType,ProviderName,VolumeName,Size,FreeSpace -Fragment -PreContent "<h2>Disk Information</h2>"

#The command below will gather the services information of the machine
$ServicesInfo = Get-CimInstance -ClassName Win32_Service -ComputerName $compName | ConvertTo-Html -As Table Name,DisplayName,State -Fragment -PreContent "<h2>Services Information</h2>"
$ServicesInfo = $ServicesInfo -replace '<td>Running</td>','<td class="RunningStatus">Running</td>'
$ServicesInfo = $ServicesInfo -replace '<td>Stopped</td>','<td class="StopStatus">Stopped</td>'

#The command below gathers the installed software on the machine
Function Get-Software {
    $Software = @()
    $Software += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* #|  ConvertTo-Html -Property DisplayName,DisplayVersion,Publisher,InstallDate -Fragment -PreContent "<h2>Software Information</h2>"
    $Software += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* #| ConvertTo-Html -Property DisplayName,DisplayVersion,Publisher,InstallDate -Fragment -PreContent "<h2>Software Information</h2>"
    $Software
    }

$SoftwareInfo = Get-Software | ConvertTo-Html -Property DisplayName,DisplayVersion,Publisher,InstallDate -As Table -Fragment -PreContent "<h2>Software Information</h2>"

#The below code gathers the list of any Attack Surface Reduction (ASR) Rules, the status of any rules
#Credit for majority of this code goes to the authors at https://github.com/directorcia. Adapted from script at https://github.com/directorcia/Office365/blob/master/win10-asr-get.ps1
function ASRRules {
    $rules = @()
    $rules += [PSCustomObject]@{ # 0
        Name = "Block executable content from email client and webmail";
        GUID = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-executable-content-from-email-client-and-webmail
    }
    $rules += [PSCustomObject]@{ # 1
        Name = "Block all Office applications from creating child processes";
        GUID = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-all-office-applications-from-creating-child-processes
    }
    $rules += [PSCustomObject]@{ # 2
        Name = "Block Office applications from creating executable content";
        GUID = "3B576869-A4EC-4529-8536-B80A7769E899"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-office-applications-from-creating-executable-content
    }
    $rules += [PSCustomObject]@{ # 3
        Name = "Block Office applications from injecting code into other processes";
        GUID = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-office-applications-from-injecting-code-into-other-processes
    }
    $rules += [PSCustomObject]@{ # 4
        Name = "Block JavaScript or VBScript from launching downloaded executable content";
        GUID = "D3E037E1-3EB8-44C8-A917-57927947596D"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-javascript-or-vbscript-from-launching-downloaded-executable-content
    }
    $rules += [PSCustomObject]@{ # 5
        Name = "Block execution of potentially obfuscated scripts";
        GUID = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-execution-of-potentially-obfuscated-scripts
    }
    $rules += [PSCustomObject]@{ # 6
        Name = "Block Win32 API calls from Office macros";
        GUID = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-win32-api-calls-from-office-macros
    }
    $rules += [PSCustomObject]@{ # 7
        Name = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion";
        GUID = "01443614-cd74-433a-b99e-2ecdc07bfc25"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-executable-files-from-running-unless-they-meet-a-prevalence-age-or-trusted-list-criterion
    }
    $rules += [PSCustomObject]@{ # 8 
        Name = "Use advanced protection against ransomware";
        GUID = "c1db55ab-c21a-4637-bb3f-a12568109d35"
        ## reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#use-advanced-protection-against-ransomware
    }
    $rules += [PSCustomObject]@{ # 9
        Name = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)";
        GUID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
        ## https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-credential-stealing-from-the-windows-local-security-authority-subsystem
    }
    $rules += [PSCustomObject]@{ # 10
        Name = "Block process creations originating from PSExec and WMI commands";
        GUID = "d1e49aac-8f56-4280-b9ba-993a6d77406c"
        ## https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-process-creations-originating-from-psexec-and-wmi-commands
    }
    $rules += [PSCustomObject]@{ # 11
        Name = "Block untrusted and unsigned processes that run from USB";
        GUID = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
        ## https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-untrusted-and-unsigned-processes-that-run-from-usb
    }
    $rules += [PSCustomObject]@{ # 12
        Name = "Block Office communication application from creating child processes";
        GUID = "26190899-1602-49e8-8b27-eb1d0a1ce869"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-office-communication-application-from-creating-child-processes
    }
    $rules += [PSCustomObject]@{ # 13
        Name = "Block Adobe Reader from creating child processes";
        GUID = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-adobe-reader-from-creating-child-processes
    }
    $rules += [PSCustomObject]@{ # 14
        Name = "Block persistence through WMI event subscription";
        GUID = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
        ## Reference - https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-persistence-through-wmi-event-subscription
    }
    $rules += [PSCustomObject]@{ # 15 
        Name = "Block abuse of exploited vulnerable signed drivers";
        GUID = "56a863a9-875e-4185-98a7-b882c64b5ce5"
        ## Reference - https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules?view=o365-worldwide#block-abuse-of-exploited-vulnerable-signed-drivers
    }
    $enabledvalues = "Not Enabled", "Enabled", "Audit"

    $results = Get-MpPreference
    write-output "Attack Surface Reduction Rules`n"

    write-output "$($results.AttackSurfaceReductionRules_ids.count) of $($rules.count) ASR rules found active`n"
    if (-not [string]::isnullorempty($results.AttackSurfaceReductionRules_ids)) {
        foreach ($id in $rules.GUID) {      
            switch ($id) {
                "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" {$index=0;break}
                "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" {$index=1;break}
                "3B576869-A4EC-4529-8536-B80A7769E899" {$index=2;break}
                "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" {$index=3;break}
                "D3E037E1-3EB8-44C8-A917-57927947596D" {$index=4;break}
                "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" {$index=5;break}
                "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" {$index=6;break}
                "01443614-cd74-433a-b99e-2ecdc07bfc25" {$index=7;break}
                "c1db55ab-c21a-4637-bb3f-a12568109d35" {$index=8;break}
                "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" {$index=9;break}
                "d1e49aac-8f56-4280-b9ba-993a6d77406c" {$index=10;break}
                "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" {$index=11;break}
                "26190899-1602-49e8-8b27-eb1d0a1ce869" {$index=12;break}
                "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" {$index=13;break}
                "e6db77e5-3df2-4cf1-b95a-636979351e5b" {$index=14;break}
                "56a863a9-875e-4185-98a7-b882c64b5ce5" {$index=15;break}
            }
            $count = 0
            $notfound = $true
            foreach ($entry in $results.AttackSurfaceReductionRules_ids) {
                if ($entry -match $id) {
                    $enabled = $results.AttackSurfaceReductionRules_actions[$count]             
                    switch ($enabled) {
                        0 {write-output "$($rules[$index].name) = $($enabledvalues[$enabled])"; break}
                        1 {write-output "$($rules[$index].name) = $($enabledvalues[$enabled])"; break}
                        2 {write-output "$($rules[$index].name) = $($enabledvalues[$enabled])"; break}
                    }
                    $notfound = $false
                }
                $count++
            }
            if ($notfound) {
                write-output $rules[$index].name"= Not found"
            }
        }
    }
    else {
        write-output $rules.count"ASR rules empty"
    }
}

$ASRStatus = ASRRules | ConvertTo-Html -Property @{l='Results';e={$_}} -Fragment -As List -PreContent "<h2>Attack Surface Reduction (ASR) Rules</h2>"

#The below code lists the various firewall profiles and their states
$FirewallProfiles = Get-NetFirewallProfile | ConvertTo-Html -Property Name,Enabled -As Table -Fragment -PreContent "<h2>Firewall Profiles</h2>"

#The below code gathers available firewall rules, their status and direction
$FirewallRules = Get-NetFirewallRule | ConvertTo-Html -Property DisplayName,Description,Profile,Direction,Action,Enabled -Fragment -As Table -PreContent "<h2>Firewall Rules</h2>"

#The code below creates a separate HTML report containing the Resultant Set of Policy (RSOP) applied on the machine
Try {
    $rsopPath = "$($Path)\RSOP"
    New-Item -ItemType Directory -Force -Path $rsopPath | Out-Null
    If ((Test-Path $rsopPath) -eq $true){
        $rsopPath = Resolve-Path $rsopPath
        Write-Output "$($rsopPath.Path) created successfully."
    }
}
Catch {
    Write-Error "Directory not created. Please check permissions."
    Exit
}

Get-GPResultantSetOfPolicy -ReportType Html -Path "$rsopPath\$compName-rsop.html"

$RSOP = Write-Output "See generated report at $rsopPath\$compName-rsop.html" | ConvertTo-Html -Property @{l='';e={$_}} -As List -Fragment -PreContent "<h2>Resultant Set of Policy</h2>"

#The code below gathers the members of Local Administrators group
$group = get-wmiobject win32_group -ComputerName $compName -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
$query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
$list = Get-WmiObject win32_groupuser -ComputerName $compName -Filter $query
$LocalAdmins = $list | ForEach-Object{$_.PartComponent} | ForEach-Object {$_.substring($_.lastindexof("Domain=") + 7).replace("`",Name=`"","\")} | ConvertTo-Html -Property @{l='Local Admins';e={$_}} -Fragment -As List -PreContent "<h2>Members of Local Administrators Group</h2>"

#The following code retrieves members of all local groups
Function LocalGroups{
    $groups = get-wmiobject -ComputerName $compName -Query "Select * From win32_group where SID LIKE 'S-1-5-32-%'"

    $results = @()

    foreach ($group in $groups){
        $GroupName = $group.Name 
        $query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
        $list = Get-WmiObject win32_groupuser -ComputerName $compName -Filter $query
        $members = $list | ForEach-Object{$_.PartComponent} | ForEach-Object {$_.substring($_.lastindexof("Domain=") + 7).replace("`",Name=`"","\")}

        If ($null -ne $members){
            $results += "$(($GroupName)), $(($Members))"
        }
    }

    $results
 }
 $AllLocalGroups = LocalGroups | ConvertTo-Html -Property  @{l='Results';e={$_}} -As List -Fragment -PreContent "<h2>Members of All Local Groups</h2>"


#The code below enumerates all Microsoft Defender Exclusions on the machine
$AVExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | ConvertTo-Html -Fragment -As List -PreContent "<h2>Windows Defender Antivirus Exclusions</h2>"

#The code below gathers a list of all installed hostfixes
$Patches = Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $compName | ConvertTo-Html -Property Description,HotFixID,InstalledOn -As Table -Fragment -PreContent "<h2>Installed HotFixes</h2>"

#The below code gets the SMB Server and Signing configuratiion of the machine
$SMBSigning = Get-SmbServerConfiguration | ConvertTo-Html -Property AuditSmb1Access,EnableSMB1Protocol,EnableSMB2Protocol,EnableSMBQuic,EncryptData,EncryptionCiphers,RejectUnencryptedAccess,RequireSecuritySignature -As List -Fragment -PreContent "<h2>SMB Server Configuration</h2>"

#The below code enumerates SMB shares on the machine and all access to each share
Function SMBShareACL{
    $smbShares = Get-SmbShare
    $access = @()
    foreach ($share in $smbShares){
        $access += Get-SmbShareAccess -Name $share.Name
    }

$access 
}

$SMBShares = SMBShareACL | ConvertTo-Html -Property Name,ScopeName,AccountName,AccessControlType,AccessRight -As Table -Fragment -PreContent "<h2>SMB Share Access Control List</h2>"

#The command below will combine all the information gathered into a single HTML report
$Report = ConvertTo-HTML -Body "$ComputerName,$OSinfo,$TPM,$HVCI,$SystemGuard,$CredentialGuard,$VBS,$SecureBoot,$DMA,$LoggedinUser,$AllUsers,$ProcessInfo,$BiosInfo,$DiscInfo,$ServicesInfo,$SoftwareInfo,$ASRStatus,$FirewallProfiles,$FirewallRules,$RSOP,$LocalAdmins,$AllLocalGroups,$AVExclusions,$Patches" -Head $header -Title "$($compName) Security Assessment Report" -PreContent "Created by <a href='https://soteria.io'>Soteria LLC</a> for $Organization" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>"

#The command below will generate the report to an HTML file
$Report | Out-File "$($Path)\$($Organization)_Machine_Security_Assessment.html"