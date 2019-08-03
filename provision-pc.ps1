# Log file location
$LogFile = ($env:ProgramData + "\pcProv\log.txt")
# Create provPC folder in ProgramData
if (-not (Test-Path -Path ($env:ProgramData + "\pcProv\"))) {
    New-Item -Path $env:ProgramData -Name "pcProv" -ItemType "directory"
}
#Log date and time on each run
Get-Date >> $LogFile

# Copy this script to ProgramData 
$oldScriptFullPath = $MyInvocation.MyCommand.Definition
$scriptFullPath = $env:ProgramData + "\pcProv\pcProv.ps1"
if ($oldScriptFullPath -ne $scriptFullPath) {
    Copy-Item -Path $oldScriptFullPath -Destination $scriptFullPath
    Write-Output "Copied script to $scriptFullPath" >> $LogFile
}

#Log date and time on each run
Get-Date >> $LogFile

# Stored function to register a scheduled task to continue the script after reboot.
function Set-ScheduledRebootTask {
    $TaskTrigger = (New-ScheduledTaskTrigger -atstartup)
    $TaskAction = New-ScheduledTaskAction -Execute Powershell.exe -argument "-ExecutionPolicy Bypass -File $scriptFullPath"
    $TaskUserID = New-ScheduledTaskPrincipal -UserId System -RunLevel Highest -LogonType ServiceAccount
    Register-ScheduledTask -Force -TaskName pcProv -Action $TaskAction -Principal $TaskUserID -Trigger $TaskTrigger
    if ($?) {
        Write-Output "Scheduled task created. Script will continue after reboot." >> $LogFile
    }
    else {
        Write-Error "Scheduled task could not be created. Run script manually after reboot." >> $LogFile
    }
}

# If Statement checks registry key to see where to start the script
# Part 1: If reg key does not exist, start provisioning
if (-not (Test-Path 'HKLM:\SOFTWARE\pcProv')) {

    #Create registry key so we can track our progress between reboots
    New-Item -Path HKLM:\SOFTWARE\pcProv -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 0 -Force
    if ($?) {
        Write-Output "Registry key created for script continuity after reboots with value: 0." >> $LogFile
    }
    else {
        Throw "Couldn't create registry key for script continuity after reboots. Exiting." >> $LogFile
    }

    # Get variables
    $credential = Get-Credential -Message "Enter your credentials in the form of domain\username"
    $domainName = Read-Host "Enter the domain to join"
    $newPCName = Read-Host "Enter the new computer name"
    # Get admin passwords until they match
    do {
        $pwd1 = Read-Host "Enter the local administrator account password" -AsSecureString
        $pwd2 = Read-Host "Confirm the local administrator password" -AsSecureString
        # Convert passwords to plaintext for comparison
        $pwd1_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd1))
        $pwd2_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd2))
    }
    while ($pwd1_txt -ne $pwd2_txt)

    # If passwords match, create accounts
    If ($pwd1_txt -eq $pwd2_txt) {
        # Set password and enable Administrator account
        Set-LocalUser -Name "Administrator" -Password $pwd1 -PasswordNeverExpires:$true
        if ($?) {
            Write-Output "Administer password set." >> $LogFile 
        }
        else {
            Write-Error "Error: Couldn't set Administrator password. " >> $LogFile
        }
        Enable-LocalUser -Name "Administrator"
        if ($?) {
            Write-Output "Administer account enabled." >> $LogFile 
        }
        else {
            Write-Error "Error: Couldn't enable administrator account. " >> $LogFile
        }
        # Set password and enable local non admin account
        New-LocalUser -Name "helpdesk" -Password (ConvertTo-SecureString -AsPlainText "helpdesk" -Force) -FullName "helpdesk" -PasswordNeverExpires:$true
        if ($?) {
            Write-Output "Standard helpdesk account created." >> $LogFile 
        }
        else {
            Write-Error "Error: Couldn't create standard helpdesk user. " >> $LogFile
        }
    }
    Else {
        Throw "Passwords don't match!"
    }

    # Install .net 3.5
    Add-WindowsCapability -Online -Name NetFx3~~~~
    if ($?) {
        Write-Output "Installed Windows Feature: .NET Framework 3.5 (Includes .NET 2.0 and 3.0)" >> $LogFile
    }
    else {
        Write-Error "Couldn't install .NET Framework 3.5. Try manually." >> $LogFile
    }

    # Install Chocolatey
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    if ($?) {
        Write-Output "Chocolatey is installed." >> $LogFile
    }
    else {
        Write-Error "Couldn't install Chocolatey. Try manually." >> $LogFile
    }

    # Encrypt System Drive
    Write-Output "Encrypting system drive..." >> $LogFile
    Start-Process 'manage-bde.exe' -ArgumentList " -protectors -add $env:SystemDrive -recoverypassword" -Verb runas -Wait
    Start-Process 'manage-bde.exe' -ArgumentList " -on -usedspaceonly $env:SystemDrive -em aes256 " -Verb runas -Wait
    #Backing Password file to the server
    $pcSerialNumber = (Get-WmiObject win32_bios).SerialNumber
#     New-PSDrive -Name "z" -PSProvider "Filesystem" -Root "" -Credential $credential
    if ($?) {
        New-Item -Path "z:\" -Name "$env:computername $pcSerialnumber" -ItemType "directory"
        (Get-BitLockerVolume -MountPoint C).KeyProtector.recoverypassword -match '\S\' > "z:\$env:computername $pcSerialnumber\Bitlocker Recovery Key.txt"
        if ($?) {
            Write-Output "Bitlocker key successfully saved." >> $LogFile
        }
        else {
            Write-Error "Saving Bitlocker key failed. Try manually." >> $LogFile
        }
    }
    else {
        Write-Error "Encryption failed, try manually."
    }

    # Increment the registry value to resume where we left off after reboot
    Set-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 1
    if ($?) {
        Write-Output "Registry key changed to value: 0." >> $LogFile
    }

    ## Rename the computer and restart
    # Rename-Computer -NewName $newPCName -Restart -Force

    Set-ScheduledRebootTask

    # Join to domain and restart
    Add-Computer -DomainName $domainName -Server HQ-corpdc01 -NewName $newPCName -Credential $credential -Restart -Force
}
# Part 2: If script has run, check reg key to determine where to continue
else {
    $regStatus = Get-ItemPropertyValue HKLM:\SOFTWARE\pcProv -Name "Status"
    # Script Part 2.1
    if ($regStatus -eq 1) {
        Write-Output "Registry key value is: 1. Continuing from Part 2.1" >> $LogFile

        # still working on this

        # Increment the registry value to resume where we left off after reboot
        Set-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 2
        if ($?) {
            Write-Output "Registry key changed to value: 2." >> $LogFile
        }
        Restart-Computer -Force

    }
    # Script Part 2.2
    elseif ($regStatus -eq 2) {
        Write-Output "Registry key value is: 2. Continuing from Part 2.2" >> $LogFile

        # Still working on this
        # Install Windows Updates
        Install-PackageProvider -Name -NuGet -Force
        Install-Module PSWindowsUpdate -Force -Confirm:$false
        Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
        do {
            Get-WUInstall -MicrosoftUpdate -AcceptAll -AutoReboot
        }
        while ((Get-WUList) -ne 0)
        if ((Get-WUList) -eq 0) {
            Write-Output "Windows Updates installed." >> $LogFile
        }
        else {
            Write-Error "Windows Updates not complete. Try manually." >> $LogFile
        }

        Write-Output "Provisioning complete." >> $LogFile

        # Play complete tones
        function b($a, $b) {
            [console]::beep($a, $b)
        }
        function s($a) {
            sleep -m $a
        }
        b 660 100;
        s 150;
        b 660 100;
        s 300;
        b 660 100;
        s 300;
        b 510 100;
        s 100;
        b 660 100;
        s 300;
        b 770 100;
        s 550;

        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("Provisioning completed", 0, "provPC")
        Unregister-ScheduledTask -TaskName pcProv -Confirm:$false
        if ($?) {
            Write-Output "Unregistered scheduled task." >> $LogFile
        }
        else {
            Write-Error "Scheduled task 'pcProv' could not be deleted. Try manually." >> $LogFile
        }
    }
    else {
        Throw "Reg key exists, but doesn't match any part of the script (or the script was already completed on this machine). Exiting." >> $LogFile
    }
}
