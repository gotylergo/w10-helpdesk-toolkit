# Windows Update Script params section
param($global:RestartRequired = 0,
$global:MoreUpdates = 0,
$global:MaxCycles = 10)

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
    # $TaskUserID = New-ScheduledTaskPrincipal -UserId (Get-CimInstance –ClassName Win32_ComputerSystem | Select-Object -expand UserName) -RunLevel Highest -LogonType ServiceAccount
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

    # Get variables, store variables that will be needed after reboot in the registry
    $credential = Get-Credential -Message "Enter your credentials in the form of domain\username or username@domain.com format"
    # New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "credentialUsername" -Value $credential.Username
    # New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "credentialPassword" -Value $credential.Password | ConvertFrom-SecureString
    $domainName = Read-Host "Enter the domain to join"
    $newPCName = Read-Host "Enter the new computer name"
    # Confirm the serial number for the bitlocker folder
    $defaultValue = (Get-WmiObject win32_bios).SerialNumber
    $pcSerialNumber = Read-Host "What is the serial number of the end user machine? Leave blank to use this value: [$($defaultValue)]"
    $pcSerialnumber = ($defaultValue,$prompt)[[bool]$prompt]
    $userToNotify = Read-Host "Enter the email of the user you want to notify when complete"
    $mailServer = Read-Host "What mail server should we use to send the completion message?"
    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "userToNotify" -Value $userToNotify -Force
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
    if ($?) {
      Write-Output "Encryption successful."
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
    Add-Computer -DomainName $domainName -NewName $newPCName -Credential $credential -Restart -Force
}
# Part 2: If script has run, check reg key to determine where to continue
else {
    $regStatus = Get-ItemPropertyValue HKLM:\SOFTWARE\pcProv -Name "Status"
    # Script Part 2.1
    if ($regStatus -eq 1) {
        Write-Output "Registry key value is: 1. Continuing from Part 2.1" >> $LogFile

        #DO STUFF

        # Increment the registry value to resume where we left off after reboot
        Set-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 2
        if ($?) {
            Write-Output "Registry key changed to value: 2." >> $LogFile
        }
        Restart-Computer -Force

    }
    elseif ($regStatus -eq 2) {
        Write-Output "Registry key value is: 2. Continuing from Part 2.2" >> $LogFile

        Write-Output "Running Windows Update Script" >> $LogFile
        # Credit to joefitzgerald on Github https://gist.github.com/joefitzgerald/8203265

        function Check-ContinueRestartOrEnd() {
            $RegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            $RegistryEntry = "InstallWindowsUpdates"
            switch ($global:RestartRequired) {
                0 {			
                    $prop = (Get-ItemProperty $RegistryKey).$RegistryEntry
                    if ($prop) {
                        Write-Host "Restart Registry Entry Exists - Removing It" >> $Logfile
                        Remove-ItemProperty -Path $RegistryKey -Name $RegistryEntry -ErrorAction SilentlyContinue
                    }
            
                    Write-Host "No Restart Required" >> $Logfile
                    Check-WindowsUpdates
            
                    if (($global:MoreUpdates -eq 1) -and ($script:Cycles -le $global:MaxCycles)) {
                        Stop-Service $script:ServiceName -Force
                        Set-Service -Name $script:ServiceName -StartupType Disabled -Status Stopped 
                        Install-WindowsUpdates
                    }
                    elseif ($script:Cycles -gt $global:MaxCycles) {
                        Write-Host "Exceeded Cycle Count - Stopping" >> $Logfile
                    }
                    else {
                        Write-Host "Done Installing Windows Updates" >> $Logfile
                    }
                }
                1 {
                    $prop = (Get-ItemProperty $RegistryKey).$RegistryEntry
                    if (-not $prop) {
                        Write-Host "Restart Registry Entry Does Not Exist - Creating It" >> $Logfile
                        Set-ItemProperty -Path $RegistryKey -Name $RegistryEntry -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File $($script:ScriptPath)"
                    }
                    else {
                        Write-Host "Restart Registry Entry Exists Already" >> $Logfile
                    }
            
                    Write-Host "Restart Required - Restarting..." >> $Logfile
                    Restart-Computer
                }
                default { 
                    Write-Host "Unsure If A Restart Is Required"  >> $Logfile
                    break
                }
            }
        }

        function Install-WindowsUpdates() {
            $script:Cycles++
            Write-Host 'Evaluating Available Updates:' >> $Logfile
            $UpdatesToDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl'
            foreach ($Update in $SearchResult.Updates) {
                if (($Update -ne $null) -and (!$Update.IsDownloaded)) {
                    [bool]$addThisUpdate = $false
                    if ($Update.InstallationBehavior.CanRequestUserInput) {
                        Write-Host "> Skipping: $($Update.Title) because it requires user input" >> $Logfile
                    }
                    else {
                        if (!($Update.EulaAccepted)) {
                            Write-Host "> Note: $($Update.Title) has a license agreement that must be accepted. Accepting the license." >> $Logfile
                            $Update.AcceptEula()
                            [bool]$addThisUpdate = $true
                        }
                        else {
                            [bool]$addThisUpdate = $true
                        }
                    }
        
                    if ([bool]$addThisUpdate) {
                        Write-Host "Adding: $($Update.Title)" >> $Logfile
                        $UpdatesToDownload.Add($Update) | Out-Null
                    }
                }
            }
    
            if ($UpdatesToDownload.Count -eq 0) {
                Write-Host "No Updates To Download..." >> $Logfile
            }
            else {
                Write-Host 'Downloading Updates...' >> $Logfile
                $Downloader = $UpdateSession.CreateUpdateDownloader()
                $Downloader.Updates = $UpdatesToDownload
                $Downloader.Download()
            }
	
            $UpdatesToInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl'
            [bool]$rebootMayBeRequired = $false
            Write-Host 'The following updates are downloaded and ready to be installed:' >> $Logfile
            foreach ($Update in $SearchResult.Updates) {
                if (($Update.IsDownloaded)) {
                    Write-Host "> $($Update.Title)" >> $Logfile
                    $UpdatesToInstall.Add($Update) | Out-Null
              
                    if ($Update.InstallationBehavior.RebootBehavior -gt 0) {
                        [bool]$rebootMayBeRequired = $true
                    }
                }
            }
    
            if ($UpdatesToInstall.Count -eq 0) {
                Write-Host 'No updates available to install...' >> $Logfile
                $global:MoreUpdates = 0
                $global:RestartRequired = 0
                break
            }

            if ($rebootMayBeRequired) {
                Write-Host 'These updates may require a reboot' >> $Logfile
                $global:RestartRequired = 1
            }
	
            Write-Host 'Installing updates...' >> $Logfile
  
            $Installer = $script:UpdateSession.CreateUpdateInstaller()
            $Installer.Updates = $UpdatesToInstall
            $InstallationResult = $Installer.Install()
  
            Write-Host "Installation Result: $($InstallationResult.ResultCode)" >> $Logfile
            Write-Host "Reboot Required: $($InstallationResult.RebootRequired)" >> $Logfile
            Write-Host 'Listing of updates installed and individual installation results:' >> $Logfile
            if ($InstallationResult.RebootRequired) {
                $global:RestartRequired = 1
            }
            else {
                $global:RestartRequired = 0
            }
    
            for ($i = 0; $i -lt $UpdatesToInstall.Count; $i++) {
                New-Object -TypeName PSObject -Property @{
                    Title  = $UpdatesToInstall.Item($i).Title
                    Result = $InstallationResult.GetUpdateResult($i).ResultCode
                }
            }
	
            Check-ContinueRestartOrEnd
        }

        function Check-WindowsUpdates() {
            Write-Host "Checking For Windows Updates" >> $Logfile
            $Username = $env:USERDOMAIN + "\" + $env:USERNAME
 
            New-EventLog -Source $ScriptName -LogName 'Windows Powershell' -ErrorAction SilentlyContinue
 
            $Message = "Script: " + $ScriptPath + "`nScript User: " + $Username + "`nStarted: " + (Get-Date).toString()

            Write-EventLog -LogName 'Windows Powershell' -Source $ScriptName -EventID "104" -EntryType "Information" -Message $Message
            Write-Host $Message >> $Logfile

            $script:UpdateSearcher = $script:UpdateSession.CreateUpdateSearcher()
            $script:SearchResult = $script:UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")      
            if ($SearchResult.Updates.Count -ne 0) {
                $script:SearchResult.Updates | Select-Object -Property Title, Description, SupportUrl, UninstallationNotes, RebootRequired, EulaAccepted | Format-List
                $global:MoreUpdates = 1
            }
            else {
                Write-Host 'There are no applicable updates' >> $Logfile
                $global:RestartRequired = 0
                $global:MoreUpdates = 0
            }
        }

        $script:ScriptName = $MyInvocation.MyCommand.ToString()
        $script:ScriptPath = $MyInvocation.MyCommand.Path
        $script:UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
        $script:UpdateSession.ClientApplicationID = 'Packer Windows Update Installer'
        $script:UpdateSearcher = $script:UpdateSession.CreateUpdateSearcher()
        $script:SearchResult = New-Object -ComObject 'Microsoft.Update.UpdateColl'
        $script:Cycles = 0

        Check-WindowsUpdates
        if ($global:MoreUpdates -eq 1) {
            Install-WindowsUpdates
        }
        else {
            Check-ContinueRestartOrEnd
        }

        Set-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 3
        if ($?) {
            Write-Output "Registry key changed to value: 3." >> $LogFile
        }
        Restart-Computer -Force

    }
    # Script Part 2.3
    elseif ($regStatus -eq 3) {
        Write-Output "Registry key value is: 3. Continuing from Part 2.3" >> $LogFile

        Write-Output "Provisioning complete." >> $LogFile

        $userToNotify = Get-ItemPropertyValue HKLM:\SOFTWARE\pcProv -Name "userToNotify"
        # MSG * /SERVER:$pcToNotify "$Env:Computername provisioning is done!"
        Send-MailMessage -From $userToNotify -To $userToNotify -Subject 'provPC Complete' -Body "See the attached log for details." -Attachments $LogFile -Priority High -DeliveryNotificationOption OnSuccess, OnFailure -SmtpServer $mailServer
        if ($?) {
            Write-Output "Completion email sent."
        }

        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("Provisioning completed", 0, "provPC")
        Unregister-ScheduledTask -TaskName pcProv -Confirm:$false
        if ($?) {
            Write-Output "Unregistered scheduled task." >> $LogFile
        }
        else {
            Write-Error "Scheduled task 'pcProv' could not be unregistered. Try manually." >> $LogFile
        }
    }
    else {
        Throw "Reg key exists, but doesn't match any part of the script (or the script was already completed on this machine). Exiting." >> $LogFile
    }
}
