# Windows Update Script params section
param($global:RestartRequired = 0,
    $global:MoreUpdates = 0,
    $global:MaxCycles = 10)

$ScriptDir = "$env:ProgramData\pcProv\"

# Log file location
$LogFile = "$ScriptDir\log.txt"
# Create provPC folder in ProgramData
If (-not (Test-Path -Path ("$env:ProgramData\pcProv\"))) {
    New-Item -Path $env:ProgramData -Name "pcProv" -ItemType "directory"
}
#Log date and time on each run
Get-Date >> $LogFile

# Copy this script to ProgramData 
$CurrentScriptPath = $MyInvocation.MyCommand.Definition
$ScriptPath = "$ScriptDir\pcProv.ps1"
If ($CurrentScriptPath -ne $ScriptPath) {
    Copy-Item -Path $CurrentScriptPath -Destination $ScriptPath
    Write-Output "Copied script to $ScriptPath" >> $LogFile
}

#Log date and time on each run
Get-Date >> $LogFile

# Stored function to register a scheduled task to continue the script after reboot.
function Set-ScheduledRebootTask {
    $TaskAction = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShellv1.0\powershell.exe' -Argument "-NonInteractive -NoLogo -NoProfile -File $ScriptPath"
    $TaskTrigger = New-ScheduledTaskTrigger -RandomDelay (New-TimeSpan -Minutes 5) -AtStartup
    $TaskSettings = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 10 -StartWhenAvailable
    $TaskSettings.ExecutionTimeLimit = "PT0S"
    $Task = New-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings
    $Task | Register-ScheduledTask -TaskName "provPC" -User "$env:USERDOMAIN\$env:USERNAME" -Password "$AdminPassword"

    If ($?) {
        Write-Output "Scheduled task created. Script will continue after reboot."
    }
    Else {
        Write-Error "Scheduled task could not be created. Run script manually after reboot."
    }
}
# If Statement checks registry key to see where to start the script
# Part 1: If reg key does not exist, start provisioning
If (-not (Test-Path 'HKLM:\SOFTWARE\pcProv')) {

    #Create registry key so we can track our progress between reboots
    New-Item -Path HKLM:\SOFTWARE\pcProv -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 0 -Force
    If ($?) {
        Write-Output "Registry key created for script continuity after reboots with value: 0." >> $LogFile
    }
    Else {
        Throw "Couldn't create registry key for script continuity after reboots. Exiting." >> $LogFile
    }

    # Get variables, store variables that will be needed after reboot in the registry
    # Get credentials
    $DomainAdminUser = Read-Host "Enter your domain admin username in the form of domain.com\username"
    $DomainAdminPwd = Read-Host "Enter your domain admin password" -AsSecureString
    $Credentials = [System.Management.Automation.PSCredential]::new($DomainAdminUser, $DomainAdminPwd)

    # Save credentials
    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "DomainAdminUser" -Value $Credentials.GetNetworkCredential().UserName
    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "DomainName" -Value $Credentials.GetNetworkCredential().Domain
    $Credentials.GetNetworkCredential().SecurePassword | ConvertFrom-SecureString | Out-File C:\ProgramData\pcProv\cred.txt
    $DomainName = $Credentials.GetNetworkCredential().Domain

    $NewPCName = Read-Host "Enter the new computer name"
    Write-Output "NewPCName: $NewPCName" >> $LogFile
    # Confirm the serial number for the bitlocker folder
    $defaultValue = (Get-WmiObject win32_bios).SerialNumber
    $PCSerialNumber = Read-Host "What is the serial number of the end user machine? Leave blank to use this value: [$($defaultValue)]"
    If ($PCSerialNumber -eq "") {
        $PCSerialNumber = $defaultValue
    }
    Write-Output "pcSerialNumber: $PCSerialNumber" >> $LogFile
    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "PCSerialNumber" -Value $PCSerialNumber
    $UserToNotify = Read-Host "Enter the email of the user you want to notify when complete"
    Write-Output "userToNotify: $UserToNotify" >> $LogFile
    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "userToNotify" -Value $UserToNotify -Force
    # Ask if user needs admin
    $NeedsAdmin = Read-Host "Is this a laptop or does the user need to be local admin? y/n"
    If ($NeedsAdmin -eq "y") {
        $EndUser = Read-Host "What is the username?"
        Write-Output "EndUser: $EndUser" >> $LogFile
        New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "EndUser" -Value $EndUser -Force
    }
    # Get admin passwords until they match
    Do {
        $Pwd1 = Read-Host "Enter the local administrator account password" -AsSecureString
        $Pwd2 = Read-Host "Confirm the local administrator password" -AsSecureString
        # Convert passwords to plaintext for comparison
        $Pwd1_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pwd1))
        $Pwd2_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pwd2))
    }
    While ($Pwd1_txt -ne $Pwd2_txt)
    # If passwords match, create accounts
    $AdminPassword = ""
    If ($Pwd1_txt -eq $Pwd2_txt) {
        $AdminPassword = $Pwd1_txt
        # Set password and enable Administrator account
        Set-LocalUser -Name "Administrator" -Password $Pwd1 -PasswordNeverExpires:$true
        If ($?) {
            Write-Output "Administer password set." >> $LogFile 
        }
        Else {
            Write-Error "Error: Couldn't set Administrator password. " >> $LogFile
        }
        Enable-LocalUser -Name "Administrator"
        If ($?) {
            Write-Output "Administer account enabled." >> $LogFile 
        }
        Else {
            Write-Error "Error: Couldn't enable administrator account. " >> $LogFile
        }
        # Set currently logged in admin account password to Administrator password
        Set-LocalUser -Name $env:UserName -Password $Pwd1 -PasswordNeverExpires:$true
        If ($?) {
            Write-Output "$env:UserName password set." >> $LogFile 
        }
        Else {
            Write-Error "Error: Couldn't set $env:UserName password. " >> $LogFile
        }
    }
    Else {
        Throw "Passwords don't match!"
    }

    # Set password and enable local non admin account
    New-LocalUser -Name "helpdesk" -Password (ConvertTo-SecureString -AsPlainText "helpdesk" -Force) -FullName "helpdesk" -PasswordNeverExpires:$true
    If ($?) {
        Write-Output "Standard helpdesk account created." >> $LogFile 
    }
    Else {
        Write-Error "Error: Couldn't create standard helpdesk user. " >> $LogFile
    }

    # Install .net 3.5
    Add-WindowsCapability -Online -Name NetFx3~~~~
    If ($?) {
        Write-Output "Installed Windows Feature: .NET Framework 3.5 (Includes .NET 2.0 and 3.0)" >> $LogFile
    }
    Else {
        Write-Error "Couldn't install .NET Framework 3.5. Try manually." >> $LogFile
    }

    # Install Chocolatey
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    If ($?) {
        Write-Output "Chocolatey is installed." >> $LogFile
    }
    Else {
        Write-Error "Couldn't install Chocolatey. Try manually." >> $LogFile
    }

    # Increment the registry value to resume where we left off after reboot
    Set-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 1
    If ($?) {
        Write-Output "Registry key changed to value: 0." >> $LogFile
    }

    ## Rename the computer and restart
    # Rename-Computer -NewName $NewPCName -Restart -Force

    Set-ScheduledRebootTask

    # Join to domain and restart
    Add-Computer -DomainName $DomainName -NewName $NewPCName -Credential $Credentials -Restart -Force
}
# Part 2: If script has run, check reg key to determine where to continue
Else {
    $regStatus = Get-ItemPropertyValue HKLM:\SOFTWARE\pcProv -Name "Status"
    # Script Part 2.1
    If ($regStatus -eq 1) {
        Write-Output "Registry key value is: 1. Continuing from Part 2.1" >> $LogFile

        # Retrieve stored credentials
        $DomainName = (Get-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "DomainName").DomainName
        $DomainAdminUser = (Get-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "DomainAdminUser").DomainAdminUser
        $DomainAdminPwd = (get-content C:\ProgramData\pcProv\cred.txt | ConvertTo-SecureString)
        # Convert stored credentials to Credential object
        $Credentials = [System.Management.Automation.PSCredential]::new("$DomainName\$DomainAdminUser", $DomainAdminPwd)

        # Retrieve PCSerialNumber
        $PCSerialNumber = (Get-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "PCSerialNumber").PCSerialNumber

        # Encrypt System Drive
        Write-Output "Encrypting system drive..." >> $LogFile
        Start-Process 'manage-bde.exe' -ArgumentList " -protectors -add $env:SystemDrive -recoverypassword" -Verb runas -Wait
        Start-Process 'manage-bde.exe' -ArgumentList " -on -usedspaceonly $env:SystemDrive -em aes256 " -Verb runas -Wait
        #Backing Password file to the server
        New-PSDrive -Name "z" -PSProvider "Filesystem" -Root "\\fileserver\fileshare" -Credential $Credentials
        If ($?) {
            New-Item -Path "z:\" -Name "$env:computername $PCSerialNumber" -ItemType "directory"
            (Get-BitLockerVolume -MountPoint C).KeyProtector > "z:\$env:computername $PCSerialNumber\Bitlocker Recovery Key.txt"
            If ($?) {
                Write-Output "Bitlocker key successfully saved." >> $LogFile
            }
            Else {
                Write-Error "Saving Bitlocker key failed. Try manually." >> $LogFile
            }
        }
        Else {
            Write-Error "Encryption failed, try manually."
        }


        # Increment the registry value to resume where we left off after reboot
        Set-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 2
        If ($?) {
            Write-Output "Registry key changed to value: 2." >> $LogFile
        }
        Restart-Computer -Force

    }
    ElseIf ($regStatus -eq 2) {
        Write-Output "Registry key value is: 2. Continuing from Part 2.2" >> $LogFile

        Write-Output "Running Windows Update Script" >> $LogFile
        # Credit to joefitzgerald on Github https://gist.github.com/joefitzgerald/8203265

        function Check-ContinueRestartOrEnd() {
            $RegistryKey = "HKLM:\SOFTWARE\pcProv"
            $RegistryEntry = "InstallWindowsUpdates"
            switch ($global:RestartRequired) {
                0 {			
                    $prop = (Get-ItemProperty $RegistryKey).$RegistryEntry
                    If ($prop) {
                        Write-Output "Restart Registry Entry Exists - Removing It" >> $Logfile
                        Remove-ItemProperty -Path $RegistryKey -Name $RegistryEntry -ErrorAction SilentlyContinue
                    }
            
                    Write-Output "No Restart Required" >> $Logfile
                    Check-WindowsUpdates
            
                    If (($global:MoreUpdates -eq 1) -and ($script:Cycles -le $global:MaxCycles)) {
                        Stop-Service $script:ServiceName -Force
                        Set-Service -Name $script:ServiceName -StartupType Disabled -Status Stopped 
                        Install-WindowsUpdates
                    }
                    ElseIf ($script:Cycles -gt $global:MaxCycles) {
                        Write-Output "Exceeded Cycle Count - Stopping" >> $Logfile
                    }
                    Else {
                        Write-Output "Done Installing Windows Updates" >> $Logfile
                    }
                }
                1 {
                    $prop = (Get-ItemProperty $RegistryKey).$RegistryEntry
                    If (-not $prop) {
                        Write-Output "Restart Registry Entry Does Not Exist - Creating It" >> $Logfile
                        Set-ItemProperty -Path $RegistryKey -Name $RegistryEntry -Value "1"
                    }
                    Else {
                        Write-Output "Restart Registry Entry Exists Already" >> $Logfile
                    }
            
                    Write-Output "Restart Required - Restarting..." >> $Logfile
                    Restart-Computer
                }
                default { 
                    Write-Output "Unsure If A Restart Is Required"  >> $Logfile
                    break
                }
            }
        }

        function Install-WindowsUpdates() {
            $script:Cycles++
            Write-Output 'Evaluating Available Updates:' >> $Logfile
            $UpdatesToDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl'
            foreach ($Update in $SearchResult.Updates) {
                If (($Update -ne $null) -and (!$Update.IsDownloaded)) {
                    [bool]$addThisUpdate = $false
                    If ($Update.InstallationBehavior.CanRequestUserInput) {
                        Write-Output "> Skipping: $($Update.Title) because it requires user input" >> $Logfile
                    }
                    Else {
                        If (!($Update.EulaAccepted)) {
                            Write-Output "> Note: $($Update.Title) has a license agreement that must be accepted. Accepting the license." >> $Logfile
                            $Update.AcceptEula()
                            [bool]$addThisUpdate = $true
                        }
                        Else {
                            [bool]$addThisUpdate = $true
                        }
                    }
        
                    If ([bool]$addThisUpdate) {
                        Write-Output "Adding: $($Update.Title)" >> $Logfile
                        $UpdatesToDownload.Add($Update) | Out-Null
                    }
                }
            }
    
            If ($UpdatesToDownload.Count -eq 0) {
                Write-Output "No Updates To Download..." >> $Logfile
            }
            Else {
                Write-Output 'Downloading Updates...' >> $Logfile
                $Downloader = $UpdateSession.CreateUpdateDownloader()
                $Downloader.Updates = $UpdatesToDownload
                $Downloader.Download()
            }
	
            $UpdatesToInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl'
            [bool]$rebootMayBeRequired = $false
            Write-Output 'The following updates are downloaded and ready to be installed:' >> $Logfile
            foreach ($Update in $SearchResult.Updates) {
                If (($Update.IsDownloaded)) {
                    Write-Output "> $($Update.Title)" >> $Logfile
                    $UpdatesToInstall.Add($Update) | Out-Null
              
                    If ($Update.InstallationBehavior.RebootBehavior -gt 0) {
                        [bool]$rebootMayBeRequired = $true
                    }
                }
            }
    
            If ($UpdatesToInstall.Count -eq 0) {
                Write-Output 'No updates available to install...' >> $Logfile
                $global:MoreUpdates = 0
                $global:RestartRequired = 0
                break
            }

            If ($rebootMayBeRequired) {
                Write-Output 'These updates may require a reboot' >> $Logfile
                $global:RestartRequired = 1
            }
	
            Write-Output 'Installing updates...' >> $Logfile
  
            $Installer = $script:UpdateSession.CreateUpdateInstaller()
            $Installer.Updates = $UpdatesToInstall
            $InstallationResult = $Installer.Install()
  
            Write-Output "Installation Result: $($InstallationResult.ResultCode)" >> $Logfile
            Write-Output "Reboot Required: $($InstallationResult.RebootRequired)" >> $Logfile
            Write-Output 'Listing of updates installed and individual installation results:' >> $Logfile
            If ($InstallationResult.RebootRequired) {
                $global:RestartRequired = 1
            }
            Else {
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
            Write-Output "Checking For Windows Updates" >> $Logfile
            $Username = $env:USERDOMAIN + "\" + $env:USERNAME
 
            New-EventLog -Source $ScriptName -LogName 'Windows Powershell' -ErrorAction SilentlyContinue
 
            $Message = "Script: " + $ScriptPath + "`nScript User: " + $Username + "`nStarted: " + (Get-Date).toString()

            Write-EventLog -LogName 'Windows Powershell' -Source $ScriptName -EventID "104" -EntryType "Information" -Message $Message
            Write-Output $Message >> $Logfile

            $script:UpdateSearcher = $script:UpdateSession.CreateUpdateSearcher()
            $script:SearchResult = $script:UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")      
            If ($SearchResult.Updates.Count -ne 0) {
                $script:SearchResult.Updates | Select-Object -Property Title, Description, SupportUrl, UninstallationNotes, RebootRequired, EulaAccepted | Format-List
                $global:MoreUpdates = 1
            }
            Else {
                Write-Output 'There are no applicable updates' >> $Logfile
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
        If ($global:MoreUpdates -eq 1) {
            Install-WindowsUpdates
        }
        Else {
            Check-ContinueRestartOrEnd
        }

        Set-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 3
        If ($?) {
            Write-Output "Registry key changed to value: 3." >> $LogFile
        }
        Restart-Computer -Force

    }
    # Script Part 2.3
    ElseIf ($regStatus -eq 3) {
        Write-Output "Registry key value is: 3. Continuing from Part 2.3" >> $LogFile
        # Add laptop user to Administrators
        $EndUser = Get-ItemPropertyValue HKLM:\SOFTWARE\pcProv -Name "EndUser"
        If ($EndUser.length -gt 0 ) {
            Write-Output "Adding $EndUser to Administrators group."
            Add-LocalGroupMember -Group "Administrators" -Member "$DomainName\$EndUser"
        }
        If ($?) {
            Write-Output "Added $EndUser to Administrators successfully"
        }
        Else {
            Write-Error "Adding $EndUser to Administrators failed. Try manually."
        }
        Write-Output "Provisioning complete." >> $LogFile

        # Email to notify the script is complete
        $UserToNotify = Get-ItemPropertyValue HKLM:\SOFTWARE\pcProv -Name "userToNotify"
        Send-MailMessage -From $UserToNotify -To $UserToNotify -Subject "$env:computername Provisioning Complete" -Body "See the attached log for details." -Attachments $LogFile -Priority High -DeliveryNotificationOption OnSuccess, OnFailure -SmtpServer 'mxout-bulk.internetbrands.com'
        If ($?) {
            Write-Output "Completion email sent." >> $LogFile
        }
        Else {
            Write-Error "Completion email could not be sent." >> $LogFile
        }

        # # Popup to notify the script is complete
        # $wshell = New-Object -ComObject Wscript.Shell
        # $wshell.Popup("Provisioning completed", 0, "provPC")

        # Cleanup
        Unregister-ScheduledTask -TaskName "pcProv" -Confirm:$false
        If ($?) {
            Write-Output "Unregistered scheduled task." >> $LogFile
        }
        Else {
            Write-Error "Scheduled task 'pcProv' could not be unregistered. Try manually." >> $LogFile
        }
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsft\Windows\CurrentVersion\Run" -Name "InstallWindowsUpdates"
        If ($?) {
            Write-Output "Removed startup reg entry." >> $LogFile
        }
        Else {
            Write-Error "Startup reg entry could not be removed. Manually delete this entry: HKLM:\SOFTWARE\Microsft\Windows\CurrentVersion\Run\InstallWindowsUpdates" >> $LogFile
        }
        Remove-Item -Path "$ScriptDir\cred.txt" -Force
        If ($?) {
            Write-Output "Removed stored credential."
        }
        Else {
            Write-Error "Couldn't remove credential. Manually from $ScriptDir\cred.txt"
        }
        # Increment script number
        Set-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 4
        If ($?) {
            Write-Output "Registry key changed to value: 4." >> $LogFile
        }
        # After completion, the script deletes itself
        Remove-Item -LiteralPath ($MyInvocation.MyCommand.Path) -Force
        If ($?) {
            Write-Output "Script deleted."
        }
        Else {
            Write-Error "Couldn't delete script. Remove manually from $ScriptDir"
        }
    }
    ElseIf ($regStatus -eq 4) {
        Write-Output "Script has already completed. Exiting."
    }
    Else {
        Throw "Reg key exists, but doesn't match any part of the script (or the script was already completed on this machine). Exiting." >> $LogFile
    }
}
