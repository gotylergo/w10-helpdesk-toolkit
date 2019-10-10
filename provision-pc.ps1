# Windows Update Script params section
param($global:RestartRequired = 0,
    $global:MoreUpdates = 0,
    $global:MaxCycles = 10)

### Config variables

### Defaults

## Domain Controller (Required) 
# $DC = 

## URL to Choco Scriptify Implementation (Required)
# $ChocoScriptifyURL = "https://tylerjustyn.dev/app/choco-scriptify"

## URL to download Chocolatey (Required) 
# $ChocolateyURL = "https://chocolatey.org/install.ps1"

## URL of internal Chocolatey Repository (Optional) 
# $ChocoRepoURL = 

## Path to Fileshare to Save Bitlocker Key (Optional)
# $BitlockerFSRoot = 

## URL of mail server for sending completion notification (Optional)
# $SMTPServer = 

$ScriptDir = "$env:ProgramData\ProvisionPC"

# Log file location
$LogFile = "$ScriptDir\log.txt"
# Create ProvisionPC folder in ProgramData
If (-not (Test-Path -Path ("$env:ProgramData\ProvisionPC\"))) {
    New-Item -Path $env:ProgramData -Name "ProvisionPC" -ItemType "directory"
}

#Log date and time on each run
Get-Date >> $LogFile

# Copy this script to ProgramData 
$CurrentScriptPath = $MyInvocation.MyCommand.Definition
$ScriptPath = "$ScriptDir\ProvisionPC.ps1"
If ($CurrentScriptPath -ne $ScriptPath) {
    Copy-Item -Path $CurrentScriptPath -Destination $ScriptPath
    Write-Output "Copied script to $ScriptPath" >> $LogFile
}


# Stored function to register a scheduled task to continue the script after reboot.
function Set-ScheduledRebootTask {
    $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NonInteractive -NoLogo -NoProfile -File $ScriptPath"
    $TaskTrigger = New-ScheduledTaskTrigger -RandomDelay (New-TimeSpan -Minutes 5) -AtStartup
    $TaskSettings = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 10 -StartWhenAvailable
    $Task = New-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings
    $CurrentUser = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -expand UserName
    $Task | Register-ScheduledTask -TaskName "ProvisionPC" -User $CurrentUser -Password "$LocalAdminPwd"

    If ($?) {
        Write-Output "Scheduled task created. Script will continue after reboot."
    }
    Else {
        Write-Error "Scheduled task could not be created. Run script manually after reboot."
    }
}
# Check if script has run yet
# Part 1.0: If reg key does not exist (script has not run before), start provisioning
If (-not (Test-Path 'HKLM:\SOFTWARE\ProvisionPC')) {

    #Create registry key so we can track our progress between reboots
    New-Item -Path HKLM:\SOFTWARE\ProvisionPC -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value 1.0 -Force
    If ($?) {
        Write-Output "Registry key created for script continuity after reboots with value: 1.0." >> $LogFile
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
    New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "DomainAdminUser" -Value $Credentials.GetNetworkCredential().UserName
    New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "DomainName" -Value $Credentials.GetNetworkCredential().Domain
    $Credentials.GetNetworkCredential().SecurePassword | ConvertFrom-SecureString | Out-File C:\ProgramData\ProvisionPC\cred.txt
    $DomainName = $Credentials.GetNetworkCredential().Domain

    $NewPCName = Read-Host "Enter the new computer name"
    New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "NewPCName" -Value $NewPCName
    Write-Output "NewPCName: $NewPCName" >> $LogFile
    # Confirm the serial number for the bitlocker folder
    $defaultValue = (Get-WmiObject win32_bios).SerialNumber
    $PCSerialNumber = Read-Host "What is the serial number of the end user machine? Leave blank to use this value: [$($defaultValue)]"
    If ($PCSerialNumber -eq "") {
        $PCSerialNumber = $defaultValue
    }
    Write-Output "pcSerialNumber: $PCSerialNumber" >> $LogFile
    New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "PCSerialNumber" -Value $PCSerialNumber
    $UserToNotify = Read-Host "Enter the email of the user you want to notify when complete"
    Write-Output "userToNotify: $UserToNotify" >> $LogFile
    New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "userToNotify" -Value $UserToNotify -Force
    # Open Choco-Scriptify and Save Command for use after Chocolatey is installed
    Write-Output "Opening Choco-Scriptify..."
    Start-Process -FilePath $ChocoScriptifyURL
    $ChocoCommand = Read-Host "Paste your Choco-Scriptify command here (uncheck 'install chocolatey')"
    $ChocoCommand = $ChocoCommand.Trim()
    New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "ChocoCommand" -Value $ChocoCommand -Force
    # Ask if user needs admin
    $NeedsAdmin = Read-Host "Is this a laptop or does the user need to be local admin? y/n"
    If ($NeedsAdmin -eq "y") {
        $EndUser = Read-Host "What is the username?"
        Write-Output "EndUser: $EndUser" >> $LogFile
        New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "EndUser" -Value $EndUser -Force
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
    $LocalAdminPwd = ""
    If ($Pwd1_txt -eq $Pwd2_txt) {
        $LocalAdminPwd = $Pwd1_txt
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
    iex ((New-Object System.Net.WebClient).DownloadString($ChocolateyURL))
    If ($?) {
        Write-Output "Chocolatey is installed." >> $LogFile
    }
    Else {
        Write-Error "Couldn't install Chocolatey. Try manually." >> $LogFile
    }

    # Increment the registry value to resume where we left off after reboot
    Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value 2.0
    If ($?) {
        Write-Output "Registry key changed to value: 2.0." >> $LogFile
    }

    Set-ScheduledRebootTask

    # Join to domain and restart
    Add-Computer -DomainName $DomainName -Server $DC -Credential $Credentials -Restart -Force
}
# Part 2: If script has run, check reg key to determine where to continue
Else {
    $regStatus = Get-ItemPropertyValue HKLM:\SOFTWARE\ProvisionPC -Name "Status"
    Switch ($regStatus) {
        "2.0" {
            Write-Output "Registry key value is: 2.0. Continuing from Part 2.0" >> $LogFile

            $NewPCName = Get-ItemPropertyValue HKLM:\SOFTWARE\ProvisionPC -Name "NewPCName"
            # Retrieve stored credentials
            $DomainName = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\ProvisionPC -Name "DomainName"
            $DomainAdminUser = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\ProvisionPC -Name "DomainAdminUser"
            $DomainAdminPwd = (Get-content C:\ProgramData\ProvisionPC\cred.txt | ConvertTo-SecureString)
            # Convert stored credentials to Credential object
            $Credentials = [System.Management.Automation.PSCredential]::new("$DomainName\$DomainAdminUser", $DomainAdminPwd)

            Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value 2.1
            If ($?) {
                Write-Output "Registry key changed to value: 2.1." >> $LogFile
            }
            Rename-Computer -NewName $NewPCName -DomainCredential $Credentials -Restart -Force

        }
        "2.1" {
            Write-Output "Registry key value is: 2.1. Continuing from Part 2.1" >> $LogFile

            # Add Choco Repo
            If ($null -ne $ChocoRepoName) {
                choco source add -n=$ChocoRepoName -s $ChocoRepoURL --priority="'1'"
                If ($?) {
                    Write-Output "Choco source added: $ChocoRepoName." >> $LogFile
                }
                Else {
                    Write-Error "Choco source add: '$ChocoRepoName' failed." >> $LogFile
                }
            }
    
            $ChocoCommand = Get-ItemPropertyValue HKLM:\SOFTWARE\ProvisionPC -Name "ChocoCommand"
            Invoke-Expression $ChocoCommand
    
            # Increment the registry value to resume where we left off after reboot
            Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value 2.2
            If ($?) {
                Write-Output "Registry key changed to value: 2.2." >> $LogFile
            }
            Restart-Computer -Force
        }
        "2.2" {
            Write-Output "Registry key value is: 2.2. Continuing from Part 2.2" >> $LogFile

            Write-Output "Running Windows Update Script" >> $LogFile
            # Credit to joefitzgerald on Github https://gist.github.com/joefitzgerald/8203265
    
            function Check-ContinueRestartOrEnd() {
                $RegistryKey = "HKLM:\SOFTWARE\ProvisionPC"
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
    
            Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value 2.3
            If ($?) {
                Write-Output "Registry key changed to value: 2.3." >> $LogFile
            }
            Restart-Computer -Force
        }
        "2.3" {
            Write-Output "Registry key value is: 2.3 Continuing from Part 2.3" >> $LogFile

            # Add laptop user to Administrators
            $EndUser = Get-ItemPropertyValue HKLM:\SOFTWARE\ProvisionPC -Name "EndUser"
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
            
            # Retrieve stored credentials
            $DomainName = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\ProvisionPC -Name "DomainName"
            $DomainAdminUser = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\ProvisionPC -Name "DomainAdminUser"
            $DomainAdminPwd = (Get-content C:\ProgramData\ProvisionPC\cred.txt | ConvertTo-SecureString)
            # Convert stored credentials to Credential object
            $Credentials = [System.Management.Automation.PSCredential]::new("$DomainName\$DomainAdminUser", $DomainAdminPwd)
    
            # Retrieve PCSerialNumber
            $PCSerialNumber = (Get-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "PCSerialNumber").PCSerialNumber
    
            # Update Group Policy (For Storing GP in AD if enabled)
            gpupdate /force
    
            # Encrypt System Drive
            Write-Output "Encrypting system drive..." >> $LogFile
            Start-Process 'manage-bde.exe' -ArgumentList " -protectors -add $env:SystemDrive -recoverypassword" -Verb runas -Wait
            Start-Process 'manage-bde.exe' -ArgumentList " -on -usedspaceonly $env:SystemDrive -em aes256 " -Verb runas -Wait
            If ($?) {
                Write-Output "Bitlocker encryption successful." >> $LogFile
            }
            Else {
                Write-Error "Bitlocker encryption failed. Try manually." >> $Logfile
            }
            #Backing Password file to the server
            New-PSDrive -Name "z" -PSProvider "Filesystem" -Root $BitlockerFSRoot -Credential $Credentials
            If ($?) {
                New-Item -Path "z:\" -Name "$env:computername $PCSerialNumber" -ItemType "directory"
                $BLV = Get-BitLockerVolume -MountPoint "C:"
                $KeyProtector = ($BLV.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
                $KeyProtectorID = $KeyProtector.$KeyProtectorID
                $KeyProtector > "z:\$env:computername $PCSerialNumber\Bitlocker Recovery Key $KeyProtectorID.txt"
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
    
            Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value 2.4
            If ($?) {
                Write-Output "Registry key changed to value: 2.4." >> $LogFile
            }
            Restart-Computer -Force
        }
        "2.4" {
            Write-Output "Registry key value is: 2.4. Continuing from Part 2.4" >> $LogFile
            Write-Output "Provisioning complete. Cleaning up..." >> $LogFile
    
            # Email to notify the script is complete
            $UserToNotify = Get-ItemPropertyValue HKLM:\SOFTWARE\ProvisionPC -Name "userToNotify"
            If ($null -ne $SMTPServer) {
                Send-MailMessage -From $UserToNotify -To $UserToNotify -Subject "$env:computername Provisioning Complete" -Body "See the attached log for details." -Attachments $LogFile -Priority High -DeliveryNotificationOption OnSuccess, OnFailure -SmtpServer $SMTPServer
                If ($?) {
                    Write-Output "Completion email sent." >> $LogFile
                }
                Else {
                    Write-Error "Completion email could not be sent." >> $LogFile
                }
            }
    
            Remove-Item -Path "$ScriptDir\cred.txt" -Force
            If ($?) {
                Write-Output "Removed stored credential."
            }
            Else {
                Write-Error "Couldn't remove credential. Manually from $ScriptDir\cred.txt"
            }
            Unregister-ScheduledTask -TaskName "ProvisionPC" -Confirm:$false
            If ($?) {
                Write-Output "Unregistered scheduled task." >> $LogFile
            }
            Else {
                Write-Error "Scheduled task 'ProvisionPC' could not be unregistered. Try manually." >> $LogFile
            }
            # Increment script number
            Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value "Done"
            If ($?) {
                Write-Output "Registry key changed to value: DONE." >> $LogFile
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
        "DONE" {
            Write-Output "Script has already completed. Exiting."
        }
        Default {
            Throw "Reg key exists, but doesn't match any part of the script. Exiting." >> $LogFile
        }
    }
}
