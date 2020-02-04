# Windows Update Script params section
param($global:RestartRequired = 0,
  $global:MoreUpdates = 0,
  $global:MaxCycles = 10)

# Confirm PC is domain joined and named correctly before running script
Write-Output "Before we start, confirm: `n 1) this workstation is joined to the domain and renamed properly `n 2) you are running the script from a local admin account (not a domain account)"
Pause

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

$SuccessLogFile = "$ScriptDir\success-log.txt"
$ErrorLogFile = "$ScriptDir\error-log.txt"
$ChocoCommandFile = "$ScriptDir\choco-command-log.txt"
# Create ProvisionPC folder in ProgramData
If (-not (Test-Path -Path ("$env:ProgramData\ProvisionPC\"))) {
  Try {
    New-Item -Path $env:ProgramData -Name "ProvisionPC" -ItemType "directory"
    Write-Output "Created '$env:ProgramData\ProvisionPC' Directory." >> $SuccessLogFile
  }
  Catch {
    Throw "Couldn't create '$env:ProgramData\ProvisionPC' Directory. Exiting." >> $ErrorLogFile
  }
}

# Log date and time on each run
Get-Date >> $SuccessLogFile
Get-Date >> $ErrorLogFile

# Copy this script to ProgramData 
$CurrentScriptPath = $MyInvocation.MyCommand.Definition
$ScriptPath = "$ScriptDir\ProvisionPC.ps1"
If ($CurrentScriptPath -ne $ScriptPath) {
  Try {
    Copy-Item -Path $CurrentScriptPath -Destination $ScriptPath
    Write-Output "Copied script to $ScriptPath" >> $SuccessLogFile
  }
  Catch {
    Throw "Couldn't move script to $ScriptPath. Exiting." >> $ErrorLogFile
  }
}


# Stored function to register a scheduled task to continue the script after reboot.
function Set-ScheduledRebootTask {
  Try {
    $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NonInteractive -NoLogo -NoProfile -File $ScriptPath"
    $TaskTrigger = New-ScheduledTaskTrigger -RandomDelay (New-TimeSpan -Minutes 5) -AtStartup
    $TaskSettings = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 10 -StartWhenAvailable
    $Task = New-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings
    $CurrentUser = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -expand UserName
    $Task | Register-ScheduledTask -TaskName "ProvisionPC" -User $CurrentUser -Password "$LocalAdminPwd"

    Write-Output "Scheduled task created. Script will continue after reboot." >> $SuccessLogFile
  }
  Catch {
    Write-Error "Scheduled task could not be created. Run script manually after reboot." >> $ErrorLogFile 
  }
}
# Check if script has run yet
# Part 1.0: If reg key does not exist (script has not run before), start provisioning
If (-not (Test-Path 'HKLM:\SOFTWARE\ProvisionPC')) {

  #Create registry key so we can track our progress between reboots
  Try {
    New-Item -Path HKLM:\SOFTWARE\ProvisionPC -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value "1.0" -Force
    Write-Output "Registry key created for script continuity after reboots with value: 1.0." >> $SuccessLogFile
  }
  Catch {
    Throw "Couldn't create registry entry in 'HKLM:\SOFTWARE\ProvisionPC'. Exiting." >> $ErrorLogFile
  }

  # Get variables, store variables that will be needed after reboot in the registry
  # Get credentials until they are correct
  Add-Type -AssemblyName System.DirectoryServices.AccountManagement
  $ValidAccount = $False
  $Attempt = 1
  $MaxAttempts = 5
  $CredentialPrompt = "Getting domain admin credentials (attempt #$Attempt out of $MaxAttempts):"

  Do {
    # Blank any previous failure messages and then prompt for credentials with the custom message and the pre-populated domain\user name.
    $FailureMessage = $Null
    Write-Output $CredentialPrompt
    $DomainAdminUser = Read-Host "Enter your domain admin username in the form of domain\username"
    $DomainAdminPwd = Read-Host "Enter your domain admin password" -AsSecureString
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $Credentials = [System.Management.Automation.PSCredential]::new($DomainAdminUser, $DomainAdminPwd)

  
    # Verify the credentials prompt wasn't bypassed.
    If ($Credentials) {
      $UserName = $Credentials.UserName
      # Test the user name (even if it was changed in the credential prompt) and password.
      $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
      Try {
        $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $ContextType, $UserDomain
      }
      Catch {
        If ($_.Exception.InnerException -like "*The server could not be contacted*") {
          $FailureMessage = "Could not contact a server for the specified domain on attempt #$Attempt out of $MaxAttempts."
        }
        Else {
          $FailureMessage = "Unpredicted failure: `"$($_.Exception.Message)`" on attempt #$Attempt out of $MaxAttempts."
        }
      }
      # If there wasn't a failure talking to the domain test the validation of the credentials, and if it fails record a failure message.
      If (-not($FailureMessage)) {
        $ValidAccount = $PrincipalContext.ValidateCredentials($UserName, $Credentials.GetNetworkCredential().Password)
        If (-not($ValidAccount)) {
          $FailureMessage = "Bad user name or password used on credential prompt attempt #$Attempt out of $MaxAttempts."
        }
      }
      # Otherwise the credential prompt was (most likely accidentally) bypassed so record a failure message.
    }
    Else {
      $FailureMessage = "Credential prompt closed/skipped on attempt #$Attempt out of $MaxAttempts."
    }
 
    # If there was a failure message recorded above, display it, and update credential prompt message.
    If ($FailureMessage) {
      Write-Warning "$FailureMessage"
      $Attempt++
      If ($Attempt -lt $MaxAttempts) {
        $CredentialPrompt = "Authentication error. Please try again (attempt #$Attempt out of $MaxAttempts):"
      }
      ElseIf ($Attempt -eq $MaxAttempts) {
        $CredentialPrompt = "Authentication error. THIS IS YOUR LAST CHANCE (attempt #$Attempt out of $MaxAttempts):"
      }
    }
  } Until (($ValidAccount) -or ($Attempt -gt $MaxAttempts))

  # Save credentials
  New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "DomainAdminUser" -Value $Credentials.GetNetworkCredential().UserName
  New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "DomainName" -Value $Credentials.GetNetworkCredential().Domain
  $Credentials.GetNetworkCredential().SecurePassword | ConvertFrom-SecureString | Out-File C:\ProgramData\ProvisionPC\cred.txt
  $DomainName = $Credentials.GetNetworkCredential().Domain

  $NewPCName = $env:COMPUTERNAME
  New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "NewPCName" -Value $NewPCName
  Write-Output "NewPCName: $NewPCName" >> $SuccessLogFile
  # Confirm the serial number for the bitlocker folder
  $defaultValue = (Get-WmiObject win32_bios).SerialNumber
  $PCSerialNumber = Read-Host "What is the serial number of the end user machine? Leave blank to use this value: [$($defaultValue)]"
  If ($PCSerialNumber -eq "") {
    $PCSerialNumber = $defaultValue
  }
  Write-Output "pcSerialNumber: $PCSerialNumber" >> $SuccessLogFile
  New-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -PropertyType String -Name "PCSerialNumber" -Value $PCSerialNumber
  $UserToNotify = Read-Host "Enter the email of the user you want to notify when complete"
  Write-Output "userToNotify: $UserToNotify" >> $SuccessLogFile
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
    Write-Output "EndUser: $EndUser" >> $SuccessLogFile
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
  $LocalAdminPwd = $Pwd1_txt
  # If passwords match, create accounts

  # Set password and enable Administrator account
  Try {
    $LocalAdminPwd = $Pwd1_txt
    Set-LocalUser -Name "Administrator" -Password $Pwd1 -PasswordNeverExpires:$true
    Write-Output "Administer password set." >> $SuccessLogFile 
  }
  Catch {
    Write-Error "Error: Couldn't set Administrator password. " >> $ErrorLogFile
  }
  Try {
    Enable-LocalUser -Name "Administrator"
    Write-Output "Administer account enabled." >> $SuccessLogFile 
  }
  Catch {
    Write-Error "Error: Couldn't enable administrator account. " >> $ErrorLogFile
  }
  # Set currently logged in admin account password to Administrator password
  Try {
    Set-LocalUser -Name $env:UserName -Password $Pwd1 -PasswordNeverExpires:$true
    Write-Output "$env:UserName password set." >> $SuccessLogFile 
  }
  Catch {
    Write-Error "Error: Couldn't set $env:UserName password. " >> $ErrorLogFile
  }

  # Set password and enable local non admin account
  Try {
    New-LocalUser -Name "helpdesk" -Password (ConvertTo-SecureString -AsPlainText "helpdesk" -Force) -FullName "helpdesk" -PasswordNeverExpires:$true
    Write-Output "Standard helpdesk account created." >> $SuccessLogFile 
  }
  Catch {
    Write-Error "Error: Couldn't create standard helpdesk user. " >> $ErrorLogFile
  }

  # Install .net 3.5
  Try {
    Add-WindowsCapability -Online -Name NetFx3~~~~
    Write-Output "Installed Windows Feature: .NET Framework 3.5 (Includes .NET 2.0 and 3.0)" >> $SuccessLogFile
  }
  Catch {
    Write-Error "Couldn't install .NET Framework 3.5. Try manually." >> $ErrorLogFile
  }

  # Install Chocolatey
  Try {
    iex ((New-Object System.Net.WebClient).DownloadString($ChocolateyURL))
    Write-Output "Chocolatey is installed." >> $SuccessLogFile
  }
  Catch {
    Write-Error "Couldn't install Chocolatey. Try manually." >> $ErrorLogFile
  }

  # Increment the registry value to resume where we left off after reboot
  Try {
    Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value "2.0"
    Write-Output "'Status' registry key changed to value: 2.0." >> $SuccessLogFile
  }
  Catch {
    Write-Error "Couldn't change 'Status' registry key."
  }

  Set-ScheduledRebootTask

  # Join to domain and restart
  Write-Output "Restarting." >> $SuccessLogFile
    Restart-Computer -Force
}
# Part 2: If script has run, check reg key to determine where to continue
Else {
  $regStatus = Get-ItemPropertyValue HKLM:\SOFTWARE\ProvisionPC -Name "Status"
  Switch ($regStatus) {
    "2.0" {
      Write-Output "Registry key value is: 2.0. Continuing from Part 2.0" >> $SuccessLogFile

      # Add Choco Repo
      If ($null -ne $ChocoRepoName) {
        Try {
          choco source add -n=$ChocoRepoName -s $ChocoRepoURL --priority="'1'"
          Write-Output "Choco source added: $ChocoRepoName." >> $SuccessLogFile
        }
        Catch {
          Write-Error "Choco source add: '$ChocoRepoName' failed." >> $ErrorLogFile
        }
      }
    
      Start-Transcript -Path $ChocoCommandFile
      $ChocoCommand = Get-ItemPropertyValue HKLM:\SOFTWARE\ProvisionPC -Name "ChocoCommand"
      Invoke-Expression $ChocoCommand
      Stop-Transcript
    
      # Increment the registry value to resume where we left off after reboot
      Try {
        Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value "2.1"
        Write-Output "'Status' registry key changed to value: 2.1." >> $SuccessLogFile
      }
      Catch {
        Write-Error "Couldn't change 'Status' registry key."
      }
      Restart-Computer -Force
    }
    "2.1" {
      Write-Output "Registry key value is: 2.1. Continuing from Part 2.1" >> $SuccessLogFile

      Write-Output "Running Windows Update Script" >> $SuccessLogFile
      # Credit to joefitzgerald on Github https://gist.github.com/joefitzgerald/8203265
    
      function Check-ContinueRestartOrEnd() {
        $RegistryKey = "HKLM:\SOFTWARE\ProvisionPC"
        $RegistryEntry = "InstallWindowsUpdates"
        switch ($global:RestartRequired) {
          0 {			
            $prop = (Get-ItemProperty $RegistryKey).$RegistryEntry
            If ($prop) {
              Write-Output "Restart Registry Entry Exists - Removing It" >> $SuccessLogFile
              Remove-ItemProperty -Path $RegistryKey -Name $RegistryEntry -ErrorAction SilentlyContinue
            }
                
            Write-Output "No Restart Required" >> $SuccessLogFile
            Check-WindowsUpdates
                
            If (($global:MoreUpdates -eq 1) -and ($script:Cycles -le $global:MaxCycles)) {
              Stop-Service $script:ServiceName -Force
              Set-Service -Name $script:ServiceName -StartupType Disabled -Status Stopped 
              Install-WindowsUpdates
            }
            ElseIf ($script:Cycles -gt $global:MaxCycles) {
              Write-Output "Exceeded Cycle Count - Stopping" >> $SuccessLogFile
            }
            Else {
              Write-Output "Done Installing Windows Updates" >> $SuccessLogFile
            }
          }
          1 {
            $prop = (Get-ItemProperty $RegistryKey).$RegistryEntry
            If (-not $prop) {
              Write-Output "Restart Registry Entry Does Not Exist - Creating It" >> $SuccessLogFile
              Set-ItemProperty -Path $RegistryKey -Name $RegistryEntry -Value "1"
            }
            Else {
              Write-Output "Restart Registry Entry Exists Already" >> $SuccessLogFile
            }
                
            Write-Output "Restart Required - Restarting..." >> $SuccessLogFile
            Restart-Computer
          }
          default { 
            Write-Output "Unsure If A Restart Is Required"  >> $SuccessLogFile
            break
          }
        }
      }
    
      function Install-WindowsUpdates() {
        $script:Cycles++
        Write-Output 'Evaluating Available Updates:' >> $SuccessLogFile
        $UpdatesToDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl'
        foreach ($Update in $SearchResult.Updates) {
          If (($Update -ne $null) -and (!$Update.IsDownloaded)) {
            [bool]$addThisUpdate = $false
            If ($Update.InstallationBehavior.CanRequestUserInput) {
              Write-Output "> Skipping: $($Update.Title) because it requires user input" >> $SuccessLogFile
            }
            Else {
              If (!($Update.EulaAccepted)) {
                Write-Output "> Note: $($Update.Title) has a license agreement that must be accepted. Accepting the license." >> $SuccessLogFile
                $Update.AcceptEula()
                [bool]$addThisUpdate = $true
              }
              Else {
                [bool]$addThisUpdate = $true
              }
            }
            
            If ([bool]$addThisUpdate) {
              Write-Output "Adding: $($Update.Title)" >> $SuccessLogFile
              $UpdatesToDownload.Add($Update) | Out-Null
            }
          }
        }
        
        If ($UpdatesToDownload.Count -eq 0) {
          Write-Output "No Updates To Download..." >> $SuccessLogFile
        }
        Else {
          Write-Output 'Downloading Updates...' >> $SuccessLogFile
          $Downloader = $UpdateSession.CreateUpdateDownloader()
          $Downloader.Updates = $UpdatesToDownload
          $Downloader.Download()
        }
        
        $UpdatesToInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl'
        [bool]$rebootMayBeRequired = $false
        Write-Output 'The following updates are downloaded and ready to be installed:' >> $SuccessLogFile
        foreach ($Update in $SearchResult.Updates) {
          If (($Update.IsDownloaded)) {
            Write-Output "> $($Update.Title)" >> $SuccessLogFile
            $UpdatesToInstall.Add($Update) | Out-Null
                  
            If ($Update.InstallationBehavior.RebootBehavior -gt 0) {
              [bool]$rebootMayBeRequired = $true
            }
          }
        }
        
        If ($UpdatesToInstall.Count -eq 0) {
          Write-Output 'No updates available to install...' >> $SuccessLogFile
          $global:MoreUpdates = 0
          $global:RestartRequired = 0
          break
        }
    
        If ($rebootMayBeRequired) {
          Write-Output 'These updates may require a reboot' >> $SuccessLogFile
          $global:RestartRequired = 1
        }
        
        Write-Output 'Installing updates...' >> $SuccessLogFile
      
        $Installer = $script:UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $UpdatesToInstall
        $InstallationResult = $Installer.Install()
      
        Write-Output "Installation Result: $($InstallationResult.ResultCode)" >> $SuccessLogFile
        Write-Output "Reboot Required: $($InstallationResult.RebootRequired)" >> $SuccessLogFile
        Write-Output 'Listing of updates installed and individual installation results:' >> $SuccessLogFile
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
        Write-Output "Checking For Windows Updates" >> $SuccessLogFile
        $Username = $env:USERDOMAIN + "\" + $env:USERNAME
     
        New-EventLog -Source $ScriptName -LogName 'Windows Powershell' -ErrorAction SilentlyContinue
     
        $Message = "Script: " + $ScriptPath + "`nScript User: " + $Username + "`nStarted: " + (Get-Date).toString()
    
        Write-EventLog -LogName 'Windows Powershell' -Source $ScriptName -EventID "104" -EntryType "Information" -Message $Message
        Write-Output $Message >> $SuccessLogFile
    
        $script:UpdateSearcher = $script:UpdateSession.CreateUpdateSearcher()
        $script:SearchResult = $script:UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")      
        If ($SearchResult.Updates.Count -ne 0) {
          $script:SearchResult.Updates | Select-Object -Property Title, Description, SupportUrl, UninstallationNotes, RebootRequired, EulaAccepted | Format-List
          $global:MoreUpdates = 1
        }
        Else {
          Write-Output 'There are no applicable updates' >> $SuccessLogFile
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

      # Increment the registry value to resume where we left off after reboot
      Try {
        Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value "2.2"
        Write-Output "'Status' registry key changed to value: 2.2." >> $SuccessLogFile
      }
      Catch {
        Write-Error "Couldn't change 'Status' registry key."
      }
      Restart-Computer -Force
    }
    "2.2" {
      Write-Output "Registry key value is: 2.2 Continuing from Part 2.2" >> $SuccessLogFile

      # Add laptop user to Administrators
      $EndUser = Get-ItemPropertyValue HKLM:\SOFTWARE\ProvisionPC -Name "EndUser"
      If ($EndUser.length -gt 0 ) {
        Try {
          Write-Output "Adding $EndUser to Administrators group."
          Add-LocalGroupMember -Group "Administrators" -Member "$DomainName\$EndUser"
          Write-Output "Added $EndUser to Administrators successfully" >> $SuccessLogFile
        }
        Catch {
          Write-Error "Adding $EndUser to Administrators failed. Try manually." >> $ErrorLogFile
        }
      }
            
      # Retrieve stored credentials
      $DomainName = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\ProvisionPC -Name "DomainName"
      $DomainAdminUser = Get-ItemPropertyValue -Path HKLM:\SOFTWARE\ProvisionPC -Name "DomainAdminUser"
      $DomainAdminPwd = (Get-content C:\ProgramData\ProvisionPC\cred.txt | ConvertTo-SecureString)
      # Convert stored credentials to Credential object
      $Credentials = [System.Management.Automation.PSCredential]::new("$DomainName\$DomainAdminUser", $DomainAdminPwd)
    
      # Retrieve PCSerialNumber
      $PCSerialNumber = (Get-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "PCSerialNumber").PCSerialNumber
    
      # Update Group Policy (For Storing Bitlocker in AD if enabled)
      gpupdate /force
    
      # Encrypt System Drive
      Try {
        Write-Output "Encrypting system drive..." >> $SuccessLogFile
        Start-Process 'manage-bde.exe' -ArgumentList " -protectors -add $env:SystemDrive -recoverypassword" -Verb runas -Wait
        Start-Process 'manage-bde.exe' -ArgumentList " -on -usedspaceonly $env:SystemDrive -em aes256 " -Verb runas -Wait
        Write-Output "Bitlocker encryption successful." >> $SuccessLogFile
      }
      Catch {
        Write-Error "Bitlocker encryption failed. Try manually." >> $ErrorLogfile
      }

      #Backing Password file to the server
      Try {
        New-PSDrive -Name "z" -PSProvider "Filesystem" -Root $BitlockerFSRoot -Credential $Credentials
        New-Item -Path "z:\" -Name "$env:computername $PCSerialNumber" -ItemType "directory"
        $BLV = Get-BitLockerVolume -MountPoint "C:"
        $KeyProtector = ($BLV.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
        $KeyProtectorID = $KeyProtector.$KeyProtectorID
        $KeyProtector > "z:\$env:computername $PCSerialNumber\Bitlocker Recovery Key $KeyProtectorID.txt"
        Write-Output "Bitlocker key successfully saved." >> $SuccessLogFile
      }
      Catch {
          Write-Error "Saving Bitlocker key failed. Try manually." >> $ErrorLogFile
      }

      # Increment the registry value to resume where we left off after reboot
      Try {
        Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value "2.3"
        Write-Output "'Status' registry key changed to value: 2.3." >> $SuccessLogFile
      }
      Catch {
        Write-Error "Couldn't change 'Status' registry key."
      }
      
      Restart-Computer -Force
    }
    "2.3" {
      Write-Output "Registry key value is: 2.3. Continuing from Part 2.3" >> $SuccessLogFile
      Write-Output "Provisioning complete. Cleaning up..." >> $SuccessLogFile
    
      # Email to notify the script is complete
      $UserToNotify = Get-ItemPropertyValue HKLM:\SOFTWARE\ProvisionPC -Name "userToNotify"
      If ($null -ne $SMTPServer) {
        Try {
          Send-MailMessage -From $UserToNotify -To $UserToNotify -Subject "$env:computername Provisioning Complete" -Body "See the attached log for details." -Attachments $SuccessLogFile, $ErrorLogFile, $ChocoCommandFile -Priority High -SmtpServer $SMTPServer
          Write-Output "Completion email sent." >> $SuccessLogFile
        }
        Catch {
          Write-Error "Completion email could not be sent." >> $ErrorLogFile
        }
      }
    
      Try {
        Remove-Item -Path "$ScriptDir\cred.txt" -Force
        Write-Output "Removed stored credential." >> $SuccessLogFile
      }
      Catch {
        Write-Error "Couldn't remove credential. Manually from $ScriptDir\cred.txt" >> $ErrorLogFile
      }
      Try {
        Unregister-ScheduledTask -TaskName "ProvisionPC" -Confirm:$false
        Write-Output "Unregistered scheduled task." >> $SuccessLogFile
      }
      Catch {
        Write-Error "Scheduled task 'ProvisionPC' could not be unregistered. Try manually." >> $ErrorLogFile
      }
      # Increment Registry 'Status'
      Try {
        Set-ItemProperty -Path HKLM:\SOFTWARE\ProvisionPC -Name "Status" -Value "DONE"
        Write-Output "'Status' registry key changed to value: DONE." >> $SuccessLogFile
      }
      Catch {
        Write-Error "Couldn't change 'Status' registry key."
      }
      # After completion, the script deletes itself
      Try {
        Remove-Item -LiteralPath ($MyInvocation.MyCommand.Path) -Force
        Write-Output "Script deleted." >> $SuccessLogFile
      }
      Catch {
        Write-Error "Couldn't delete script. Remove manually from $ScriptDir" >> $ErrorLogFile
      }    
    }
    "DONE" {
      Write-Output "Script has already completed. Exiting." >> $SuccessLogFile
    }
    Default {
      Throw "Reg key exists, but doesn't match any part of the script. Exiting." >> $SuccessLogFile
    }
  }
}
