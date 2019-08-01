# Check registry key to see where to start the script
if (Test-Path 'HKLM:\SOFTWARE\pcProv') {
    $regStatus = Get-ItemPropertyValue HKLM:\SOFTWARE\pcProv -Name "Status"
    if ($regStatus -eq 1) {
        Write-Output "Still working on this part! Stay tuned!"
    }
}
else {

    # Get variables first
    $credential = Get-Credential -Message "Enter your credentials in the form of domain\username"
    $domainName = Read-Host "Enter the domain to join"
    $newPCName = Read-Host "Enter the new computer name"
    $pwd1 = Read-Host "Enter the local administrator account password" -AsSecureString
    $pwd2 = Read-Host "Confirm the local administrator password" -AsSecureString

    #Create registry key so we can track our progress between reboots
    New-Item -Path HKLM:\SOFTWARE\pcProv -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 0 -Force

    # Convert passwords to plaintext for comparison
    $pwd1_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd1))
    $pwd2_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd2))
    # Check if passwords match and if so, create accounts
    If ($pwd1_txt -eq $pwd2_txt) {
        # Set password and enable Administrator account
        Set-LocalUser -Name "Administrator" -Password $pwd1 -PasswordNeverExpires:$true
        Enable-LocalUser -Name "Administrator"
        # Set password and enable local non admin account
        New-LocalUser -Name "helpdesk" -Password (ConvertTo-SecureString -AsPlainText "helpdesk" -Force) -FullName "helpdesk" -PasswordNeverExpires:$true
    }
    Else {
        Write-Output "Passwords don't match!"
    }

    # Install .net 3.5
    Add-WindowsCapability -Online -Name NetFx3~~~~

    # Run W10 Cleanup Script
    # Invoke-Expression -Command ".\w10-clean.ps1"

    # Increment the registry value to resume where we left off after reboot
    Set-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "Status" -Value 1

    ## Rename the computer and restart
    # Rename-Computer -NewName $newPCName -Restart -Force

    # Join to domain and restart
    Add-Computer -DomainName $domainName -NewName $newPCName -Credential $credential -Restart -Force

}
