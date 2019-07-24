# Get variables
$credential = Get-Credential -Message "Enter your network credentials (domain\username)"
$domainName = Read-Host "Enter the domain to join"
$pcName = Read-Host "Enter the new computer name"
$pwd1 = Read-Host "Enter the local administrator account password" -AsSecureString
$pwd2 = Read-Host "Confirm the local administrator password" -AsSecureString

# Convert passwords to plaintext for comparison
$pwd1_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd1))
$pwd2_txt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd2))
# Check if passwords match and if so, create accounts
If ($pwd1_txt -eq $pwd2_txt) {
    # Set Password and enable Administrator account
    Set-LocalUser -Name "Administrator" -Password $pwd1 -PasswordNeverExpires:$true
    Enable-LocalUser -Name "Administrator"
    # Set password and enable local non admin account
    New-LocalUser -Name "helpdesk" -Password (ConvertTo-SecureString -AsPlainText "helpdesk" -Force) -FullName "helpdesk" -PasswordNeverExpires:$true
} Else {
    Write-Output "Passwords don't match!"
}

# Install .net 3.5
Add-WindowsCapability -Online -Name NetFx3~~~~

# Join to domain
Add-Computer -DomainName $domainName -NewName $pcName -Credential $credential -Restart -Force
