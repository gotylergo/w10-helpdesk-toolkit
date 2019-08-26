    # Get credentials
    $DomainAdminUser = Read-Host "Enter your admin domain username in the form of domain\username"
    $DomainAdminPwd = Read-Host "Enter your domain password" -AsSecureString
    # $PlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainAdminPwd))
    # $Credentials = [System.Management.Automation.PSCredential]::new($DomainAdminUser, (ConvertTo-SecureString -AsPlainText -String $PlainText -Force))
    $Credentials = [System.Management.Automation.PSCredential]::new($DomainAdminUser, $DomainAdminPwd)
    $Credentials = $Credentials.GetNetworkCredential()
    Write-Output DomainName: $Credentials.Domain
    Write-Output DomainAdminUser: $Credentials.UserName
    Write-Output DomainAdminPwd: $Credentials.Password
    # $ClearText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credentials.Password))    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "Domain" -Value $credential.Domain

    # Save credentials
    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "DomainAdminUser" -Value $Credentials.UserName
    New-ItemProperty -Path HKLM:\SOFTWARE\pcProv -PropertyType String -Name "DomainName" -Value $Credentials.Domain
    $Credentials.SecurePassword | ConvertFrom-SecureString | Out-File C:\ProgramData\pcProv\cred.txt
    $DomainName = $Credentials.Domain
    Write-Output "domainName: $domainName" >> $LogFile

    # Retrieve and use stored credentials
    $DomainName = (Get-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "DomainName").DomainName
    Write-Output $DomainName
    $DomainAdminUser = (Get-ItemProperty -Path HKLM:\SOFTWARE\pcProv -Name "DomainAdminUser").DomainAdminUser
    Write-Output $DomainAdminUser
    $DomainAdminPwd = (get-content C:\ProgramData\pcProv\cred.txt | ConvertTo-SecureString)
    # Convert to plaintext
    # $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode(($StoredPwd | ConvertTo-SecureString))
    # $PlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
    # [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
    # Write-Output $PlainText
    # Convert stored credentials to Credential object
    $Credentials = [System.Management.Automation.PSCredential]::new("$DomainName\$DomainAdminUser", $DomainAdminPwd)
    $Credentials = $Credentials.GetNetworkCredential()
    Write-Output DomainName: $Credentials.Domain
    Write-Output DomainAdminUser: $Credentials.UserName
    Write-Output DomainAdminPwd: $Credentials.Password
