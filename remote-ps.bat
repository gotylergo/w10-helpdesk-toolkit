REM Setting PC up for remote powershell and joining to domain
powershell.exe -Command "Enable-PSRemoting -Force"
set /p NewPCName=Enter the NewPCName.
set /p DomainName=Enter the domain to join
set /p Server=Enter the domain controller
powershell.exe -Command "Add-Computer -DomainName %DomainName% -Server %Server% -NewName %NewPCName% -Credential (Get-Credential) -Restart -Force"
