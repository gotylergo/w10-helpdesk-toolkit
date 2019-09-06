REM Setting PC up for remote powershell and joining to domain
powershell.exe -Command "Enable-PSRemoting -Force"
set /p NewPCName=Enter the NewPCName.
set DomainName=carsdirect.win
powershell.exe -Command "Add-Computer -DomainName %DomainName% -Server HQ-corpdc01 -NewName %NewPCName% -Credential (Get-Credential) -Restart -Force"
