# Use to undo provision-pc in case it needs to be run again (reg settings, scheduled tasks, saved credentials)

$ScriptDir = "$env:ProgramData\ProvisionPC"

If (Test-Path -Path ($ScriptDir)) {
  Get-ChildItem $ScriptDir -Include * -Recurse | Remove-Item
  Remove-Item -Path $ScriptDir -Force
}

If (Test-Path 'HKLM:\SOFTWARE\ProvisionPC') {
  Remove-Item -Path HKLM:\SOFTWARE\ProvisionPC -Recurse -Force
}

$TaskExists = Get-ScheduledTask | Where-Object { $_.TaskName -like "ProvisionPC" }

If ($TaskExists) {
  Unregister-ScheduledTask -TaskName "ProvisionPC" -Confirm:$false
} 
