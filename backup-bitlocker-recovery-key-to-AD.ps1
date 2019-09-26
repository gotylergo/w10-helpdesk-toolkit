$BLV = Get-BitLockerVolume -MountPoint "C:"
$Key = ($BLV.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}).KeyProtectorId
manage-bde -protectors -adbackup c: -id $Key
