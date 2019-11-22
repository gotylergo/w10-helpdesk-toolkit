# Windows 10 Provisioning Scripts

Scripts to be used by helpdesk in provisioning Windows computers (tested on Windows 10).

- **[backup-bitlocker-recovery-key-to-AD.ps1](backup-bitlocker-recovery-key-to-AD.ps1)**: If Group Policy allows it, backup the bitlocker recovery key to the computer's Active Directory object
- **[provision-pc.ps1](provision-pc.ps1)**: Provision a PC in a domain environment
- **[provision-pc-reset.ps1](provision-pc-reset.ps1)**: Use to undo provision-pc.ps1 in case it needs to be run again (registry settings, scheduled tasks, saved credentials) _Note: Does not undo the provisioning steps that were already performed _
- **[remote-ps.bat](remote-ps.bat)**: Join to a domain and enable remote PS execution
- **[set-user-accounts.ps1](set-user-accounts.ps1)** Enable local admin user (with password) and local standard user
- **[term-processor.ps1](term-processor.ps1)**: _WIP_ Process employee terminations in Active Directory
