# Scripts de Sauvegarde Active Directory

## Prérequis

- Windows Server avec rôle AD DS
- Module PowerShell ActiveDirectory
- Privilèges administrateur
- Module GroupPolicy (optionnel pour les GPO)

## Utilisation

### Sauvegarde manuelle

```powershell
.\Backup-ActiveDirectory.ps1 -BackupPath "C:\ADBackup" -FullBackup
```

### Programmation automatique

```powershell
.\Schedule-ADBackup.ps1 -TaskName "AD-Backup-Daily" -ScheduleTime "02:00"
```

### Restauration

```powershell
.\Restore-ADObjects.ps1 -BackupFolder "C:\ADBackup\20241220_020000"
```

## Fichiers générés

- `Users.csv` - Tous les utilisateurs AD
- `Groups.csv` - Tous les groupes AD
- `OUs.csv` - Toutes les unités organisationnelles
- `Computers.csv` - Tous les ordinateurs AD
- `GPOBackup/` - Sauvegarde des stratégies de groupe
- `SystemState/` - Sauvegarde complète (avec -FullBackup)
- `backup.log` - Journal des opérations
