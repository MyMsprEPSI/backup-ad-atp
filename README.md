# Backup AD & ATP

## Description

Ce projet permet d'automatiser la sauvegarde et la gestion des données Active Directory (AD) et Advanced Threat Protection (ATP). Il fournit des scripts et outils pour faciliter la maintenance, la sécurité et la restauration des environnements AD et ATP.

## Fonctionnalités

- Sauvegarde automatisée des objets AD (utilisateurs, groupes, ordinateurs, etc.)
- Exportation et archivage des configurations ATP
- Restauration rapide à partir des sauvegardes
- Journalisation détaillée des opérations
- Notifications en cas d'échec ou de succès des sauvegardes
- Interface de configuration simple

## Prérequis

- Windows Server avec droits d'administration
- PowerShell 5.1 ou supérieur
- Droits d'accès à Active Directory et ATP
- Modules PowerShell : ActiveDirectory, AzureAD (si applicable)

## Installation

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/MyMsprEPSI/backup-ad-atp.git
   ```
2. Accédez au dossier du projet :
   ```bash
   cd backup-ad-atp
   ```
3. Installez les modules nécessaires :
   ```powershell
   Install-Module ActiveDirectory
   Install-Module AzureAD
   ```

## Utilisation

1. Configurez les paramètres dans le fichier `config.json` ou via les variables d'environnement.
2. Lancez le script principal :
   ```powershell
   .\backup-ad-atp.ps1
   ```
3. Consultez les logs dans le dossier `logs/` pour le suivi des opérations.

## Structure du projet

- `backup-ad-atp.ps1` : Script principal de sauvegarde
- `config.json` : Fichier de configuration
- `modules/` : Modules complémentaires
- `logs/` : Fichiers journaux
- `README.md` : Documentation

## Bonnes pratiques

- Planifiez les sauvegardes en dehors des heures de production.
- Testez régulièrement la restauration à partir des sauvegardes.
- Sécurisez les accès aux fichiers de sauvegarde.

## Support

Pour toute question ou problème, veuillez ouvrir une issue sur le dépôt GitHub ou contacter l'administrateur du projet.

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus d'informations.


Vérifier les modules

```powershell
Import-Module ActiveDirectory, GroupPolicy
```


🎯 Utilisation
Lancement interactif

```powershell
.\Backup-AD-ATP.ps1
```

Utilisation programmatique

Sauvegarde des utilisateurs

```powershell
$BackupPath = "C:\ADBackup\$(Get-Date -Format 'yyyyMMdd')"
New-Item -Path $BackupPath -ItemType Directory -Force
$Result = Backup-ADUsers -Path $BackupPath
```

Restauration avec simulation

```powershell
Restore-ADUsers -FilePath "C:\ADBackup\Users_20231201_143022.csv" -DryRun
```

Restauration complète

```powershell
$BackupDir = "C:\ADBackup\20231201_143022_COMPLETE"
Start-CompleteRestore -BackupPath $BackupDir
```

Test d'intégrité

```powershell
Test-BackupIntegrity -BackupPath "C:\ADBackup"
```

📁 Structure des fichiers

```plaintext
backup-ad-atp/
├── Backup-AD-ATP.ps1              # Script principal
├── Tests/
│   ├── Backup-AD-ATP.Tests.ps1    # Tests Pester
│   └── Pester.ps1                 # Runner de tests
├── pester.config.ps1              # Configuration Pester
├── README.md                      # Ce fichier
├── LICENSE                        # Licence Apache 2.0
└── .gitignore                     # Exclusions Git
```

Structure des sauvegardes

```plaintext
C:\ADBackup/
├── 20231201_143022_COMPLETE/       # Sauvegarde complète
│   ├── Users_20231201_143022.csv
│   ├── Groups_20231201_143022.csv
│   ├── Computers_20231201_143022.csv
│   ├── OrganizationalUnits_20231201_143022.csv
│   └── GPO_20231201_143022/
├── Logs/                           # Fichiers de logs
└── Temp/                           # Fichiers temporaires
```

🧪 Tests
Exécuter les tests Pester

```powershell
# Tests complets
Invoke-Pester -Script "Tests/Backup-AD-ATP.Tests.ps1" -Output Detailed

# Via le runner
.\Tests\Pester.ps1
```

Fonctions testées

`Initialize-Environment` - Initialisation de l'environnement
`Test-ADAuthority` - Vérification des permissions
`Write-LogMessage` - Système de logging
`Backup-ADUsers` - Sauvegarde utilisateurs
`Backup-ADGroups` - Sauvegarde groupes
`Restore-ADUsers` - Restauration utilisateurs

📊 Menu interactif

Le script propose un menu interactif avec les options suivantes :

```plaintext
SAUVEGARDES
1. Sauvegarder Utilisateurs
2. Sauvegarder Groupes
3. Sauvegarder Ordinateurs
4. Sauvegarder Unités Organisationnelles
5. Sauvegarder GPO
6. Sauvegarde COMPLÈTE

RESTAURATIONS
7. Restaurer Utilisateurs
8. Restaurer Groupes
9. Restaurer Ordinateurs
10. Restaurer Unités Organisationnelles
11. Restaurer GPO
12. Restauration COMPLÈTE

TESTS ET MAINTENANCE
13. Test d'intégrité des sauvegardes
14. Simulation de restauration
15. Rotation des sauvegardes
```

🔧 Configuration avancée
Notifications email

```powershell
$Global:Config.SMTPServer = "smtp.gmail.com"
$Global:Config.SMTPPort = 587
$Global:Config.SMTPUseSSL = $true
$Global:Config.SMTPFrom = "backup@mondomaine.com"
$Global:Config.SMTPTo = @("admin1@mondomaine.com", "admin2@mondomaine.com")
```

Rétention des sauvegardes

```powershell
$Global:Config.RetentionDays = 90  # Conserver 90 jours
```

Format d'export

```powershell
$Global:Config.ADExportFormat = "CSV"  # ou "LDIF"
```

⚠️ Limitations

- Ne sauvegarde pas l'état système, DNS ou autres services
- Focalisé uniquement sur les objets AD et GPO
- Nécessite une connectivité réseau pour les notifications
- La création d'objets lors de la restauration est partiellement implémentée

🛡️ Sécurité

- Utilisez des comptes de service dédiés avec permissions minimales
- Chiffrez les fichiers de sauvegarde sensibles
- Sécurisez l'accès au dossier de sauvegarde
- Testez régulièrement les procédures de restauration

📈 Monitoring

Logs disponibles

- Fichiers logs : C:\ADBackup\Logs\ADBackup_YYYYMMDD.log
- EventLog Windows : Application > ADBackupScript
- Notifications email automatiques

Codes d'erreur

- EventID 1001 : Opérations générales
- Niveaux : Info, Warning, Error

🤝 Contribution

1. Fork le projet
2. Créez une branche feature (git checkout -b feature/nouvelle-fonctionnalite)
3. Commitez vos changements (git commit -m 'Ajout nouvelle fonctionnalité')
4. Pushez vers la branche (git push origin feature/nouvelle-fonctionnalite)
5. Ouvrez une Pull Request

Standards de code

- Suivez les conventions PowerShell
- Ajoutez des tests Pester pour les nouvelles fonctions
- Documentez avec comment-based help
- Testez sur multiple versions PowerShell

📝 Licence
Ce projet est sous licence Apache 2.0 - voir le fichier LICENSE pour plus de détails.

🙏 Remerciements

- Microsoft pour les modules ActiveDirectory et GroupPolicy
- Communauté PowerShell pour les meilleures pratiques
- Pester pour le framework de tests
