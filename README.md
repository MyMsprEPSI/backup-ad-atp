# Backup-AD-ATP

Script PowerShell interactif pour la sauvegarde et restauration d'objets Active Directory et GPO.

## 📋 Description

Ce script offre une solution complète pour la gestion des sauvegardes Active Directory, incluant :

- **Sauvegarde/restauration** des objets AD (Utilisateurs, Groupes, Ordinateurs, OU)
- **Sauvegarde/restauration** des Group Policy Objects (GPO)
- **Tests de validation** des exports/imports
- **Gestion automatique** de la rotation des sauvegardes
- **Notifications par email** des résultats des opérations
- **Interface interactive** avec menu utilisateur

## 🚀 Fonctionnalités

### Sauvegardes
- ✅ Utilisateurs Active Directory
- ✅ Groupes et leurs membres
- ✅ Ordinateurs du domaine
- ✅ Unités Organisationnelles (OU)
- ✅ Group Policy Objects (GPO)
- ✅ Sauvegarde complète automatisée

### Restaurations
- ✅ Restauration sélective par type d'objet
- ✅ Restauration complète avec ordre optimisé
- ✅ Mode simulation (dry-run) pour validation
- ✅ Gestion des conflits d'objets existants

### Outils de maintenance
- ✅ Test d'intégrité des sauvegardes
- ✅ Rotation automatique des anciens fichiers
- ✅ Logs détaillés et EventLog Windows
- ✅ Notifications email automatiques

## 📋 Prérequis

### Système
- **PowerShell** 5.1 ou 7.x
- **Windows Server** 2016/2019/2022
- **Modules PowerShell** : ActiveDirectory, GroupPolicy

### Permissions
- **Domain Admin** pour les opérations de restauration
- **Lecture AD** minimum pour les sauvegardes
- **Droits administrateur local** recommandés

### Réseau
- Connectivité vers contrôleur de domaine
- Accès SMTP pour notifications (optionnel)

## 🔧 Installation

1. **Cloner le repository**
```powershell
git clone https://github.com/MyMsprEPSI/backup-ad-atp.git
cd backup-ad-atp
```

Configurer les variables Éditez le fichier Backup-AD-ATP.ps1 et personnalisez la section $Global:Config :
```powershell
$Global:Config = @{
    BackupRootPath = "C:\ADBackup"              # Chemin des sauvegardes
    LogPath        = "C:\ADBackup\Logs"         # Chemin des logs
    TempPath       = "C:\ADBackup\Temp"         # Dossier temporaire
    RetentionDays  = 30                         # Rétention en jours
    SMTPServer     = "smtp.votredomaine.com"    # Serveur SMTP
    SMTPFrom       = "adbackup@votredomaine.com" # Expéditeur
    SMTPTo         = @("admin@votredomaine.com") # Destinataires
    # ... autres paramètres
}
```
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

``Initialize-Environment`` - Initialisation de l'environnement
``Test-ADAuthority`` - Vérification des permissions
``Write-LogMessage`` - Système de logging
``Backup-ADUsers`` - Sauvegarde utilisateurs
``Backup-ADGroups`` - Sauvegarde groupes
``Restore-ADUsers`` - Restauration utilisateurs

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
````

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
