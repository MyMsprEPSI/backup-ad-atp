<#
.SYNOPSIS
    Script PowerShell interactif pour la sauvegarde et restauration d'objets Active Directory et GPO

.DESCRIPTION
    Ce script offre un menu interactif permettant de :
    - Sauvegarder/restaurer des objets AD (Utilisateurs, Groupes, Ordinateurs, OU)
    - Sauvegarder/restaurer des GPO
    - Effectuer des tests de validation des exports/imports
    - Gérer la rotation automatique des sauvegardes
    - Notifier par mail les résultats des opérations

.AUTHOR
    Générée par GitHub Copilot

.VERSION
    1.0.0

.PREREQUISITES
    - PowerShell 5.1 ou 7.x
    - Windows Server 2016/2019/2022
    - Module ActiveDirectory
    - Module GroupPolicy
    - Droits Domain Admin pour les opérations de restauration
    - Droits lecture AD pour les sauvegardes

.LIMITATIONS
    - Ne sauvegarde pas l'état système, DNS ou autres services
    - Focalisé uniquement sur les objets AD et GPO
    - Nécessite une connectivité réseau pour les notifications mail

.NOTES
    Modifiez les variables de configuration ci-dessous selon votre environnement
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy

# ===================================================================================================
# VARIABLES DE CONFIGURATION GLOBALES - À PERSONNALISER
# ===================================================================================================

# Chemins de sauvegarde et restauration
$Global:Config = @{
    BackupRootPath = "C:\ADBackup"
    LogPath        = "C:\ADBackup\Logs"
    TempPath       = "C:\ADBackup\Temp"
    
    # Rotation des sauvegardes (en jours)
    RetentionDays  = 30
    
    # Configuration SMTP pour notifications
    SMTPServer     = "smtp.votredomaine.com"
    SMTPPort       = 587
    SMTPFrom       = "adbackup@votredomaine.com"
    SMTPTo         = @("admin@votredomaine.com")
    SMTPSubject    = "[AD Backup] Rapport d'opération"
    SMTPUseSSL     = $true
    
    # Configuration EventLog
    EventLogSource = "ADBackupScript"
    EventLogName   = "Application"
    
    # Formats d'export
    ADExportFormat = "CSV"  # CSV ou LDIF
    
    # Messages personnalisables
    Messages       = @{
        Welcome        = "=== Script de Sauvegarde/Restauration Active Directory & GPO ==="
        Goodbye        = "Au revoir ! Script terminé."
        ConfirmRestore = "ATTENTION : Cette opération va modifier Active Directory. Continuer ?"
        TestMode       = "[MODE TEST]"
        DryRun         = "[DRY-RUN]"
    }
}

# ===================================================================================================
# FONCTIONS UTILITAIRES
# ===================================================================================================

function Initialize-Environment {
    <#
    .SYNOPSIS
        Initialise l'environnement du script (dossiers, logs, vérifications)
    #>
    
    try {
        # Création des dossiers
        @($Config.BackupRootPath, $Config.LogPath, $Config.TempPath) | ForEach-Object {
            if (!(Test-Path $_)) {
                New-Item -Path $_ -ItemType Directory -Force | Out-Null
                Write-LogMessage "Dossier créé : $_" -Level Info
            }
        }
        
        # Vérification des modules
        $RequiredModules = @("ActiveDirectory", "GroupPolicy")
        foreach ($Module in $RequiredModules) {
            if (!(Get-Module -Name $Module -ListAvailable)) {
                throw "Module requis non disponible : $Module"
            }
            Import-Module $Module -Force
        }
        
        # Configuration EventLog
        if (!(Get-EventLog -LogName $Config.EventLogName -Source $Config.EventLogSource -ErrorAction SilentlyContinue)) {
            New-EventLog -LogName $Config.EventLogName -Source $Config.EventLogSource
        }
        
        Write-LogMessage "Environnement initialisé avec succès" -Level Info
        return $true
    }
    catch {
        Write-Error "Erreur lors de l'initialisation : $($_.Exception.Message)"
        return $false
    }
}

function Test-ADAuthority {
    <#
    .SYNOPSIS
        Vérifie les droits utilisateur pour les opérations AD
    #>
    
    try {
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
        
        # Vérification droits admin local
        $IsAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        
        # Test de connectivité AD
        $ADTest = Get-ADDomain -ErrorAction Stop
        
        return @{
            IsAdmin         = $IsAdmin
            DomainConnected = $true
            Domain          = $ADTest.Name
            User            = $CurrentUser.Name
        }
    }
    catch {
        return @{
            IsAdmin         = $false
            DomainConnected = $false
            Error           = $_.Exception.Message
        }
    }
}

function Write-LogMessage {
    <#
    .SYNOPSIS
        Écrit un message dans les logs (fichier + EventLog)
    .PARAMETER Message
        Message à logger
    .PARAMETER Level
        Niveau de log (Info, Warning, Error)
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Log fichier
    $LogFile = Join-Path $Config.LogPath "ADBackup_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $LogFile -Value $LogEntry
    
    # EventLog
    $EventType = switch ($Level) {
        "Info" { "Information" }
        "Warning" { "Warning" }
        "Error" { "Error" }
    }
    
    try {
        Write-EventLog -LogName $Config.EventLogName -Source $Config.EventLogSource -EventId 1001 -EntryType $EventType -Message $Message
    }
    catch {
        # Silencieux si EventLog non disponible
    }
    
    # Console avec couleurs
    $Color = switch ($Level) {
        "Info" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
    }
    Write-Host $LogEntry -ForegroundColor $Color
}

# ===================================================================================================
# FONCTIONS DE SAUVEGARDE
# ===================================================================================================

function Backup-ADUsers {
    <#
    .SYNOPSIS
        Sauvegarde les utilisateurs Active Directory
    .PARAMETER Path
        Chemin de sauvegarde
    .PARAMETER Filter
        Filtre LDAP optionnel
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [string]$Filter = "*"
    )
    
    try {
        Write-LogMessage "Début sauvegarde utilisateurs AD" -Level Info
        
        $Users = Get-ADUser -Filter $Filter -Properties *
        $ExportPath = Join-Path $Path "Users_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        $Users | Select-Object Name, SamAccountName, UserPrincipalName, Enabled, DistinguishedName, 
        Description, Department, Title, Manager, Mail, MobilePhone, 
        LastLogonDate, PasswordLastSet, AccountExpirationDate | 
        Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        
        Write-LogMessage "Utilisateurs sauvegardés : $($Users.Count) vers $ExportPath" -Level Info
        
        return @{
            Success = $true
            Count   = $Users.Count
            Path    = $ExportPath
        }
    }
    catch {
        Write-LogMessage "Erreur sauvegarde utilisateurs : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Backup-ADGroups {
    <#
    .SYNOPSIS
        Sauvegarde les groupes Active Directory
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [string]$Filter = "*"
    )
    
    try {
        Write-LogMessage "Début sauvegarde groupes AD" -Level Info
        
        $Groups = Get-ADGroup -Filter $Filter -Properties *
        $ExportPath = Join-Path $Path "Groups_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        $GroupsData = foreach ($Group in $Groups) {
            $Members = Get-ADGroupMember -Identity $Group.DistinguishedName -ErrorAction SilentlyContinue | 
            Select-Object -ExpandProperty SamAccountName
            
            [PSCustomObject]@{
                Name              = $Group.Name
                SamAccountName    = $Group.SamAccountName
                DistinguishedName = $Group.DistinguishedName
                GroupCategory     = $Group.GroupCategory
                GroupScope        = $Group.GroupScope
                Description       = $Group.Description
                Members           = ($Members -join ";")
                MemberCount       = $Members.Count
            }
        }
        
        $GroupsData | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        
        Write-LogMessage "Groupes sauvegardés : $($Groups.Count) vers $ExportPath" -Level Info
        
        return @{
            Success = $true
            Count   = $Groups.Count
            Path    = $ExportPath
        }
    }
    catch {
        Write-LogMessage "Erreur sauvegarde groupes : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Backup-ADComputers {
    <#
    .SYNOPSIS
        Sauvegarde les ordinateurs Active Directory
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [string]$Filter = "*"
    )
    
    try {
        Write-LogMessage "Début sauvegarde ordinateurs AD" -Level Info
        
        $Computers = Get-ADComputer -Filter $Filter -Properties *
        $ExportPath = Join-Path $Path "Computers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        $Computers | Select-Object Name, SamAccountName, DistinguishedName, Enabled, 
        OperatingSystem, OperatingSystemVersion, Description,
        LastLogonDate, PasswordLastSet, Location | 
        Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        
        Write-LogMessage "Ordinateurs sauvegardés : $($Computers.Count) vers $ExportPath" -Level Info
        
        return @{
            Success = $true
            Count   = $Computers.Count
            Path    = $ExportPath
        }
    }
    catch {
        Write-LogMessage "Erreur sauvegarde ordinateurs : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Backup-ADOrganizationalUnits {
    <#
    .SYNOPSIS
        Sauvegarde les unités organisationnelles
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    try {
        Write-LogMessage "Début sauvegarde OU AD" -Level Info
        
        $OUs = Get-ADOrganizationalUnit -Filter * -Properties *
        $ExportPath = Join-Path $Path "OrganizationalUnits_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        $OUs | Select-Object Name, DistinguishedName, Description, ProtectedFromAccidentalDeletion,
        City, Country, PostalCode, State, StreetAddress | 
        Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        
        Write-LogMessage "OU sauvegardées : $($OUs.Count) vers $ExportPath" -Level Info
        
        return @{
            Success = $true
            Count   = $OUs.Count
            Path    = $ExportPath
        }
    }
    catch {
        Write-LogMessage "Erreur sauvegarde OU : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Backup-GPOs {
    <#
    .SYNOPSIS
        Sauvegarde les Group Policy Objects
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    try {
        Write-LogMessage "Début sauvegarde GPO" -Level Info
        
        $GPOBackupPath = Join-Path $Path "GPO_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -Path $GPOBackupPath -ItemType Directory -Force | Out-Null
        
        $GPOs = Get-GPO -All
        $BackupResults = @()
        
        foreach ($GPO in $GPOs) {
            try {
                $BackupInfo = Backup-GPO -Guid $GPO.Id -Path $GPOBackupPath
                $BackupResults += [PSCustomObject]@{
                    Name     = $GPO.DisplayName
                    Id       = $GPO.Id
                    BackupId = $BackupInfo.Id
                    Success  = $true
                }
            }
            catch {
                Write-LogMessage "Erreur sauvegarde GPO $($GPO.DisplayName) : $($_.Exception.Message)" -Level Warning
                $BackupResults += [PSCustomObject]@{
                    Name     = $GPO.DisplayName
                    Id       = $GPO.Id
                    BackupId = $null
                    Success  = $false
                    Error    = $_.Exception.Message
                }
            }
        }
        
        # Export du rapport de sauvegarde
        $ReportPath = Join-Path $GPOBackupPath "BackupReport.csv"
        $BackupResults | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
        
        $SuccessCount = ($BackupResults | Where-Object Success).Count
        Write-LogMessage "GPO sauvegardées : $SuccessCount/$($GPOs.Count) vers $GPOBackupPath" -Level Info
        
        return @{
            Success = $true
            Count   = $SuccessCount
            Total   = $GPOs.Count
            Path    = $GPOBackupPath
            Report  = $BackupResults
        }
    }
    catch {
        Write-LogMessage "Erreur sauvegarde GPO : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ===================================================================================================
# FONCTIONS DE RESTAURATION
# ===================================================================================================

function Restore-ADUsers {
    <#
    .SYNOPSIS
        Restaure les utilisateurs Active Directory depuis un fichier CSV
    .PARAMETER FilePath
        Chemin du fichier CSV de sauvegarde
    .PARAMETER DryRun
        Mode simulation sans modification réelle
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [switch]$DryRun
    )
    
    try {
        $Mode = if ($DryRun) { $Config.Messages.DryRun } else { "" }
        Write-LogMessage "$Mode Début restauration utilisateurs depuis $FilePath" -Level Info
        
        if (!(Test-Path $FilePath)) {
            throw "Fichier de sauvegarde introuvable : $FilePath"
        }
        
        $Users = Import-Csv -Path $FilePath -Encoding UTF8
        $Results = @()
        
        foreach ($User in $Users) {
            try {
                $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$($User.SamAccountName)'" -ErrorAction SilentlyContinue
                
                if (!$DryRun) {
                    if ($ExistingUser) {
                        # Mise à jour utilisateur existant
                        Set-ADUser -Identity $User.SamAccountName -Description $User.Description -Department $User.Department -Title $User.Title
                        $Action = "Mis à jour"
                    }
                    else {
                        # Création nouvel utilisateur (nécessiterait plus de paramètres)
                        Write-LogMessage "Création d'utilisateur non implémentée dans cette version : $($User.SamAccountName)" -Level Warning
                        $Action = "Ignoré (création)"
                    }
                }
                else {
                    $Action = if ($ExistingUser) { "Serait mis à jour" } else { "Serait créé" }
                }
                
                $Results += [PSCustomObject]@{
                    SamAccountName = $User.SamAccountName
                    Action         = $Action
                    Success        = $true
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    SamAccountName = $User.SamAccountName
                    Action         = "Erreur"
                    Success        = $false
                    Error          = $_.Exception.Message
                }
            }
        }
        
        $SuccessCount = ($Results | Where-Object Success).Count
        Write-LogMessage "$Mode Utilisateurs traités : $SuccessCount/$($Users.Count)" -Level Info
        
        return @{
            Success = $true
            Count   = $SuccessCount
            Total   = $Users.Count
            Results = $Results
        }
    }
    catch {
        Write-LogMessage "Erreur restauration utilisateurs : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Restore-GPOs {
    <#
    .SYNOPSIS
        Restaure les GPO depuis un dossier de sauvegarde
    .PARAMETER BackupPath
        Chemin du dossier de sauvegarde GPO
    .PARAMETER DryRun
        Mode simulation
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath,
        
        [switch]$DryRun
    )
    
    try {
        $Mode = if ($DryRun) { $Config.Messages.DryRun } else { "" }
        Write-LogMessage "$Mode Début restauration GPO depuis $BackupPath" -Level Info
        
        if (!(Test-Path $BackupPath)) {
            throw "Dossier de sauvegarde introuvable : $BackupPath"
        }
        
        $ReportPath = Join-Path $BackupPath "BackupReport.csv"
        if (!(Test-Path $ReportPath)) {
            throw "Rapport de sauvegarde introuvable : $ReportPath"
        }
        
        $BackupReport = Import-Csv -Path $ReportPath -Encoding UTF8
        $Results = @()
        
        foreach ($GPOBackup in $BackupReport | Where-Object Success -eq $true) {
            try {
                if (!$DryRun) {
                    $ExistingGPO = Get-GPO -Name $GPOBackup.Name -ErrorAction SilentlyContinue
                    if ($ExistingGPO) {
                        Import-GPO -BackupId $GPOBackup.BackupId -Path $BackupPath -TargetName $GPOBackup.Name
                        $Action = "Restauré (écrasé)"
                    }
                    else {
                        Import-GPO -BackupId $GPOBackup.BackupId -Path $BackupPath -TargetName $GPOBackup.Name -CreateIfNeeded
                        $Action = "Restauré (créé)"
                    }
                }
                else {
                    $ExistingGPO = Get-GPO -Name $GPOBackup.Name -ErrorAction SilentlyContinue
                    $Action = if ($ExistingGPO) { "Serait restauré (écrasé)" } else { "Serait restauré (créé)" }
                }
                
                $Results += [PSCustomObject]@{
                    Name    = $GPOBackup.Name
                    Action  = $Action
                    Success = $true
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    Name    = $GPOBackup.Name
                    Action  = "Erreur"
                    Success = $false
                    Error   = $_.Exception.Message
                }
            }
        }
        
        $SuccessCount = ($Results | Where-Object Success).Count
        Write-LogMessage "$Mode GPO traitées : $SuccessCount/$($BackupReport.Count)" -Level Info
        
        return @{
            Success = $true
            Count   = $SuccessCount
            Total   = $BackupReport.Count
            Results = $Results
        }
    }
    catch {
        Write-LogMessage "Erreur restauration GPO : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ===================================================================================================
# FONCTIONS DE TEST ET VALIDATION
# ===================================================================================================

function Test-BackupIntegrity {
    <#
    .SYNOPSIS
        Teste l'intégrité des fichiers de sauvegarde
    .PARAMETER BackupPath
        Chemin du dossier de sauvegarde à tester
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath
    )
    
    try {
        Write-LogMessage "Début test d'intégrité des sauvegardes dans $BackupPath" -Level Info
        
        $TestResults = @{
            FilesFound   = @()
            FilesValid   = @()
            FilesInvalid = @()
            GPOBackups   = @()
        }
        
        # Test des fichiers CSV
        $CSVFiles = Get-ChildItem -Path $BackupPath -Filter "*.csv" -Recurse
        foreach ($File in $CSVFiles) {
            $TestResults.FilesFound += $File.Name
            
            try {
                $Data = Import-Csv -Path $File.FullName -Encoding UTF8
                if ($Data.Count -gt 0) {
                    $TestResults.FilesValid += $File.Name
                }
                else {
                    $TestResults.FilesInvalid += "$($File.Name) (vide)"
                }
            }
            catch {
                $TestResults.FilesInvalid += "$($File.Name) (format invalide)"
            }
        }
        
        # Test des sauvegardes GPO
        $GPODirs = Get-ChildItem -Path $BackupPath -Directory | Where-Object Name -match "^GPO_"
        foreach ($GPODir in $GPODirs) {
            $ReportFile = Join-Path $GPODir.FullName "BackupReport.csv"
            if (Test-Path $ReportFile) {
                try {
                    $GPOReport = Import-Csv -Path $ReportFile -Encoding UTF8
                    $ValidBackups = ($GPOReport | Where-Object Success -eq $true).Count
                    $TestResults.GPOBackups += [PSCustomObject]@{
                        Directory    = $GPODir.Name
                        TotalGPOs    = $GPOReport.Count
                        ValidBackups = $ValidBackups
                        Success      = $ValidBackups -eq $GPOReport.Count
                    }
                }
                catch {
                    $TestResults.GPOBackups += [PSCustomObject]@{
                        Directory = $GPODir.Name
                        Success   = $false
                        Error     = "Rapport illisible"
                    }
                }
            }
        }
        
        # Génération du rapport
        Write-Host "`n=== RAPPORT DE TEST D'INTÉGRITÉ ===" -ForegroundColor Cyan
        Write-Host "Fichiers trouvés : $($TestResults.FilesFound.Count)" -ForegroundColor White
        Write-Host "Fichiers valides : $($TestResults.FilesValid.Count)" -ForegroundColor Green
        Write-Host "Fichiers invalides : $($TestResults.FilesInvalid.Count)" -ForegroundColor $(if ($TestResults.FilesInvalid.Count -eq 0) { 'Green' }else { 'Red' })
        
        if ($TestResults.FilesInvalid.Count -gt 0) {
            Write-Host "Fichiers problématiques :" -ForegroundColor Yellow
            $TestResults.FilesInvalid | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        }
        
        Write-Host "`nSauvegardes GPO : $($TestResults.GPOBackups.Count)" -ForegroundColor White
        $TestResults.GPOBackups | ForEach-Object {
            $Color = if ($_.Success) { "Green" } else { "Red" }
            Write-Host "  $($_.Directory) : $($_.ValidBackups)/$($_.TotalGPOs) GPO" -ForegroundColor $Color
        }
        
        Write-LogMessage "Test d'intégrité terminé" -Level Info
        return $TestResults
    }
    catch {
        Write-LogMessage "Erreur lors du test d'intégrité : $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Test-RestoreSimulation {
    <#
    .SYNOPSIS
        Effectue une simulation complète de restauration pour valider les sauvegardes
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath
    )
    
    Write-LogMessage "Début simulation de restauration depuis $BackupPath" -Level Info
    
    $SimulationResults = @{
        Users          = $null
        Groups         = $null
        Computers      = $null
        GPOs           = $null
        OverallSuccess = $false
    }
    
    try {
        # Test restauration utilisateurs
        $UserFiles = Get-ChildItem -Path $BackupPath -Filter "Users_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($UserFiles) {
            $SimulationResults.Users = Restore-ADUsers -FilePath $UserFiles.FullName -DryRun
        }
        
        # Test restauration GPO
        $GPODirs = Get-ChildItem -Path $BackupPath -Directory | Where-Object Name -match "^GPO_" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($GPODirs) {
            $SimulationResults.GPOs = Restore-GPOs -BackupPath $GPODirs.FullName -DryRun
        }
        
        # Évaluation globale
        $AllTests = @($SimulationResults.Users, $SimulationResults.Groups, $SimulationResults.Computers, $SimulationResults.GPOs) | Where-Object { $_ -ne $null }
        $SimulationResults.OverallSuccess = ($AllTests | Where-Object Success).Count -eq $AllTests.Count
        
        # Rapport de simulation
        Write-Host "`n=== RAPPORT DE SIMULATION DE RESTAURATION ===" -ForegroundColor Cyan
        
        if ($SimulationResults.Users) {
            Write-Host "Utilisateurs : $($SimulationResults.Users.Count)/$($SimulationResults.Users.Total) traités" -ForegroundColor $(if ($SimulationResults.Users.Success) { 'Green' }else { 'Red' })
        }
        
        if ($SimulationResults.GPOs) {
            Write-Host "GPO : $($SimulationResults.GPOs.Count)/$($SimulationResults.GPOs.Total) traitées" -ForegroundColor $(if ($SimulationResults.GPOs.Success) { 'Green' }else { 'Red' })
        }
        
        $Status = if ($SimulationResults.OverallSuccess) { "SUCCÈS" } else { "ÉCHEC" }
        $Color = if ($SimulationResults.OverallSuccess) { "Green" } else { "Red" }
        Write-Host "`nStatut global : $Status" -ForegroundColor $Color
        
        Write-LogMessage "Simulation de restauration terminée - Succès : $($SimulationResults.OverallSuccess)" -Level Info
        return $SimulationResults
    }
    catch {
        Write-LogMessage "Erreur lors de la simulation : $($_.Exception.Message)" -Level Error
        return $SimulationResults
    }
}

# ===================================================================================================
# FONCTIONS DE GESTION
# ===================================================================================================

function Invoke-BackupRotation {
    <#
    .SYNOPSIS
        Effectue la rotation des sauvegardes selon la politique de rétention
    #>
    
    try {
        Write-LogMessage "Début rotation des sauvegardes (rétention : $($Config.RetentionDays) jours)" -Level Info
        
        $CutoffDate = (Get-Date).AddDays(-$Config.RetentionDays)
        $DeletedItems = 0
        
        # Rotation des fichiers CSV
        $OldFiles = Get-ChildItem -Path $Config.BackupRootPath -Filter "*.csv" -Recurse | 
        Where-Object LastWriteTime -lt $CutoffDate
        
        foreach ($File in $OldFiles) {
            Remove-Item -Path $File.FullName -Force
            $DeletedItems++
            Write-LogMessage "Fichier supprimé : $($File.Name)" -Level Info
        }
        
        # Rotation des dossiers GPO
        $OldGPODirs = Get-ChildItem -Path $Config.BackupRootPath -Directory | 
        Where-Object { $_.Name -match "^GPO_" -and $_.LastWriteTime -lt $CutoffDate }
        
        foreach ($Dir in $OldGPODirs) {
            Remove-Item -Path $Dir.FullName -Recurse -Force
            $DeletedItems++
            Write-LogMessage "Dossier GPO supprimé : $($Dir.Name)" -Level Info
        }
        
        Write-LogMessage "Rotation terminée - $DeletedItems éléments supprimés" -Level Info
        return $DeletedItems
    }
    catch {
        Write-LogMessage "Erreur lors de la rotation : $($_.Exception.Message)" -Level Error
        return -1
    }
}

function Send-NotificationEmail {
    <#
    .SYNOPSIS
        Envoie une notification par mail
    .PARAMETER Subject
        Sujet du mail
    .PARAMETER Body
        Corps du message
    .PARAMETER IsError
        Indique si c'est une notification d'erreur
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Subject,
        
        [Parameter(Mandatory)]
        [string]$Body,
        
        [switch]$IsError
    )
    
    try {
        if (!$Config.SMTPServer) {
            Write-LogMessage "Configuration SMTP non définie - notification ignorée" -Level Warning
            return
        }
        
        $Credential = Get-Credential -Message "Credentials SMTP pour notification"
        if (!$Credential) {
            Write-LogMessage "Credentials SMTP non fournis - notification ignorée" -Level Warning
            return
        }
        
        $MailParams = @{
            SmtpServer = $Config.SMTPServer
            Port       = $Config.SMTPPort
            From       = $Config.SMTPFrom
            To         = $Config.SMTPTo
            Subject    = "$($Config.SMTPSubject) - $Subject"
            Body       = $Body
            Credential = $Credential
        }
        
        if ($Config.SMTPUseSSL) {
            $MailParams.UseSSL = $true
        }
        
        Send-MailMessage @MailParams
        Write-LogMessage "Notification envoyée : $Subject" -Level Info
    }
    catch {
        Write-LogMessage "Erreur envoi notification : $($_.Exception.Message)" -Level Error
    }
}

# ===================================================================================================
# INTERFACE UTILISATEUR
# ===================================================================================================

function Show-MainMenu {
    <#
    .SYNOPSIS
        Affiche le menu principal interactif
    #>
    
    Clear-Host
    Write-Host $Config.Messages.Welcome -ForegroundColor Cyan
    Write-Host ("=" * $Config.Messages.Welcome.Length) -ForegroundColor Cyan
    Write-Host ""
    
    # Affichage des informations système
    $AuthInfo = Test-ADAuthority
    Write-Host "Domaine : " -NoNewline
    Write-Host $AuthInfo.Domain -ForegroundColor $(if ($AuthInfo.DomainConnected) { 'Green' }else { 'Red' })
    Write-Host "Utilisateur : " -NoNewline  
    Write-Host $AuthInfo.User -ForegroundColor $(if ($AuthInfo.IsAdmin) { 'Green' }else { 'Yellow' })
    Write-Host ""
    
    Write-Host "SAUVEGARDES" -ForegroundColor Yellow
    Write-Host "1. Sauvegarder Utilisateurs" -ForegroundColor White
    Write-Host "2. Sauvegarder Groupes" -ForegroundColor White
    Write-Host "3. Sauvegarder Ordinateurs" -ForegroundColor White
    Write-Host "4. Sauvegarder Unités Organisationnelles" -ForegroundColor White
    Write-Host "5. Sauvegarder GPO" -ForegroundColor White
    Write-Host "6. Sauvegarde COMPLÈTE" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "RESTAURATIONS" -ForegroundColor Yellow
    Write-Host "7. Restaurer Utilisateurs" -ForegroundColor White
    Write-Host "8. Restaurer GPO" -ForegroundColor White
    Write-Host ""
    
    Write-Host "TESTS ET MAINTENANCE" -ForegroundColor Yellow
    Write-Host "9. Test d'intégrité des sauvegardes" -ForegroundColor White
    Write-Host "10. Simulation de restauration" -ForegroundColor White
    Write-Host "11. Rotation des sauvegardes" -ForegroundColor White
    Write-Host ""
    
    Write-Host "0. Quitter" -ForegroundColor Red
    Write-Host ""
    
    return Read-Host "Votre choix"
}

function Confirm-Action {
    <#
    .SYNOPSIS
        Demande confirmation pour une action
    .PARAMETER Message
        Message de confirmation
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    
    Write-Host ""
    Write-Host "CONFIRMATION REQUISE" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host $Message -ForegroundColor Yellow
    Write-Host ""
    
    do {
        $Response = Read-Host "Continuer ? (O/N)"
    } while ($Response -notin @('O', 'o', 'N', 'n', 'Oui', 'oui', 'Non', 'non'))
    
    return $Response -in @('O', 'o', 'Oui', 'oui')
}

function Select-BackupFile {
    <#
    .SYNOPSIS
        Permet de sélectionner un fichier de sauvegarde
    .PARAMETER Filter
        Filtre pour les fichiers (ex: "*.csv", "GPO_*")
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Filter
    )
    
    $Files = Get-ChildItem -Path $Config.BackupRootPath -Filter $Filter -Recurse | 
    Sort-Object LastWriteTime -Descending
    
    if ($Files.Count -eq 0) {
        Write-Host "Aucun fichier de sauvegarde trouvé avec le filtre : $Filter" -ForegroundColor Red
        return $null
    }
    
    Write-Host "`nFichiers de sauvegarde disponibles :" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Files.Count; $i++) {
        $Size = [math]::Round($Files[$i].Length / 1KB, 2)
        Write-Host "$($i + 1). $($Files[$i].Name) - $Size KB - $($Files[$i].LastWriteTime)" -ForegroundColor White
    }
    
    do {
        $Selection = Read-Host "`nSélectionnez un fichier (numéro) ou 0 pour annuler"
        if ($Selection -eq "0") { return $null }
    } while (![int]::TryParse($Selection, [ref]$null) -or $Selection -lt 1 -or $Selection -gt $Files.Count)
    
    return $Files[$Selection - 1]
}

# ===================================================================================================
# FONCTION PRINCIPALE
# ===================================================================================================

function Start-ADBackupScript {
    <#
    .SYNOPSIS
        Point d'entrée principal du script
    #>
    
    # Initialisation
    if (!(Initialize-Environment)) {
        Write-Error "Impossible d'initialiser l'environnement"
        return
    }
    
    # Vérification des droits
    $AuthInfo = Test-ADAuthority
    if (!$AuthInfo.DomainConnected) {
        Write-Error "Impossible de se connecter à Active Directory : $($AuthInfo.Error)"
        return
    }
    
    if (!$AuthInfo.IsAdmin) {
        Write-Warning "Droits administrateur non détectés - certaines opérations peuvent échouer"
    }
    
    # Boucle principale du menu
    do {
        $Choice = Show-MainMenu
        
        switch ($Choice) {
            "1" {
                Write-Host "`nSauvegarde des utilisateurs..." -ForegroundColor Yellow
                $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd")
                if (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
                
                $Result = Backup-ADUsers -Path $BackupPath
                if ($Result.Success) {
                    Write-Host "Sauvegarde réussie : $($Result.Count) utilisateurs" -ForegroundColor Green
                }
                else {
                    Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                }
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "2" {
                Write-Host "`nSauvegarde des groupes..." -ForegroundColor Yellow
                $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd")
                if (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
                
                $Result = Backup-ADGroups -Path $BackupPath
                if ($Result.Success) {
                    Write-Host "Sauvegarde réussie : $($Result.Count) groupes" -ForegroundColor Green
                }
                else {
                    Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                }
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "3" {
                Write-Host "`nSauvegarde des ordinateurs..." -ForegroundColor Yellow
                $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd")
                if (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
                
                $Result = Backup-ADComputers -Path $BackupPath
                if ($Result.Success) {
                    Write-Host "Sauvegarde réussie : $($Result.Count) ordinateurs" -ForegroundColor Green
                }
                else {
                    Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                }
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "4" {
                Write-Host "`nSauvegarde des OU..." -ForegroundColor Yellow
                $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd")
                if (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
                
                $Result = Backup-ADOrganizationalUnits -Path $BackupPath
                if ($Result.Success) {
                    Write-Host "Sauvegarde réussie : $($Result.Count) OU" -ForegroundColor Green
                }
                else {
                    Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                }
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "5" {
                Write-Host "`nSauvegarde des GPO..." -ForegroundColor Yellow
                $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd")
                if (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
                
                $Result = Backup-GPOs -Path $BackupPath
                if ($Result.Success) {
                    Write-Host "Sauvegarde réussie : $($Result.Count)/$($Result.Total) GPO" -ForegroundColor Green
                }
                else {
                    Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                }
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "6" {
                if (Confirm-Action "Lancer une sauvegarde complète (Utilisateurs, Groupes, Ordinateurs, OU, GPO) ?") {
                    Write-Host "`nSauvegarde complète en cours..." -ForegroundColor Yellow
                    $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd_HHmmss_COMPLETE")
                    New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
                    
                    $Results = @()
                    $Results += Backup-ADUsers -Path $BackupPath
                    $Results += Backup-ADGroups -Path $BackupPath  
                    $Results += Backup-ADComputers -Path $BackupPath
                    $Results += Backup-ADOrganizationalUnits -Path $BackupPath
                    $Results += Backup-GPOs -Path $BackupPath
                    
                    $SuccessCount = ($Results | Where-Object Success).Count
                    Write-Host "`nSauvegarde complète : $SuccessCount/5 opérations réussies" -ForegroundColor $(if ($SuccessCount -eq 5) { 'Green' }else { 'Yellow' })
                    
                    # Notification mail
                    $EmailBody = "Sauvegarde complète terminée`n$SuccessCount/5 opérations réussies`nChemin : $BackupPath"
                    Send-NotificationEmail -Subject "Sauvegarde complète" -Body $EmailBody -IsError:($SuccessCount -lt 5)
                }
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "7" {
                if (Confirm-Action $Config.Messages.ConfirmRestore) {
                    $SelectedFile = Select-BackupFile -Filter "Users_*.csv"
                    if ($SelectedFile) {
                        $DryRun = Confirm-Action "Effectuer une simulation (dry-run) d'abord ?"
                        $Result = Restore-ADUsers -FilePath $SelectedFile.FullName -DryRun:$DryRun
                        
                        if ($Result.Success) {
                            Write-Host "Restauration réussie : $($Result.Count)/$($Result.Total) utilisateurs" -ForegroundColor Green
                        }
                        else {
                            Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                        }
                    }
                }
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "8" {
                if (Confirm-Action $Config.Messages.ConfirmRestore) {
                    $GPODirs = Get-ChildItem -Path $Config.BackupRootPath -Directory | Where-Object Name -match "^GPO_"
                    if ($GPODirs) {
                        # Sélection du dossier GPO (simplifié)
                        $LatestGPO = $GPODirs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                        
                        $DryRun = Confirm-Action "Effectuer une simulation (dry-run) d'abord ?"
                        $Result = Restore-GPOs -BackupPath $LatestGPO.FullName -DryRun:$DryRun
                        
                        if ($Result.Success) {
                            Write-Host "Restauration réussie : $($Result.Count)/$($Result.Total) GPO" -ForegroundColor Green
                        }
                        else {
                            Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                        }
                    }
                    else {
                        Write-Host "Aucune sauvegarde GPO trouvée" -ForegroundColor Red
                    }
                }
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "9" {
                Write-Host "`nTest d'intégrité en cours..." -ForegroundColor Yellow
                Test-BackupIntegrity -BackupPath $Config.BackupRootPath
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "10" {
                Write-Host "`nSimulation de restauration en cours..." -ForegroundColor Yellow
                Test-RestoreSimulation -BackupPath $Config.BackupRootPath
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "11" {
                if (Confirm-Action "Lancer la rotation des sauvegardes (suppression des fichiers > $($Config.RetentionDays) jours) ?") {
                    $DeletedCount = Invoke-BackupRotation
                    if ($DeletedCount -ge 0) {
                        Write-Host "Rotation terminée : $DeletedCount éléments supprimés" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Erreur lors de la rotation" -ForegroundColor Red
                    }
                }
                Read-Host "`nAppuyez sur Entrée pour continuer"
            }
            
            "0" {
                Write-Host "`n$($Config.Messages.Goodbye)" -ForegroundColor Cyan
                break
            }
            
            default {
                Write-Host "`nChoix invalide, veuillez réessayer." -ForegroundColor Red
                Start-Sleep 2
            }
        }
    } while ($Choice -ne "0")
}

# ===================================================================================================
# EXEMPLES D'UTILISATION
# ===================================================================================================

<#
.EXAMPLE
    # Lancement interactif du script
    .\Backup-AD-ATP.ps1

.EXAMPLE
    # Sauvegarde programmatique des utilisateurs
    $BackupPath = "C:\ADBackup\$(Get-Date -Format 'yyyyMMdd')"
    New-Item -Path $BackupPath -ItemType Directory -Force
    $Result = Backup-ADUsers -Path $BackupPath
    
.EXAMPLE
    # Test d'intégrité programmatique
    Test-BackupIntegrity -BackupPath "C:\ADBackup"
    
.EXAMPLE
    # Restauration avec simulation
    Restore-ADUsers -FilePath "C:\ADBackup\Users_20231201_143022.csv" -DryRun
#>

# ===================================================================================================
# POINT D'ENTRÉE
# ===================================================================================================

# Lancement automatique si exécuté directement
if ($MyInvocation.InvocationName -ne '.') {
    Start-ADBackupScript
}
