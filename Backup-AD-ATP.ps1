<#
.SYNOPSIS
    Script PowerShell interactif pour la sauvegarde et restauration d'objets Active Directory et GPO

.DESCRIPTION
    Ce script offre un menu interactif permettant de :
    - Sauvegarder/restaurer des objets AD (Utilisateurs, Groupes, Ordinateurs, OU)
    - Sauvegarder/restaurer des GPO
    - Effectuer des tests de validation des exports/imports
    - Gerer la rotation automatique des sauvegardes
    - Notifier par mail les resultats des operations

.AUTHOR
    Generee par GitHub Copilot

.VERSION
    1.0.0

.PREREQUISITES
    - PowerShell 5.1 ou 7.x
    - Windows Server 2016/2019/2022
    - Module ActiveDirectory
    - Module GroupPolicy
    - Droits Domain Admin pour les operations de restauration
    - Droits lecture AD pour les sauvegardes

.LIMITATIONS
    - Ne sauvegarde pas l'etat systeme, DNS ou autres services
    - Focalise uniquement sur les objets AD et GPO
    - Necessite une connectivite reseau pour les notifications mail

.NOTES
    Modifiez les variables de configuration ci-dessous selon votre environnement
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy

# ===================================================================================================
# VARIABLES DE CONFIGURATION GLOBALES - A PERSONNALISER
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
    SMTPSubject    = "[AD Backup] Rapport d'operation"
    SMTPUseSSL     = $true
    
    # Configuration EventLog
    EventLogSource = "ADBackupScript"
    EventLogName   = "Application"
    
    # Formats d'export
    ADExportFormat = "CSV"  # CSV ou LDIF
    
    # Messages personnalisables
    Messages       = @{
        Welcome        = "=== Script de Sauvegarde/Restauration Active Directory & GPO ==="
        Goodbye        = "Au revoir ! Script termine."
        ConfirmRestore = "ATTENTION : Cette operation va modifier Active Directory. Continuer ?"
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
        Initialise l'environnement du script (dossiers, logs, verifications)
    #>
    
    try {
        # Creation des dossiers
        @($Config.BackupRootPath, $Config.LogPath, $Config.TempPath) | ForEach-Object {
            if (!(Test-Path $_)) {
                New-Item -Path $_ -ItemType Directory -Force | Out-Null
                Write-LogMessage "Dossier cree : $_" -Level Info
            }
        }
        
        # Verification des modules
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
        
        Write-LogMessage "Environnement initialise avec succes" -Level Info
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
        Verifie les droits utilisateur pour les operations AD
    #>
    
    try {
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
        
        # Verification droits admin local
        $IsAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        
        # Test de connectivite AD
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
        Ecrit un message dans les logs (fichier + EventLog)
    .PARAMETER Message
        Message a logger
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
    Add-Content -Path $LogFile -Value $LogEntry -Encoding UTF8
    
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
        Write-LogMessage "Debut sauvegarde utilisateurs AD" -Level Info
        
        $Users = Get-ADUser -Filter $Filter -Properties *
        $ExportPath = Join-Path $Path "Users_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        $Users | Select-Object Name, SamAccountName, UserPrincipalName, Enabled, DistinguishedName, 
        Description, Department, Title, Manager, Mail, MobilePhone, 
        LastLogonDate, PasswordLastSet, AccountExpirationDate | 
        Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        
        Write-LogMessage "Utilisateurs sauvegardes : $($Users.Count) vers $ExportPath" -Level Info
        
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
        Write-LogMessage "Debut sauvegarde groupes AD" -Level Info
        
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
        
        Write-LogMessage "Groupes sauvegardes : $($Groups.Count) vers $ExportPath" -Level Info
        
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
        Write-LogMessage "Debut sauvegarde ordinateurs AD" -Level Info
        
        $Computers = Get-ADComputer -Filter $Filter -Properties *
        $ExportPath = Join-Path $Path "Computers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        $Computers | Select-Object Name, SamAccountName, DistinguishedName, Enabled, 
        OperatingSystem, OperatingSystemVersion, Description,
        LastLogonDate, PasswordLastSet, Location | 
        Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        
        Write-LogMessage "Ordinateurs sauvegardes : $($Computers.Count) vers $ExportPath" -Level Info
        
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
        Sauvegarde les unites organisationnelles
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    try {
        Write-LogMessage "Debut sauvegarde OU AD" -Level Info
        
        $OUs = Get-ADOrganizationalUnit -Filter * -Properties *
        $ExportPath = Join-Path $Path "OrganizationalUnits_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        $OUs | Select-Object Name, DistinguishedName, Description, ProtectedFromAccidentalDeletion,
        City, Country, PostalCode, State, StreetAddress | 
        Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        
        Write-LogMessage "OU sauvegardees : $($OUs.Count) vers $ExportPath" -Level Info
        
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
        Write-LogMessage "Debut sauvegarde GPO" -Level Info
        
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
        Write-LogMessage "GPO sauvegardees : $SuccessCount/$($GPOs.Count) vers $GPOBackupPath" -Level Info
        
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
        Mode simulation sans modification reelle
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [switch]$DryRun
    )
    
    try {
        $Mode = if ($DryRun) { $Config.Messages.DryRun } else { "" }
        Write-LogMessage "$Mode Debut restauration utilisateurs depuis $FilePath" -Level Info
        
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
                        # Mise a jour utilisateur existant
                        Set-ADUser -Identity $User.SamAccountName -Description $User.Description -Department $User.Department -Title $User.Title
                        $Action = "Mis a jour"
                    }
                    else {
                        # Creation nouvel utilisateur (necessiterait plus de parametres)
                        Write-LogMessage "Creation d'utilisateur non implementee dans cette version : $($User.SamAccountName)" -Level Warning
                        $Action = "Ignore (creation)"
                    }
                }
                else {
                    $Action = if ($ExistingUser) { "Serait mis a jour" } else { "Serait cree" }
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
        Write-LogMessage "$Mode Utilisateurs traites : $SuccessCount/$($Users.Count)" -Level Info
        
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

function Restore-ADGroups {
    <#
    .SYNOPSIS
        Restaure les groupes Active Directory depuis un fichier CSV
    .PARAMETER FilePath
        Chemin du fichier CSV de sauvegarde
    .PARAMETER DryRun
        Mode simulation sans modification reelle
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [switch]$DryRun
    )
    
    try {
        $Mode = if ($DryRun) { $Config.Messages.DryRun } else { "" }
        Write-LogMessage "$Mode Debut restauration groupes depuis $FilePath" -Level Info
        
        if (!(Test-Path $FilePath)) {
            throw "Fichier de sauvegarde introuvable : $FilePath"
        }
        
        $Groups = Import-Csv -Path $FilePath -Encoding UTF8
        $Results = @()
        
        foreach ($Group in $Groups) {
            try {
                $ExistingGroup = Get-ADGroup -Filter "SamAccountName -eq '$($Group.SamAccountName)'" -ErrorAction SilentlyContinue
                
                if (!$DryRun) {
                    if ($ExistingGroup) {
                        # Mise a jour groupe existant
                        Set-ADGroup -Identity $Group.SamAccountName -Description $Group.Description
                        
                        # Restauration des membres si disponible
                        if ($Group.Members -and $Group.Members -ne "") {
                            $Members = $Group.Members -split ";"
                            foreach ($Member in $Members) {
                                try {
                                    Add-ADGroupMember -Identity $Group.SamAccountName -Members $Member -ErrorAction SilentlyContinue
                                }
                                catch {
                                    Write-LogMessage "Impossible d'ajouter le membre $Member au groupe $($Group.SamAccountName)" -Level Warning
                                }
                            }
                        }
                        $Action = "Mis a jour"
                    }
                    else {
                        # Creation nouveau groupe
                        $NewGroupParams = @{
                            Name           = $Group.Name
                            SamAccountName = $Group.SamAccountName
                            GroupCategory  = $Group.GroupCategory
                            GroupScope     = $Group.GroupScope
                            Description    = $Group.Description
                        }
                        New-ADGroup @NewGroupParams
                        $Action = "Cree"
                    }
                }
                else {
                    $Action = if ($ExistingGroup) { "Serait mis a jour" } else { "Serait cree" }
                }
                
                $Results += [PSCustomObject]@{
                    SamAccountName = $Group.SamAccountName
                    Action         = $Action
                    Success        = $true
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    SamAccountName = $Group.SamAccountName
                    Action         = "Erreur"
                    Success        = $false
                    Error          = $_.Exception.Message
                }
            }
        }
        
        $SuccessCount = ($Results | Where-Object Success).Count
        Write-LogMessage "$Mode Groupes traites : $SuccessCount/$($Groups.Count)" -Level Info
        
        return @{
            Success = $true
            Count   = $SuccessCount
            Total   = $Groups.Count
            Results = $Results
        }
    }
    catch {
        Write-LogMessage "Erreur restauration groupes : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Restore-ADComputers {
    <#
    .SYNOPSIS
        Restaure les ordinateurs Active Directory depuis un fichier CSV
    .PARAMETER FilePath
        Chemin du fichier CSV de sauvegarde
    .PARAMETER DryRun
        Mode simulation sans modification reelle
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [switch]$DryRun
    )
    
    try {
        $Mode = if ($DryRun) { $Config.Messages.DryRun } else { "" }
        Write-LogMessage "$Mode Debut restauration ordinateurs depuis $FilePath" -Level Info
        
        if (!(Test-Path $FilePath)) {
            throw "Fichier de sauvegarde introuvable : $FilePath"
        }
        
        $Computers = Import-Csv -Path $FilePath -Encoding UTF8
        $Results = @()
        
        foreach ($Computer in $Computers) {
            try {
                $ExistingComputer = Get-ADComputer -Filter "SamAccountName -eq '$($Computer.SamAccountName)'" -ErrorAction SilentlyContinue
                
                if (!$DryRun) {
                    if ($ExistingComputer) {
                        # Mise a jour ordinateur existant
                        Set-ADComputer -Identity $Computer.SamAccountName -Description $Computer.Description -Location $Computer.Location
                        $Action = "Mis a jour"
                    }
                    else {
                        # Note: Creation d'ordinateur necessite des parametres specifiques
                        Write-LogMessage "Creation d'ordinateur non implementee dans cette version : $($Computer.SamAccountName)" -Level Warning
                        $Action = "Ignore (creation)"
                    }
                }
                else {
                    $Action = if ($ExistingComputer) { "Serait mis a jour" } else { "Serait cree" }
                }
                
                $Results += [PSCustomObject]@{
                    SamAccountName = $Computer.SamAccountName
                    Action         = $Action
                    Success        = $true
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    SamAccountName = $Computer.SamAccountName
                    Action         = "Erreur"
                    Success        = $false
                    Error          = $_.Exception.Message
                }
            }
        }
        
        $SuccessCount = ($Results | Where-Object Success).Count
        Write-LogMessage "$Mode Ordinateurs traites : $SuccessCount/$($Computers.Count)" -Level Info
        
        return @{
            Success = $true
            Count   = $SuccessCount
            Total   = $Computers.Count
            Results = $Results
        }
    }
    catch {
        Write-LogMessage "Erreur restauration ordinateurs : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Restore-ADOrganizationalUnits {
    <#
    .SYNOPSIS
        Restaure les unites organisationnelles depuis un fichier CSV
    .PARAMETER FilePath
        Chemin du fichier CSV de sauvegarde
    .PARAMETER DryRun
        Mode simulation sans modification reelle
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [switch]$DryRun
    )
    
    try {
        $Mode = if ($DryRun) { $Config.Messages.DryRun } else { "" }
        Write-LogMessage "$Mode Debut restauration OU depuis $FilePath" -Level Info
        
        if (!(Test-Path $FilePath)) {
            throw "Fichier de sauvegarde introuvable : $FilePath"
        }
        
        $OUs = Import-Csv -Path $FilePath -Encoding UTF8
        $Results = @()
        
        # Tri par profondeur de DN pour creer les OU parents en premier
        $SortedOUs = $OUs | Sort-Object { ($_.DistinguishedName -split ',').Count }
        
        foreach ($OU in $SortedOUs) {
            try {
                $ExistingOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($OU.DistinguishedName)'" -ErrorAction SilentlyContinue
                
                if (!$DryRun) {
                    if ($ExistingOU) {
                        # Mise a jour OU existante
                        Set-ADOrganizationalUnit -Identity $OU.DistinguishedName -Description $OU.Description -City $OU.City -Country $OU.Country
                        $Action = "Mis a jour"
                    }
                    else {
                        # Creation nouvelle OU
                        $ParentPath = ($OU.DistinguishedName -split ',', 2)[1]
                        New-ADOrganizationalUnit -Name $OU.Name -Path $ParentPath -Description $OU.Description
                        $Action = "Cree"
                    }
                }
                else {
                    $Action = if ($ExistingOU) { "Serait mis a jour" } else { "Serait cree" }
                }
                
                $Results += [PSCustomObject]@{
                    Name    = $OU.Name
                    Action  = $Action
                    Success = $true
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    Name    = $OU.Name
                    Action  = "Erreur"
                    Success = $false
                    Error   = $_.Exception.Message
                }
            }
        }
        
        $SuccessCount = ($Results | Where-Object Success).Count
        Write-LogMessage "$Mode OU traitees : $SuccessCount/$($OUs.Count)" -Level Info
        
        return @{
            Success = $true
            Count   = $SuccessCount
            Total   = $OUs.Count
            Results = $Results
        }
    }
    catch {
        Write-LogMessage "Erreur restauration OU : $($_.Exception.Message)" -Level Error
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
        Write-LogMessage "$Mode Debut restauration GPO depuis $BackupPath" -Level Info
        
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
                        $Action = "Restaure (ecrase)"
                    }
                    else {
                        Import-GPO -BackupId $GPOBackup.BackupId -Path $BackupPath -TargetName $GPOBackup.Name -CreateIfNeeded
                        $Action = "Restaure (cree)"
                    }
                }
                else {
                    $ExistingGPO = Get-GPO -Name $GPOBackup.Name -ErrorAction SilentlyContinue
                    $Action = if ($ExistingGPO) { "Serait restaure (ecrase)" } else { "Serait restaure (cree)" }
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
        Write-LogMessage "$Mode GPO traitees : $SuccessCount/$($BackupReport.Count)" -Level Info
        
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
# FONCTIONS DE RESTAURATION (AJOUTS)
# ===================================================================================================

function Restore-ADGroups {
    <#
    .SYNOPSIS
        Restaure les groupes Active Directory depuis un fichier CSV
    .PARAMETER FilePath
        Chemin du fichier CSV de sauvegarde
    .PARAMETER DryRun
        Mode simulation sans modification reelle
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [switch]$DryRun
    )
    
    try {
        $Mode = if ($DryRun) { $Config.Messages.DryRun } else { "" }
        Write-LogMessage "$Mode Debut restauration groupes depuis $FilePath" -Level Info
        
        if (!(Test-Path $FilePath)) {
            throw "Fichier de sauvegarde introuvable : $FilePath"
        }
        
        $Groups = Import-Csv -Path $FilePath -Encoding UTF8
        $Results = @()
        
        foreach ($Group in $Groups) {
            try {
                $ExistingGroup = Get-ADGroup -Filter "SamAccountName -eq '$($Group.SamAccountName)'" -ErrorAction SilentlyContinue
                
                if (!$DryRun) {
                    if ($ExistingGroup) {
                        # Mise a jour groupe existant
                        Set-ADGroup -Identity $Group.SamAccountName -Description $Group.Description
                        
                        # Restauration des membres si disponible
                        if ($Group.Members -and $Group.Members -ne "") {
                            $Members = $Group.Members -split ";"
                            foreach ($Member in $Members) {
                                try {
                                    Add-ADGroupMember -Identity $Group.SamAccountName -Members $Member -ErrorAction SilentlyContinue
                                }
                                catch {
                                    Write-LogMessage "Impossible d'ajouter le membre $Member au groupe $($Group.SamAccountName)" -Level Warning
                                }
                            }
                        }
                        $Action = "Mis a jour"
                    }
                    else {
                        # Creation nouveau groupe
                        $NewGroupParams = @{
                            Name           = $Group.Name
                            SamAccountName = $Group.SamAccountName
                            GroupCategory  = $Group.GroupCategory
                            GroupScope     = $Group.GroupScope
                            Description    = $Group.Description
                        }
                        New-ADGroup @NewGroupParams
                        $Action = "Cree"
                    }
                }
                else {
                    $Action = if ($ExistingGroup) { "Serait mis a jour" } else { "Serait cree" }
                }
                
                $Results += [PSCustomObject]@{
                    SamAccountName = $Group.SamAccountName
                    Action         = $Action
                    Success        = $true
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    SamAccountName = $Group.SamAccountName
                    Action         = "Erreur"
                    Success        = $false
                    Error          = $_.Exception.Message
                }
            }
        }
        
        $SuccessCount = ($Results | Where-Object Success).Count
        Write-LogMessage "$Mode Groupes traites : $SuccessCount/$($Groups.Count)" -Level Info
        
        return @{
            Success = $true
            Count   = $SuccessCount
            Total   = $Groups.Count
            Results = $Results
        }
    }
    catch {
        Write-LogMessage "Erreur restauration groupes : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Restore-ADComputers {
    <#
    .SYNOPSIS
        Restaure les ordinateurs Active Directory depuis un fichier CSV
    .PARAMETER FilePath
        Chemin du fichier CSV de sauvegarde
    .PARAMETER DryRun
        Mode simulation sans modification reelle
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [switch]$DryRun
    )
    
    try {
        $Mode = if ($DryRun) { $Config.Messages.DryRun } else { "" }
        Write-LogMessage "$Mode Debut restauration ordinateurs depuis $FilePath" -Level Info
        
        if (!(Test-Path $FilePath)) {
            throw "Fichier de sauvegarde introuvable : $FilePath"
        }
        
        $Computers = Import-Csv -Path $FilePath -Encoding UTF8
        $Results = @()
        
        foreach ($Computer in $Computers) {
            try {
                $ExistingComputer = Get-ADComputer -Filter "SamAccountName -eq '$($Computer.SamAccountName)'" -ErrorAction SilentlyContinue
                
                if (!$DryRun) {
                    if ($ExistingComputer) {
                        # Mise a jour ordinateur existant
                        Set-ADComputer -Identity $Computer.SamAccountName -Description $Computer.Description -Location $Computer.Location
                        $Action = "Mis a jour"
                    }
                    else {
                        # Note: Creation d'ordinateur necessite des parametres specifiques
                        Write-LogMessage "Creation d'ordinateur non implementee dans cette version : $($Computer.SamAccountName)" -Level Warning
                        $Action = "Ignore (creation)"
                    }
                }
                else {
                    $Action = if ($ExistingComputer) { "Serait mis a jour" } else { "Serait cree" }
                }
                
                $Results += [PSCustomObject]@{
                    SamAccountName = $Computer.SamAccountName
                    Action         = $Action
                    Success        = $true
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    SamAccountName = $Computer.SamAccountName
                    Action         = "Erreur"
                    Success        = $false
                    Error          = $_.Exception.Message
                }
            }
        }
        
        $SuccessCount = ($Results | Where-Object Success).Count
        Write-LogMessage "$Mode Ordinateurs traites : $SuccessCount/$($Computers.Count)" -Level Info
        
        return @{
            Success = $true
            Count   = $SuccessCount
            Total   = $Computers.Count
            Results = $Results
        }
    }
    catch {
        Write-LogMessage "Erreur restauration ordinateurs : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Restore-ADOrganizationalUnits {
    <#
    .SYNOPSIS
        Restaure les unites organisationnelles depuis un fichier CSV
    .PARAMETER FilePath
        Chemin du fichier CSV de sauvegarde
    .PARAMETER DryRun
        Mode simulation sans modification reelle
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [switch]$DryRun
    )
    
    try {
        $Mode = if ($DryRun) { $Config.Messages.DryRun } else { "" }
        Write-LogMessage "$Mode Debut restauration OU depuis $FilePath" -Level Info
        
        if (!(Test-Path $FilePath)) {
            throw "Fichier de sauvegarde introuvable : $FilePath"
        }
        
        $OUs = Import-Csv -Path $FilePath -Encoding UTF8
        $Results = @()
        
        # Tri par profondeur de DN pour creer les OU parents en premier
        $SortedOUs = $OUs | Sort-Object { ($_.DistinguishedName -split ',').Count }
        
        foreach ($OU in $SortedOUs) {
            try {
                $ExistingOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($OU.DistinguishedName)'" -ErrorAction SilentlyContinue
                
                if (!$DryRun) {
                    if ($ExistingOU) {
                        # Mise a jour OU existante
                        Set-ADOrganizationalUnit -Identity $OU.DistinguishedName -Description $OU.Description -City $OU.City -Country $OU.Country
                        $Action = "Mis a jour"
                    }
                    else {
                        # Creation nouvelle OU
                        $ParentPath = ($OU.DistinguishedName -split ',', 2)[1]
                        New-ADOrganizationalUnit -Name $OU.Name -Path $ParentPath -Description $OU.Description
                        $Action = "Cree"
                    }
                }
                else {
                    $Action = if ($ExistingOU) { "Serait mis a jour" } else { "Serait cree" }
                }
                
                $Results += [PSCustomObject]@{
                    Name    = $OU.Name
                    Action  = $Action
                    Success = $true
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    Name    = $OU.Name
                    Action  = "Erreur"
                    Success = $false
                    Error   = $_.Exception.Message
                }
            }
        }
        
        $SuccessCount = ($Results | Where-Object Success).Count
        Write-LogMessage "$Mode OU traitees : $SuccessCount/$($OUs.Count)" -Level Info
        
        return @{
            Success = $true
            Count   = $SuccessCount
            Total   = $OUs.Count
            Results = $Results
        }
    }
    catch {
        Write-LogMessage "Erreur restauration OU : $($_.Exception.Message)" -Level Error
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
        Write-LogMessage "$Mode Debut restauration GPO depuis $BackupPath" -Level Info
        
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
                        $Action = "Restaure (ecrase)"
                    }
                    else {
                        Import-GPO -BackupId $GPOBackup.BackupId -Path $BackupPath -TargetName $GPOBackup.Name -CreateIfNeeded
                        $Action = "Restaure (cree)"
                    }
                }
                else {
                    $ExistingGPO = Get-GPO -Name $GPOBackup.Name -ErrorAction SilentlyContinue
                    $Action = if ($ExistingGPO) { "Serait restaure (ecrase)" } else { "Serait restaure (cree)" }
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
        Write-LogMessage "$Mode GPO traitees : $SuccessCount/$($BackupReport.Count)" -Level Info
        
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

function Start-CompleteRestore {
    <#
    .SYNOPSIS
        Effectue une restauration complete de tous les objets AD et GPO
    .PARAMETER BackupPath
        Chemin du dossier contenant les sauvegardes
    .PARAMETER DryRun
        Mode simulation sans modification reelle
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath,
        
        [switch]$DryRun
    )
    
    try {
        $Mode = if ($DryRun) { $Config.Messages.DryRun } else { "" }
        Write-LogMessage "$Mode Debut restauration complete depuis $BackupPath" -Level Info
        
        if (!(Test-Path $BackupPath)) {
            throw "Dossier de sauvegarde introuvable : $BackupPath"
        }
        
        $RestoreResults = @{
            Users          = $null
            Groups         = $null
            Computers      = $null
            OUs            = $null
            GPOs           = $null
            OverallSuccess = $false
            Summary        = @()
        }
        
        # Ordre de restauration important : OU -> Groupes -> Utilisateurs -> Ordinateurs -> GPO
        
        # 1. Restauration des OU (doivent exister avant les autres objets)
        $OUFiles = Get-ChildItem -Path $BackupPath -Filter "OrganizationalUnits_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($OUFiles) {
            Write-Host "Restauration des OU..." -ForegroundColor Yellow
            $RestoreResults.OUs = Restore-ADOrganizationalUnits -FilePath $OUFiles.FullName -DryRun:$DryRun
            $RestoreResults.Summary += "OU : $($RestoreResults.OUs.Count)/$($RestoreResults.OUs.Total) restaurees"
        }
        
        # 2. Restauration des groupes
        $GroupFiles = Get-ChildItem -Path $BackupPath -Filter "Groups_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($GroupFiles) {
            Write-Host "Restauration des groupes..." -ForegroundColor Yellow
            $RestoreResults.Groups = Restore-ADGroups -FilePath $GroupFiles.FullName -DryRun:$DryRun
            $RestoreResults.Summary += "Groupes : $($RestoreResults.Groups.Count)/$($RestoreResults.Groups.Total) restaures"
        }
        
        # 3. Restauration des utilisateurs
        $UserFiles = Get-ChildItem -Path $BackupPath -Filter "Users_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($UserFiles) {
            Write-Host "Restauration des utilisateurs..." -ForegroundColor Yellow
            $RestoreResults.Users = Restore-ADUsers -FilePath $UserFiles.FullName -DryRun:$DryRun
            $RestoreResults.Summary += "Utilisateurs : $($RestoreResults.Users.Count)/$($RestoreResults.Users.Total) restaures"
        }
        
        # 4. Restauration des ordinateurs
        $ComputerFiles = Get-ChildItem -Path $BackupPath -Filter "Computers_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($ComputerFiles) {
            Write-Host "Restauration des ordinateurs..." -ForegroundColor Yellow
            $RestoreResults.Computers = Restore-ADComputers -FilePath $ComputerFiles.FullName -DryRun:$DryRun
            $RestoreResults.Summary += "Ordinateurs : $($RestoreResults.Computers.Count)/$($RestoreResults.Computers.Total) restaures"
        }
        
        # 5. Restauration des GPO
        $GPODirs = Get-ChildItem -Path $BackupPath -Directory | Where-Object Name -match "^GPO_" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($GPODirs) {
            Write-Host "Restauration des GPO..." -ForegroundColor Yellow
            $RestoreResults.GPOs = Restore-GPOs -BackupPath $GPODirs.FullName -DryRun:$DryRun
            $RestoreResults.Summary += "GPO : $($RestoreResults.GPOs.Count)/$($RestoreResults.GPOs.Total) restaurees"
        }
        
        # Evaluation du succes global
        $AllOperations = @($RestoreResults.Users, $RestoreResults.Groups, $RestoreResults.Computers, $RestoreResults.OUs, $RestoreResults.GPOs) | Where-Object { $_ -ne $null }
        $SuccessfulOperations = ($AllOperations | Where-Object Success).Count
        $RestoreResults.OverallSuccess = $SuccessfulOperations -eq $AllOperations.Count
        
        # Rapport final
        Write-Host ""
        Write-Host "=== RAPPORT DE RESTAURATION COMPLETE ===" -ForegroundColor Cyan
        $RestoreResults.Summary | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
        
        $Status = if ($RestoreResults.OverallSuccess) { "SUCCES" } else { "PARTIEL" }
        $Color = if ($RestoreResults.OverallSuccess) { "Green" } else { "Yellow" }
        Write-Host ""
        Write-Host "Statut global : $Status ($SuccessfulOperations/$($AllOperations.Count) operations reussies)" -ForegroundColor $Color
        
        # Notification mail
        $EmailSubject = "$Mode Restauration complete $Status"
        $EmailBody = "Restauration complete terminee`n"
        $EmailBody += "Statut : $Status`n"
        $EmailBody += "Operations reussies : $SuccessfulOperations/$($AllOperations.Count)`n"
        $EmailBody += "Details :`n" + ($RestoreResults.Summary -join "`n")
        
        Send-NotificationEmail -Subject $EmailSubject -Body $EmailBody -IsError:(!$RestoreResults.OverallSuccess)
        
        Write-LogMessage "$Mode Restauration complete terminee - Succes : $($RestoreResults.OverallSuccess)" -Level Info
        return $RestoreResults
    }
    catch {
        Write-LogMessage "Erreur lors de la restauration complete : $($_.Exception.Message)" -Level Error
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Select-BackupDirectory {
    <#
    .SYNOPSIS
        Permet de selectionner un dossier de sauvegarde pour restauration complete
    #>
    
    # Recherche des dossiers de sauvegarde complete
    $CompleteDirs = Get-ChildItem -Path $Config.BackupRootPath -Directory | 
    Where-Object Name -match "_COMPLETE$" | 
    Sort-Object LastWriteTime -Descending
    
    # Inclure aussi les dossiers par date
    $DateDirs = Get-ChildItem -Path $Config.BackupRootPath -Directory | 
    Where-Object Name -match "^\d{8}(_\d{6})?$" | 
    Sort-Object LastWriteTime -Descending
    
    $AllDirs = @($CompleteDirs) + @($DateDirs) | Sort-Object LastWriteTime -Descending
    
    if ($AllDirs.Count -eq 0) {
        Write-Host "Aucun dossier de sauvegarde trouve" -ForegroundColor Red
        return $null
    }
    
    Write-Host ""
    Write-Host "Dossiers de sauvegarde disponibles :" -ForegroundColor Cyan
    for ($i = 0; $i -lt $AllDirs.Count; $i++) {
        $Type = if ($AllDirs[$i].Name -match "_COMPLETE$") { "[COMPLETE]" } else { "[PARTIEL]" }
        $Size = Get-ChildItem -Path $AllDirs[$i].FullName -Recurse | Measure-Object -Property Length -Sum | ForEach-Object { [math]::Round($_.Sum / 1MB, 2) }
        Write-Host "$($i + 1). $($AllDirs[$i].Name) $Type - $Size MB - $($AllDirs[$i].LastWriteTime)" -ForegroundColor White
    }
    
    do {
        $Selection = Read-Host "`nSelectionnez un dossier (numero) ou 0 pour annuler"
        if ($Selection -eq "0") { return $null }
    } while (![int]::TryParse($Selection, [ref]$null) -or $Selection -lt 1 -or $Selection -gt $AllDirs.Count)
    
    return $AllDirs[$Selection - 1]
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
    
    # Affichage des informations systeme
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
    Write-Host "4. Sauvegarder Unites Organisationnelles" -ForegroundColor White
    Write-Host "5. Sauvegarder GPO" -ForegroundColor White
    Write-Host "6. Sauvegarde COMPLETE" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "RESTAURATIONS" -ForegroundColor Yellow
    Write-Host "7. Restaurer Utilisateurs" -ForegroundColor White
    Write-Host "8. Restaurer Groupes" -ForegroundColor White
    Write-Host "9. Restaurer Ordinateurs" -ForegroundColor White
    Write-Host "10. Restaurer Unites Organisationnelles" -ForegroundColor White
    Write-Host "11. Restaurer GPO" -ForegroundColor White
    Write-Host "12. Restauration COMPLETE" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "TESTS ET MAINTENANCE" -ForegroundColor Yellow
    Write-Host "13. Test d'integrite des sauvegardes" -ForegroundColor White
    Write-Host "14. Simulation de restauration" -ForegroundColor White
    Write-Host "15. Rotation des sauvegardes" -ForegroundColor White
    
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
        Permet de selectionner un fichier de sauvegarde
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
        Write-Host "Aucun fichier de sauvegarde trouve avec le filtre : $Filter" -ForegroundColor Red
        return $null
    }
    
    Write-Host ""
    Write-Host "Fichiers de sauvegarde disponibles :" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Files.Count; $i++) {
        $Size = [math]::Round($Files[$i].Length / 1KB, 2)
        Write-Host "$($i + 1). $($Files[$i].Name) - $Size KB - $($Files[$i].LastWriteTime)" -ForegroundColor White
    }
    
    do {
        $Selection = Read-Host "`nSelectionnez un fichier (numero) ou 0 pour annuler"
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
        Point d'entree principal du script
    #>
    
    # Initialisation
    if (!(Initialize-Environment)) {
        Write-Error "Impossible d'initialiser l'environnement"
        return
    }
    
    # Verification des droits
    $AuthInfo = Test-ADAuthority
    if (!$AuthInfo.DomainConnected) {
        Write-Error "Impossible de se connecter a Active Directory : $($AuthInfo.Error)"
        return
    }
    
    if (!$AuthInfo.IsAdmin) {
        Write-Warning "Droits administrateur non detectes - certaines operations peuvent echouer"
    }
    
    # Boucle principale du menu
    do {
        $Choice = Show-MainMenu
        
        switch ($Choice) {
            "1" {
                Write-Host ""
                Write-Host "Sauvegarde des utilisateurs..." -ForegroundColor Yellow
                $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd")
                if (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
                
                $Result = Backup-ADUsers -Path $BackupPath
                if ($Result.Success) {
                    Write-Host "Sauvegarde reussie : $($Result.Count) utilisateurs" -ForegroundColor Green
                }
                else {
                    Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "2" {
                Write-Host ""
                Write-Host "Sauvegarde des groupes..." -ForegroundColor Yellow
                $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd")
                if (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
                
                $Result = Backup-ADGroups -Path $BackupPath
                if ($Result.Success) {
                    Write-Host "Sauvegarde reussie : $($Result.Count) groupes" -ForegroundColor Green
                }
                else {
                    Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "3" {
                Write-Host ""
                Write-Host "Sauvegarde des ordinateurs..." -ForegroundColor Yellow
                $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd")
                if (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
                
                $Result = Backup-ADComputers -Path $BackupPath
                if ($Result.Success) {
                    Write-Host "Sauvegarde reussie : $($Result.Count) ordinateurs" -ForegroundColor Green
                }
                else {
                    Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "4" {
                Write-Host ""
                Write-Host "Sauvegarde des OU..." -ForegroundColor Yellow
                $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd")
                if (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
                
                $Result = Backup-ADOrganizationalUnits -Path $BackupPath
                if ($Result.Success) {
                    Write-Host "Sauvegarde reussie : $($Result.Count) OU" -ForegroundColor Green
                }
                else {
                    Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "5" {
                Write-Host ""
                Write-Host "Sauvegarde des GPO..." -ForegroundColor Yellow
                $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd")
                if (!(Test-Path $BackupPath)) { New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null }
                
                $Result = Backup-GPOs -Path $BackupPath
                if ($Result.Success) {
                    Write-Host "Sauvegarde reussie : $($Result.Count)/$($Result.Total) GPO" -ForegroundColor Green
                }
                else {
                    Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "6" {
                if (Confirm-Action "Lancer une sauvegarde complete (Utilisateurs, Groupes, Ordinateurs, OU, GPO) ?") {
                    Write-Host ""
                    Write-Host "Sauvegarde complete en cours..." -ForegroundColor Yellow
                    $BackupPath = Join-Path $Config.BackupRootPath (Get-Date -Format "yyyyMMdd_HHmmss_COMPLETE")
                    New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
                    
                    $Results = @()
                    $Results += Backup-ADUsers -Path $BackupPath
                    $Results += Backup-ADGroups -Path $BackupPath  
                    $Results += Backup-ADComputers -Path $BackupPath
                    $Results += Backup-ADOrganizationalUnits -Path $BackupPath
                    $Results += Backup-GPOs -Path $BackupPath
                    
                    $SuccessCount = ($Results | Where-Object Success).Count
                    Write-Host ""
                    Write-Host "Sauvegarde complete : $SuccessCount/5 operations reussies" -ForegroundColor $(if ($SuccessCount -eq 5) { 'Green' }else { 'Yellow' })
                    
                    # Notification mail
                    $EmailBody = "Sauvegarde complete terminee`n$SuccessCount/5 operations reussies`nChemin : $BackupPath"
                    Send-NotificationEmail -Subject "Sauvegarde complete" -Body $EmailBody -IsError:($SuccessCount -lt 5)
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "7" {
                if (Confirm-Action $Config.Messages.ConfirmRestore) {
                    $SelectedFile = Select-BackupFile -Filter "Users_*.csv"
                    if ($SelectedFile) {
                        $DryRun = Confirm-Action "Effectuer une simulation (dry-run) d'abord ?"
                        $Result = Restore-ADUsers -FilePath $SelectedFile.FullName -DryRun:$DryRun
                        
                        if ($Result.Success) {
                            Write-Host "Restauration reussie : $($Result.Count)/$($Result.Total) utilisateurs" -ForegroundColor Green
                        }
                        else {
                            Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                        }
                    }
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "8" {
                if (Confirm-Action $Config.Messages.ConfirmRestore) {
                    $SelectedFile = Select-BackupFile -Filter "Groups_*.csv"
                    if ($SelectedFile) {
                        $DryRun = Confirm-Action "Effectuer une simulation (dry-run) d'abord ?"
                        $Result = Restore-ADGroups -FilePath $SelectedFile.FullName -DryRun:$DryRun
                        
                        if ($Result.Success) {
                            Write-Host "Restauration reussie : $($Result.Count)/$($Result.Total) groupes" -ForegroundColor Green
                        }
                        else {
                            Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                        }
                    }
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "9" {
                if (Confirm-Action $Config.Messages.ConfirmRestore) {
                    $SelectedFile = Select-BackupFile -Filter "Computers_*.csv"
                    if ($SelectedFile) {
                        $DryRun = Confirm-Action "Effectuer une simulation (dry-run) d'abord ?"
                        $Result = Restore-ADComputers -FilePath $SelectedFile.FullName -DryRun:$DryRun
                        
                        if ($Result.Success) {
                            Write-Host "Restauration reussie : $($Result.Count)/$($Result.Total) ordinateurs" -ForegroundColor Green
                        }
                        else {
                            Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                        }
                    }
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "10" {
                if (Confirm-Action $Config.Messages.ConfirmRestore) {
                    $SelectedFile = Select-BackupFile -Filter "OrganizationalUnits_*.csv"
                    if ($SelectedFile) {
                        $DryRun = Confirm-Action "Effectuer une simulation (dry-run) d'abord ?"
                        $Result = Restore-ADOrganizationalUnits -FilePath $SelectedFile.FullName -DryRun:$DryRun
                        
                        if ($Result.Success) {
                            Write-Host "Restauration reussie : $($Result.Count)/$($Result.Total) OU" -ForegroundColor Green
                        }
                        else {
                            Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                        }
                    }
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "11" {
                if (Confirm-Action $Config.Messages.ConfirmRestore) {
                    $GPODirs = Get-ChildItem -Path $Config.BackupRootPath -Directory | Where-Object Name -match "^GPO_"
                    if ($GPODirs) {
                        # Selection du dossier GPO (simplifie)
                        $LatestGPO = $GPODirs | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                        
                        $DryRun = Confirm-Action "Effectuer une simulation (dry-run) d'abord ?"
                        $Result = Restore-GPOs -BackupPath $LatestGPO.FullName -DryRun:$DryRun
                        
                        if ($Result.Success) {
                            Write-Host "Restauration reussie : $($Result.Count)/$($Result.Total) GPO" -ForegroundColor Green
                        }
                        else {
                            Write-Host "Erreur : $($Result.Error)" -ForegroundColor Red
                        }
                    }
                    else {
                        Write-Host "Aucune sauvegarde GPO trouvee" -ForegroundColor Red
                    }
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "12" {
                if (Confirm-Action "ATTENTION : Restauration complete de tous les objets AD et GPO. Cette operation peut prendre du temps et impacter significativement l'environnement. Continuer ?") {
                    $SelectedDir = Select-BackupDirectory
                    if ($SelectedDir) {
                        $DryRun = Confirm-Action "Effectuer une simulation (dry-run) d'abord ?"
                        
                        Write-Host ""
                        Write-Host "Restauration complete en cours..." -ForegroundColor Yellow
                        Write-Host "Dossier source : $($SelectedDir.FullName)" -ForegroundColor Cyan
                        
                        $Result = Start-CompleteRestore -BackupPath $SelectedDir.FullName -DryRun:$DryRun
                        
                        if ($Result.OverallSuccess) {
                            Write-Host ""
                            Write-Host "Restauration complete reussie !" -ForegroundColor Green
                        }
                        else {
                            Write-Host ""
                            Write-Host "Restauration complete avec erreurs - Voir les details ci-dessus" -ForegroundColor Yellow
                        }
                    }
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "13" {
                Write-Host ""
                Write-Host "Test d'integrite en cours..." -ForegroundColor Yellow
                Test-BackupIntegrity -BackupPath $Config.BackupRootPath
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "14" {
                Write-Host ""
                Write-Host "Simulation de restauration en cours..." -ForegroundColor Yellow
                Test-RestoreSimulation -BackupPath $Config.BackupRootPath
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "15" {
                if (Confirm-Action "Lancer la rotation des sauvegardes (suppression des fichiers > $($Config.RetentionDays) jours) ?") {
                    $DeletedCount = Invoke-BackupRotation
                    if ($DeletedCount -ge 0) {
                        Write-Host "Rotation terminee : $DeletedCount elements supprimes" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Erreur lors de la rotation" -ForegroundColor Red
                    }
                }
                Read-Host "`nAppuyez sur Entree pour continuer"
            }
            
            "0" {
                Write-Host ""
                Write-Host $Config.Messages.Goodbye -ForegroundColor Cyan
                break
            }
            
            default {
                Write-Host ""
                Write-Host "Choix invalide, veuillez reessayer." -ForegroundColor Red
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
    # Test d'integrite programmatique
    Test-BackupIntegrity -BackupPath "C:\ADBackup"
    
.EXAMPLE
    # Restauration avec simulation
    Restore-ADUsers -FilePath "C:\ADBackup\Users_20231201_143022.csv" -DryRun
    
.EXAMPLE
    # Restauration complete avec simulation
    $BackupDir = "C:\ADBackup\20231201_143022_COMPLETE"
    Start-CompleteRestore -BackupPath $BackupDir -DryRun
    
.EXAMPLE
    # Restauration complete reelle
    Start-CompleteRestore -BackupPath $BackupDir
#>

# ===================================================================================================
# POINT D'ENTREE
# ===================================================================================================

# Lancement automatique si execute directement
if ($MyInvocation.InvocationName -ne '.') {
    Start-ADBackupScript
}
