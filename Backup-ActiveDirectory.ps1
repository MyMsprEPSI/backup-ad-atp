<#
.SYNOPSIS
    Script interactif de sauvegarde selective Active Directory
.DESCRIPTION
    Permet de choisir specifiquement quels objets AD sauvegarder
.NOTES
    Necessite des privileges administrateur et le module ActiveDirectory
.AUTHOR
    Thibaut Maurras
.VERSION
    1.2
.DATE
    2025-01-20
.PREREQUISITES
    - Module ActiveDirectory
    - Privileges Administrateur
    - Module GroupPolicy (optionnel pour GPO)
.EXAMPLE
    .\Backup-Interactive.ps1
    .\Backup-Interactive.ps1 -BackupPath "D:\Backups\AD"
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Chemin de destination pour les sauvegardes")]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath = "C:\ADBackup"
)

# Verification des prerequis
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Verbose "Module ActiveDirectory charge avec succes"
}
catch {
    Write-Error "Impossible de charger le module ActiveDirectory. Verifiez qu'il est installe."
    exit 1
}

# Configuration des chemins
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFolder = Join-Path $BackupPath "Interactive_$timestamp"
$logFile = Join-Path $backupFolder "backup.log"

# Creation du dossier de sauvegarde
try {
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    Write-Verbose "Dossier de sauvegarde cree: $backupFolder"
}
catch {
    Write-Error "Impossible de creer le dossier de sauvegarde: $($_.Exception.Message)"
    exit 1
}

# Dictionnaire des options de sauvegarde
$backupOptions = @{
    "1"  = @{ Name = "Utilisateurs"; Selected = $false; Function = "Backup-Users" }
    "2"  = @{ Name = "Groupes"; Selected = $false; Function = "Backup-Groups" }
    "3"  = @{ Name = "Unites Organisationnelles"; Selected = $false; Function = "Backup-OUs" }
    "4"  = @{ Name = "Ordinateurs"; Selected = $false; Function = "Backup-Computers" }
    "5"  = @{ Name = "Serveurs"; Selected = $false; Function = "Backup-Servers" }
    "6"  = @{ Name = "Controleurs de domaine"; Selected = $false; Function = "Backup-DomainControllers" }
    "7"  = @{ Name = "Contacts"; Selected = $false; Function = "Backup-Contacts" }
    "8"  = @{ Name = "Comptes de service"; Selected = $false; Function = "Backup-ServiceAccounts" }
    "9"  = @{ Name = "Membres des groupes"; Selected = $false; Function = "Backup-GroupMemberships" }
    "10" = @{ Name = "Sites et sous-reseaux"; Selected = $false; Function = "Backup-Sites" }
    "11" = @{ Name = "Trusts"; Selected = $false; Function = "Backup-Trusts" }
    "12" = @{ Name = "GPO"; Selected = $false; Function = "Backup-GPO" }
    "13" = @{ Name = "Schema AD"; Selected = $false; Function = "Backup-Schema" }
    "14" = @{ Name = "Liens de replication"; Selected = $false; Function = "Backup-Replication" }
    "15" = @{ Name = "Modeles de certificats"; Selected = $false; Function = "Backup-Certificates" }
}

<#
.SYNOPSIS
    Journalise les messages avec horodatage
.DESCRIPTION
    Ecrit les messages a la fois dans la console et dans le fichier de log
.PARAMETER Message
    Message a journaliser
.PARAMETER Level
    Niveau de log (INFO, WARNING, ERROR)
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $(
        switch ($Level) {
            "INFO" { "White" }
            "WARNING" { "Yellow" }
            "ERROR" { "Red" }
        }
    )
    
    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Warning "Impossible d'ecrire dans le fichier de log: $($_.Exception.Message)"
    }
}

# Fonction pour afficher le menu de selection
function Show-SelectionMenu {
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host "        SAUVEGARDE INTERACTIVE ACTIVE DIRECTORY" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Selectionnez les elements a sauvegarder:" -ForegroundColor Cyan
    Write-Host ""
    
    # Affichage avec indicateurs visuels
    foreach ($key in ($backupOptions.Keys | Sort-Object { [int]$_ })) {
        $option = $backupOptions[$key]
        $indicator = if ($option.Selected) { "[X]" } else { "[ ]" }
        $color = if ($option.Selected) { "Green" } else { "White" }
        Write-Host " $indicator [$key] $($option.Name)" -ForegroundColor $color
    }
    
    Write-Host ""
    Write-Host " [A] TOUT selectionner/deselectionner" -ForegroundColor Green
    Write-Host " [P] Presets rapides" -ForegroundColor Magenta
    Write-Host " [I] Informations sur l'AD" -ForegroundColor Cyan
    Write-Host " [S] Demarrer la sauvegarde" -ForegroundColor Green
    Write-Host " [Q] Quitter" -ForegroundColor Red
    Write-Host ""
}

# Fonction pour afficher les presets
function Show-PresetMenu {
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor Magenta
    Write-Host "                    PRESETS DE SAUVEGARDE" -ForegroundColor Magenta
    Write-Host "===============================================================" -ForegroundColor Magenta
    Write-Host ""
    Write-Host " [1] Sauvegarde ESSENTIELLE (Users, Groups, OUs, Computers)" -ForegroundColor White
    Write-Host " [2] Sauvegarde COMPLETE (Tout sauf Schema et Replication)" -ForegroundColor White
    Write-Host " [3] Sauvegarde SECURITE (Users, Groups, GPO, Trusts)" -ForegroundColor White
    Write-Host " [4] Sauvegarde INFRASTRUCTURE (Sites, DC, Replication)" -ForegroundColor White
    Write-Host " [5] Sauvegarde PERSONNALISEE (Selection manuelle)" -ForegroundColor White
    Write-Host " [R] Retour au menu principal" -ForegroundColor Yellow
    Write-Host ""
    
    $presetChoice = Read-Host "Choisissez un preset"
    
    # Reset toutes les selections
    foreach ($key in $backupOptions.Keys) {
        $backupOptions[$key].Selected = $false
    }
    
    switch ($presetChoice) {
        "1" {
            # Essentiel
            @("1", "2", "3", "4") | ForEach-Object { $backupOptions[$_].Selected = $true }
            Write-Host "Preset ESSENTIEL applique!" -ForegroundColor Green
        }
        "2" {
            # Complet
            @("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "15") | ForEach-Object { $backupOptions[$_].Selected = $true }
            Write-Host "Preset COMPLET applique!" -ForegroundColor Green
        }
        "3" {
            # Securite
            @("1", "2", "12", "11") | ForEach-Object { $backupOptions[$_].Selected = $true }
            Write-Host "Preset SECURITE applique!" -ForegroundColor Green
        }
        "4" {
            # Infrastructure
            @("6", "10", "14") | ForEach-Object { $backupOptions[$_].Selected = $true }
            Write-Host "Preset INFRASTRUCTURE applique!" -ForegroundColor Green
        }
        "5" {
            Write-Host "Mode personnalise - selectionnez manuellement vos options" -ForegroundColor Yellow
        }
        default {
            return
        }
    }
    Start-Sleep 2
}

# Fonction pour afficher les informations AD
function Show-ADInfo {
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "              INFORMATIONS ACTIVE DIRECTORY" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest
        $dcCount = (Get-ADDomainController -Filter *).Count
        $userCount = (Get-ADUser -Filter *).Count
        $groupCount = (Get-ADGroup -Filter *).Count
        $computerCount = (Get-ADComputer -Filter *).Count
        $ouCount = (Get-ADOrganizationalUnit -Filter *).Count
        
        Write-Host "Domaine: $($domain.DNSRoot)" -ForegroundColor White
        Write-Host "Niveau fonctionnel: $($domain.DomainMode)" -ForegroundColor White
        Write-Host "Foret: $($forest.Name)" -ForegroundColor White
        Write-Host "Controleurs de domaine: $dcCount" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Statistiques des objets:" -ForegroundColor Cyan
        Write-Host "  - Utilisateurs: $userCount" -ForegroundColor White
        Write-Host "  - Groupes: $groupCount" -ForegroundColor White
        Write-Host "  - Ordinateurs: $computerCount" -ForegroundColor White
        Write-Host "  - Unites organisationnelles: $ouCount" -ForegroundColor White
        
        # Estimation de la taille de sauvegarde
        $estimatedSize = [math]::Round(($userCount * 50 + $groupCount * 20 + $computerCount * 30 + $ouCount * 10) / 1024, 2)
        Write-Host ""
        Write-Host "Taille estimee de la sauvegarde: ~$estimatedSize MB" -ForegroundColor Green
        
    }
    catch {
        Write-Host "Erreur lors de la recuperation des informations AD: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Appuyez sur une touche pour continuer..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Amelioration des fonctions de sauvegarde avec validation et statistiques
function Backup-Users {
    Write-Log "Sauvegarde des utilisateurs..."
    $users = Get-ADUser -Filter * -Properties *
    $users | Export-Csv -Path (Join-Path $backupFolder "Users.csv") -NoTypeInformation -Encoding UTF8
    Write-Log "[$($users.Count) utilisateurs sauvegardes]"
}

function Backup-Groups {
    Write-Log "Sauvegarde des groupes..."
    $groups = Get-ADGroup -Filter * -Properties *
    $groups | Export-Csv -Path (Join-Path $backupFolder "Groups.csv") -NoTypeInformation -Encoding UTF8
    Write-Log "[$($groups.Count) groupes sauvegardes]"
}

function Backup-OUs {
    Write-Log "Sauvegarde des unites organisationnelles..."
    $ous = Get-ADOrganizationalUnit -Filter * -Properties *
    $ous | Export-Csv -Path (Join-Path $backupFolder "OUs.csv") -NoTypeInformation -Encoding UTF8
    Write-Log "[$($ous.Count) OUs sauvegardees]"
}

function Backup-Computers {
    Write-Log "Sauvegarde des ordinateurs..."
    $computers = Get-ADComputer -Filter * -Properties *
    $computers | Export-Csv -Path (Join-Path $backupFolder "Computers.csv") -NoTypeInformation -Encoding UTF8
    Write-Log "[$($computers.Count) ordinateurs sauvegardes]"
}

function Backup-Servers {
    Write-Log "Sauvegarde des serveurs..."
    $servers = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' -Properties *
    $servers | Export-Csv -Path (Join-Path $backupFolder "Servers.csv") -NoTypeInformation -Encoding UTF8
    Write-Log "[$($servers.Count) serveurs sauvegardes]"
}

function Backup-DomainControllers {
    Write-Log "Sauvegarde des controleurs de domaine..."
    $dcs = Get-ADDomainController -Filter *
    $dcs | Export-Csv -Path (Join-Path $backupFolder "DomainControllers.csv") -NoTypeInformation -Encoding UTF8
    Write-Log "[$($dcs.Count) controleurs de domaine sauvegardes]"
}

function Backup-GroupMemberships {
    Write-Log "Sauvegarde des membres de groupes..."
    $groupMemberships = @()
    $groups = Get-ADGroup -Filter *
    $totalGroups = $groups.Count
    $currentGroup = 0
    
    $groups | ForEach-Object {
        $group = $_
        $currentGroup++
        Write-Progress -Activity "Sauvegarde des appartenances" -Status "Groupe: $($group.Name)" -PercentComplete (($currentGroup / $totalGroups) * 100)
        
        Get-ADGroupMember -Identity $group.SamAccountName -ErrorAction SilentlyContinue | ForEach-Object {
            $groupMemberships += [PSCustomObject]@{
                GroupName   = $group.SamAccountName
                GroupDN     = $group.DistinguishedName
                MemberName  = $_.SamAccountName
                MemberDN    = $_.DistinguishedName
                ObjectClass = $_.ObjectClass
            }
        }
    }
    Write-Progress -Activity "Sauvegarde des appartenances" -Completed
    $groupMemberships | Export-Csv -Path (Join-Path $backupFolder "GroupMemberships.csv") -NoTypeInformation -Encoding UTF8
    Write-Log "[$($groupMemberships.Count) relations d'appartenance sauvegardees]"
}

<#
.SYNOPSIS
    Sauvegarde les contacts Active Directory
.DESCRIPTION
    Exporte tous les objets contact vers un fichier CSV
#>
function Backup-Contacts {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Sauvegarde des contacts..."
        $contacts = Get-ADObject -Filter 'ObjectClass -eq "contact"' -Properties * -ErrorAction Stop
        $contacts | Export-Csv -Path (Join-Path $backupFolder "Contacts.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($contacts.Count) contacts sauvegardes]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde des contacts: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les comptes de service geres
.DESCRIPTION
    Exporte tous les comptes de service geres vers un fichier CSV
#>
function Backup-ServiceAccounts {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Sauvegarde des comptes de service..."
        $serviceAccounts = Get-ADServiceAccount -Filter * -Properties * -ErrorAction SilentlyContinue
        if ($serviceAccounts) {
            $serviceAccounts | Export-Csv -Path (Join-Path $backupFolder "ServiceAccounts.csv") -NoTypeInformation -Encoding UTF8
            Write-Log "[$($serviceAccounts.Count) comptes de service sauvegardes]"
        }
        else {
            Write-Log "[Aucun compte de service trouve]" "WARNING"
        }
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde des comptes de service: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les sites et sous-reseaux de replication
.DESCRIPTION
    Exporte les sites AD et sous-reseaux vers des fichiers CSV separes
#>
function Backup-Sites {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Sauvegarde des sites et sous-reseaux..."
        
        # Sauvegarde des sites
        $sites = Get-ADReplicationSite -Filter * -Properties * -ErrorAction Stop
        $sites | Export-Csv -Path (Join-Path $backupFolder "Sites.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($sites.Count) sites sauvegardes]"
        
        # Sauvegarde des sous-reseaux
        $subnets = Get-ADReplicationSubnet -Filter * -Properties * -ErrorAction Stop
        $subnets | Export-Csv -Path (Join-Path $backupFolder "Subnets.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($subnets.Count) sous-reseaux sauvegardes]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde des sites/sous-reseaux: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les trusts de domaine
.DESCRIPTION
    Exporte toutes les relations d'approbation vers un fichier CSV
#>
function Backup-Trusts {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Sauvegarde des trusts..."
        $trusts = Get-ADTrust -Filter * -ErrorAction Stop
        $trusts | Export-Csv -Path (Join-Path $backupFolder "Trusts.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($trusts.Count) trusts sauvegardes]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde des trusts: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les strategies de groupe (GPO)
.DESCRIPTION
    Exporte toutes les GPO avec leur contenu dans un dossier dedie
#>
function Backup-GPO {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Sauvegarde des GPO..."
        
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-Log "Module GroupPolicy non disponible" "WARNING"
            return
        }
        
        Import-Module GroupPolicy -ErrorAction Stop
        $gpoBackupPath = Join-Path $backupFolder "GPOBackup"
        New-Item -Path $gpoBackupPath -ItemType Directory -Force | Out-Null
        
        $gpos = Get-GPO -All -ErrorAction Stop
        $successCount = 0
        
        foreach ($gpo in $gpos) {
            try {
                Backup-GPO -Guid $gpo.Id -Path $gpoBackupPath -ErrorAction Stop | Out-Null
                Write-Log "GPO sauvegarde: $($gpo.DisplayName)"
                $successCount++
            }
            catch {
                Write-Log "Erreur GPO $($gpo.DisplayName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-Log "[$successCount/$($gpos.Count) GPO sauvegardees]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde des GPO: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde le schema Active Directory
.DESCRIPTION
    Exporte les attributs et classes du schema vers des fichiers CSV separes
#>
function Backup-Schema {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Sauvegarde du schema AD..."
        $rootDSE = Get-ADRootDSE -ErrorAction Stop
        
        # Sauvegarde des attributs de schema
        $schemaAttributes = Get-ADObject -SearchBase $rootDSE.SchemaNamingContext -Filter 'ObjectClass -eq "attributeSchema"' -Properties * -ErrorAction Stop
        $schemaAttributes | Export-Csv -Path (Join-Path $backupFolder "SchemaAttributes.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($schemaAttributes.Count) attributs de schema sauvegardes]"
        
        # Sauvegarde des classes de schema
        $schemaClasses = Get-ADObject -SearchBase $rootDSE.SchemaNamingContext -Filter 'ObjectClass -eq "classSchema"' -Properties * -ErrorAction Stop
        $schemaClasses | Export-Csv -Path (Join-Path $backupFolder "SchemaClasses.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($schemaClasses.Count) classes de schema sauvegardees]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde du schema: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les liens de replication
.DESCRIPTION
    Exporte toutes les connexions de replication vers un fichier CSV
#>
function Backup-Replication {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Sauvegarde des liens de replication..."
        $replConnections = Get-ADReplicationConnection -Filter * -ErrorAction Stop
        $replConnections | Export-Csv -Path (Join-Path $backupFolder "ReplicationConnections.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($replConnections.Count) liens de replication sauvegardes]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde des liens de replication: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les modeles de certificats
.DESCRIPTION
    Exporte tous les modeles de certificats PKI vers un fichier CSV
#>
function Backup-Certificates {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Sauvegarde des modeles de certificats..."
        $rootDSE = Get-ADRootDSE -ErrorAction Stop
        $certTemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.ConfigurationNamingContext)"
        
        $certTemplates = Get-ADObject -SearchBase $certTemplatesPath -Filter * -Properties * -ErrorAction Stop
        $certTemplates | Export-Csv -Path (Join-Path $backupFolder "CertificateTemplates.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($certTemplates.Count) modeles de certificats sauvegardes]"
    }
    catch {
        if ($_.Exception.Message -like "*objet introuvable*" -or $_.Exception.Message -like "*not found*") {
            Write-Log "Aucun modele de certificat trouve (PKI non deploye)" "WARNING"
        }
        else {
            Write-Log "Erreur lors de la sauvegarde des certificats: $($_.Exception.Message)" "ERROR"
            throw
        }
    }
}

<#
.SYNOPSIS
    Teste la validite d'un choix utilisateur
.DESCRIPTION
    Verifie si le choix correspond a une option valide
.PARAMETER Choice
    Choix saisi par l'utilisateur
.PARAMETER ValidOptions
    Liste des options valides
#>
function Test-UserChoice {
    [CmdletBinding()]
    param(
        [string]$Choice,
        [string[]]$ValidOptions
    )
    
    return $Choice.ToUpper() -in $ValidOptions
}

# Boucle principale du menu interactif
Write-Log "Debut de la sauvegarde interactive AD dans $backupFolder"

$allSelected = $false

# Variables pour les options valides
$validNumericOptions = $backupOptions.Keys
$validSpecialOptions = @("A", "P", "I", "S", "Q")
$allValidOptions = $validNumericOptions + $validSpecialOptions

do {
    try {
        Show-SelectionMenu
        
        # Affichage du compteur de selections
        $selectedCount = ($backupOptions.Values | Where-Object { $_.Selected }).Count
        $totalCount = $backupOptions.Count
        Write-Host "Elements selectionnes: $selectedCount/$totalCount" -ForegroundColor Cyan
        Write-Host ""
        
        $choice = Read-Host "Votre choix"
        
        # Validation du choix
        if (-not (Test-UserChoice -Choice $choice -ValidOptions $allValidOptions)) {
            Write-Host "Choix invalide! Options valides: $($allValidOptions -join ', ')" -ForegroundColor Red
            Start-Sleep 2
            continue
        }
        
        switch ($choice.ToUpper()) {
            "A" {
                # Basculer tout
                $allSelected = -not $allSelected
                foreach ($key in $backupOptions.Keys) {
                    $backupOptions[$key].Selected = $allSelected
                }
                $status = if ($allSelected) { "selectionnes" } else { "deselectionnes" }
                Write-Host "Tous les elements ont ete $status!" -ForegroundColor Green
                Start-Sleep 1
            }
            "P" {
                # Menu des presets
                Show-PresetMenu
            }
            "I" {
                # Informations AD
                Show-ADInfo
            }
            "S" {
                # Demarrer la sauvegarde
                if ($selectedCount -eq 0) {
                    Write-Host "Aucun element selectionne pour la sauvegarde!" -ForegroundColor Red
                    Start-Sleep 2
                }
                else {
                    Write-Host "Demarrage de la sauvegarde de $selectedCount elements..." -ForegroundColor Green
                    $startTime = Get-Date
                    $errorCount = 0
                    
                    foreach ($key in ($backupOptions.Keys | Sort-Object { [int]$_ })) {
                        if ($backupOptions[$key].Selected) {
                            try {
                                Write-Progress -Activity "Sauvegarde en cours" -Status "Traitement: $($backupOptions[$key].Name)" -PercentComplete ((([int]$key) / $totalCount) * 100)
                                & $backupOptions[$key].Function
                            }
                            catch {
                                $errorCount++
                                Write-Log "Erreur lors de la sauvegarde de $($backupOptions[$key].Name): $($_.Exception.Message)" "ERROR"
                            }
                        }
                    }
                    Write-Progress -Activity "Sauvegarde en cours" -Completed
                    
                    $endTime = Get-Date
                    $duration = $endTime - $startTime
                    
                    # Creation du rapport de synthese ameliore
                    $summary = @{
                        Date          = Get-Date
                        BackupFolder  = $backupFolder
                        SelectedItems = ($backupOptions.Keys | Where-Object { $backupOptions[$_].Selected } | ForEach-Object { $backupOptions[$_].Name })
                        Duration      = [math]::Round($duration.TotalMinutes, 2)
                        FilesCreated  = (Get-ChildItem $backupFolder -File -ErrorAction SilentlyContinue).Count
                        TotalSize     = [math]::Round(((Get-ChildItem $backupFolder -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB), 2)
                        ErrorCount    = $errorCount
                        SuccessCount  = $selectedCount - $errorCount
                    }
                    
                    try {
                        $summary | ConvertTo-Json -Depth 3 | Out-File (Join-Path $backupFolder "BackupSummary.json") -Encoding UTF8
                    }
                    catch {
                        Write-Log "Impossible de creer le rapport de synthese: $($_.Exception.Message)" "WARNING"
                    }
                    
                    Write-Log "Sauvegarde interactive terminee en $([math]::Round($duration.TotalMinutes, 1)) minutes ($($summary.SuccessCount) succes, $errorCount erreurs)"
                    Write-Host ""
                    Write-Host "========== SAUVEGARDE TERMINEE ==========" -ForegroundColor Green
                    Write-Host "Dossier: $backupFolder" -ForegroundColor White
                    Write-Host "Duree: $([math]::Round($duration.TotalMinutes, 1)) minutes" -ForegroundColor White
                    Write-Host "Fichiers crees: $($summary.FilesCreated)" -ForegroundColor White
                    Write-Host "Taille totale: $($summary.TotalSize) MB" -ForegroundColor White
                    Write-Host "Succes: $($summary.SuccessCount)/$selectedCount" -ForegroundColor $(if ($errorCount -eq 0) { "Green" } else { "Yellow" })
                    Write-Host "=========================================" -ForegroundColor Green
                    Write-Host ""
                    Write-Host "Appuyez sur une touche pour continuer..." -ForegroundColor Yellow
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    return
                }
            }
            "Q" {
                Write-Host "Annulation de la sauvegarde." -ForegroundColor Yellow
                return
            }
            default {
                # Gestion des selections numeriques
                if ($backupOptions.ContainsKey($choice)) {
                    $backupOptions[$choice].Selected = -not $backupOptions[$choice].Selected
                    $status = if ($backupOptions[$choice].Selected) { "selectionne" } else { "deselectionne" }
                    Write-Host "$($backupOptions[$choice].Name) $status" -ForegroundColor Green
                    Start-Sleep 1
                }
            }
        }
    }
    catch {
        Write-Log "Erreur inattendue dans la boucle principale: $($_.Exception.Message)" "ERROR"
        Write-Host "Une erreur s'est produite. Consultez le fichier de log pour plus de details." -ForegroundColor Red
        Start-Sleep 3
    }
} while ($true)
