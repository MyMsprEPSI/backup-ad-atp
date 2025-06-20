<#
.SYNOPSIS
    Script interactif de sauvegarde selective Active Directory (version modulaire)
.DESCRIPTION
    Permet de choisir specifiquement quels objets AD sauvegarder
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

# Configuration
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFolder = Join-Path $BackupPath "Interactive_$timestamp"
$logFile = Join-Path $backupFolder "backup.log"

try {
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
}
catch {
    Write-Error "Impossible de creer le dossier de sauvegarde: $($_.Exception.Message)"
    exit 1
}

# Configuration des options complete
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

# Fonction de logging
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

# Fonctions de sauvegarde
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

function Backup-Contacts {
    try {
        Write-Log "Sauvegarde des contacts..."
        $contacts = Get-ADObject -Filter 'ObjectClass -eq "contact"' -Properties * -ErrorAction Stop
        $contacts | Export-Csv -Path (Join-Path $backupFolder "Contacts.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($contacts.Count) contacts sauvegardes]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde des contacts: $($_.Exception.Message)" "ERROR"
    }
}

function Backup-ServiceAccounts {
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
    }
}

function Backup-GroupMemberships {
    Write-Log "Sauvegarde des membres de groupes..."
    $groupMemberships = @()
    $groups = Get-ADGroup -Filter *
    $totalGroups = $groups.Count
    $currentGroup = 0
    
    foreach ($group in $groups) {
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

function Backup-Sites {
    try {
        Write-Log "Sauvegarde des sites et sous-reseaux..."
        $sites = Get-ADReplicationSite -Filter * -Properties * -ErrorAction Stop
        $sites | Export-Csv -Path (Join-Path $backupFolder "Sites.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($sites.Count) sites sauvegardes]"
        
        $subnets = Get-ADReplicationSubnet -Filter * -Properties * -ErrorAction Stop
        $subnets | Export-Csv -Path (Join-Path $backupFolder "Subnets.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($subnets.Count) sous-reseaux sauvegardes]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde des sites/sous-reseaux: $($_.Exception.Message)" "ERROR"
    }
}

function Backup-Trusts {
    try {
        Write-Log "Sauvegarde des trusts..."
        $trusts = Get-ADTrust -Filter * -ErrorAction Stop
        $trusts | Export-Csv -Path (Join-Path $backupFolder "Trusts.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($trusts.Count) trusts sauvegardes]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde des trusts: $($_.Exception.Message)" "ERROR"
    }
}

function Backup-GPO {
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
    }
}

function Backup-Schema {
    try {
        Write-Log "Sauvegarde du schema AD..."
        $rootDSE = Get-ADRootDSE -ErrorAction Stop
        
        $schemaAttributes = Get-ADObject -SearchBase $rootDSE.SchemaNamingContext -Filter 'ObjectClass -eq "attributeSchema"' -Properties * -ErrorAction Stop
        $schemaAttributes | Export-Csv -Path (Join-Path $backupFolder "SchemaAttributes.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($schemaAttributes.Count) attributs de schema sauvegardes]"
        
        $schemaClasses = Get-ADObject -SearchBase $rootDSE.SchemaNamingContext -Filter 'ObjectClass -eq "classSchema"' -Properties * -ErrorAction Stop
        $schemaClasses | Export-Csv -Path (Join-Path $backupFolder "SchemaClasses.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($schemaClasses.Count) classes de schema sauvegardees]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde du schema: $($_.Exception.Message)" "ERROR"
    }
}

function Backup-Replication {
    try {
        Write-Log "Sauvegarde des liens de replication..."
        $replConnections = Get-ADReplicationConnection -Filter * -ErrorAction Stop
        $replConnections | Export-Csv -Path (Join-Path $backupFolder "ReplicationConnections.csv") -NoTypeInformation -Encoding UTF8
        Write-Log "[$($replConnections.Count) liens de replication sauvegardes]"
    }
    catch {
        Write-Log "Erreur lors de la sauvegarde des liens de replication: $($_.Exception.Message)" "ERROR"
    }
}

function Backup-Certificates {
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
        }
    }
}

# Boucle principale
Write-Log "Debut de la sauvegarde interactive AD dans $backupFolder"

$allSelected = $false

do {
    # Affichage du menu
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host "        SAUVEGARDE INTERACTIVE ACTIVE DIRECTORY" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Selectionnez les elements a sauvegarder:" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($key in ($backupOptions.Keys | Sort-Object { [int]$_ })) {
        $option = $backupOptions[$key]
        $indicator = if ($option.Selected) { "[X]" } else { "[ ]" }
        $color = if ($option.Selected) { "Green" } else { "White" }
        Write-Host " $indicator [$key] $($option.Name)" -ForegroundColor $color
    }
    
    Write-Host ""
    Write-Host " [A] TOUT selectionner/deselectionner" -ForegroundColor Green
    Write-Host " [S] Demarrer la sauvegarde" -ForegroundColor Green
    Write-Host " [Q] Quitter" -ForegroundColor Red
    Write-Host ""
    
    $selectedCount = ($backupOptions.Values | Where-Object { $_.Selected }).Count
    Write-Host "Elements selectionnes: $selectedCount/$($backupOptions.Count)" -ForegroundColor Cyan
    Write-Host ""
    
    $choice = Read-Host "Votre choix"
    
    switch ($choice.ToUpper()) {
        "A" {
            $allSelected = -not $allSelected
            foreach ($key in $backupOptions.Keys) {
                $backupOptions[$key].Selected = $allSelected
            }
            $status = if ($allSelected) { "selectionnes" } else { "deselectionnes" }
            Write-Host "Tous les elements ont ete $status!" -ForegroundColor Green
            Start-Sleep 1
        }
        "S" {
            $selectedCount = ($backupOptions.Values | Where-Object { $_.Selected }).Count
            if ($selectedCount -eq 0) {
                Write-Host "Aucun element selectionne!" -ForegroundColor Red
                Start-Sleep 2
                continue
            }
            
            Write-Host "Demarrage de la sauvegarde..." -ForegroundColor Green
            $startTime = Get-Date
            $errorCount = 0
            
            foreach ($key in ($backupOptions.Keys | Sort-Object { [int]$_ })) {
                if ($backupOptions[$key].Selected) {
                    try {
                        Write-Progress -Activity "Sauvegarde en cours" -Status $backupOptions[$key].Name -PercentComplete ((([int]$key) / $backupOptions.Count) * 100)
                        & $backupOptions[$key].Function
                    }
                    catch {
                        $errorCount++
                        Write-Log "Erreur: $($_.Exception.Message)" "ERROR"
                    }
                }
            }
            
            Write-Progress -Activity "Sauvegarde en cours" -Completed
            
            $endTime = Get-Date
            $duration = $endTime - $startTime
            
            # Creation du rapport de synthese
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
        "Q" {
            Write-Host "Annulation de la sauvegarde." -ForegroundColor Yellow
            return
        }
        default {
            if ($backupOptions.ContainsKey($choice)) {
                $backupOptions[$choice].Selected = -not $backupOptions[$choice].Selected
                $status = if ($backupOptions[$choice].Selected) { "selectionne" } else { "deselectionne" }
                Write-Host "$($backupOptions[$choice].Name) $status" -ForegroundColor Green
                Start-Sleep 1
            }
            else {
                Write-Host "Choix invalide!" -ForegroundColor Red
                Start-Sleep 1
            }
        }
    }
} while ($true)
