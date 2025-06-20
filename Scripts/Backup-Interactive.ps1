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

# Import des modules
$ModulePath = Join-Path $PSScriptRoot "..\Core"
Import-Module (Join-Path $ModulePath "ADBackupCore.psm1") -Force
Import-Module (Join-Path $ModulePath "BackupFunctions.psm1") -Force
Import-Module (Join-Path $ModulePath "UIHelpers.psm1") -Force

# Configuration
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFolder = Join-Path $BackupPath "Interactive_$timestamp"

try {
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    Initialize-ADBackupModule -BackupPath $backupFolder
} catch {
    Write-Error "Impossible de creer le dossier de sauvegarde: $($_.Exception.Message)"
    exit 1
}

# Configuration des options (complete avec toutes les fonctions)
$backupOptions = @{
    "1"  = @{ Name = "Utilisateurs"; Selected = $false; Function = "Backup-ADUsers" }
    "2"  = @{ Name = "Groupes"; Selected = $false; Function = "Backup-ADGroups" }
    "3"  = @{ Name = "Unites Organisationnelles"; Selected = $false; Function = "Backup-ADOUs" }
    "4"  = @{ Name = "Ordinateurs"; Selected = $false; Function = "Backup-ADComputers" }
    "5"  = @{ Name = "Serveurs"; Selected = $false; Function = "Backup-ADServers" }
    "6"  = @{ Name = "Controleurs de domaine"; Selected = $false; Function = "Backup-ADDomainControllers" }
    "7"  = @{ Name = "Contacts"; Selected = $false; Function = "Backup-ADContacts" }
    "8"  = @{ Name = "Comptes de service"; Selected = $false; Function = "Backup-ADServiceAccounts" }
    "9"  = @{ Name = "Membres des groupes"; Selected = $false; Function = "Backup-ADGroupMemberships" }
    "10" = @{ Name = "Sites et sous-reseaux"; Selected = $false; Function = "Backup-ADSites" }
    "11" = @{ Name = "Trusts"; Selected = $false; Function = "Backup-ADTrusts" }
    "12" = @{ Name = "GPO"; Selected = $false; Function = "Backup-ADGPO" }
    "13" = @{ Name = "Schema AD"; Selected = $false; Function = "Backup-ADSchema" }
    "14" = @{ Name = "Liens de replication"; Selected = $false; Function = "Backup-ADReplication" }
    "15" = @{ Name = "Modeles de certificats"; Selected = $false; Function = "Backup-ADCertificates" }
}

# Import du module de presets
Import-Module (Join-Path $PSScriptRoot "..\Config\PresetManager.psm1") -Force

# Fonction pour afficher les presets
function Show-PresetMenu {
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor Magenta
    Write-Host "                    PRESETS DE SAUVEGARDE" -ForegroundColor Magenta
    Write-Host "===============================================================" -ForegroundColor Magenta
    Write-Host ""
    
    $presets = Get-BackupPresets
    if ($presets) {
        Write-Host " [1] $($presets.essential.name) - $($presets.essential.description)" -ForegroundColor White
        Write-Host " [2] $($presets.complete.name) - $($presets.complete.description)" -ForegroundColor White
        Write-Host " [3] $($presets.security.name) - $($presets.security.description)" -ForegroundColor White
        Write-Host " [4] $($presets.infrastructure.name) - $($presets.infrastructure.description)" -ForegroundColor White
    } else {
        Write-Host " [1] Sauvegarde ESSENTIELLE (Users, Groups, OUs, Computers)" -ForegroundColor White
        Write-Host " [2] Sauvegarde COMPLETE (Tout sauf Schema et Replication)" -ForegroundColor White
        Write-Host " [3] Sauvegarde SECURITE (Users, Groups, GPO, Trusts)" -ForegroundColor White
        Write-Host " [4] Sauvegarde INFRASTRUCTURE (Sites, DC, Replication)" -ForegroundColor White
    }
    
    Write-Host " [R] Retour au menu principal" -ForegroundColor Yellow
    Write-Host ""
    
    $presetChoice = Read-Host "Choisissez un preset"
    
    switch ($presetChoice) {
        "1" { Set-BackupPreset -BackupOptions $backupOptions -PresetName "essential" }
        "2" { Set-BackupPreset -BackupOptions $backupOptions -PresetName "complete" }
        "3" { Set-BackupPreset -BackupOptions $backupOptions -PresetName "security" }
        "4" { Set-BackupPreset -BackupOptions $backupOptions -PresetName "infrastructure" }
        default { return }
    }
    
    Write-Host "Preset applique!" -ForegroundColor Green
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
        
    } catch {
        Write-Host "Erreur lors de la recuperation des informations AD: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Appuyez sur une touche pour continuer..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Boucle principale simplifiee
Write-ADLog "Debut de la sauvegarde interactive AD dans $backupFolder"

$allSelected = $false

do {
    $choice = Show-ColorMenu -Title "SAUVEGARDE INTERACTIVE ACTIVE DIRECTORY" -Options $backupOptions -SpecialOptions @(
        "[A] TOUT selectionner/deselectionner",
        "[P] Presets rapides", 
        "[I] Informations sur l'AD",
        "[S] Demarrer la sauvegarde",
        "[Q] Quitter"
    )
    
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
            # Logique de sauvegarde
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
                        Show-OperationProgress -Activity "Sauvegarde en cours" -Status $backupOptions[$key].Name -PercentComplete ((([int]$key) / $backupOptions.Count) * 100)
                        & $backupOptions[$key].Function -OutputPath $backupFolder
                    } catch {
                        $errorCount++
                        Write-ADLog "Erreur: $($_.Exception.Message)" "ERROR"
                    }
                }
            }
            
            Write-Progress -Activity "Sauvegarde en cours" -Completed
            
            $endTime = Get-Date
            $duration = $endTime - $startTime
            
            # Creation du rapport de synthese
            $summary = @{
                Date = Get-Date
                BackupFolder = $backupFolder
                SelectedItems = ($backupOptions.Keys | Where-Object { $backupOptions[$_].Selected } | ForEach-Object { $backupOptions[$_].Name })
                Duration = [math]::Round($duration.TotalMinutes, 2)
                FilesCreated = (Get-ChildItem $backupFolder -File -ErrorAction SilentlyContinue).Count
                TotalSize = [math]::Round(((Get-ChildItem $backupFolder -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB), 2)
                ErrorCount = $errorCount
                SuccessCount = $selectedCount - $errorCount
            }
            
            $summary | ConvertTo-Json -Depth 3 | Out-File (Join-Path $backupFolder "BackupSummary.json") -Encoding UTF8
            
            Write-ADLog "Sauvegarde interactive terminee en $([math]::Round($duration.TotalMinutes, 1)) minutes ($($summary.SuccessCount) succes, $errorCount erreurs)"
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
            # Gestion des selections numeriques
            if ($backupOptions.ContainsKey($choice)) {
                $backupOptions[$choice].Selected = -not $backupOptions[$choice].Selected
                $status = if ($backupOptions[$choice].Selected) { "selectionne" } else { "deselectionne" }
                Write-Host "$($backupOptions[$choice].Name) $status" -ForegroundColor Green
                Start-Sleep 1
            } else {
                Write-Host "Choix invalide!" -ForegroundColor Red
                Start-Sleep 1
            }
        }
    }
} while ($true)
