<#
.SYNOPSIS
    Script interactif de restauration selective Active Directory (version modulaire)
...existing header...
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Chemin racine des sauvegardes")]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath = "C:\ADBackup"
)

# Import des modules
$ModulePath = Join-Path $PSScriptRoot "..\Core"
Import-Module (Join-Path $ModulePath "ADBackupCore.psm1") -Force
Import-Module (Join-Path $ModulePath "RestoreFunctions.psm1") -Force
Import-Module (Join-Path $ModulePath "UIHelpers.psm1") -Force

# Variables globales
$selectedBackupFolder = $null
$restoreOptions = @{
    "1" = @{ Name = "Unites Organisationnelles"; Selected = $false; Function = "Restore-ADOUs"; File = "OUs.csv" }
    "2" = @{ Name = "Utilisateurs"; Selected = $false; Function = "Restore-ADUsers"; File = "Users.csv" }
    "3" = @{ Name = "Groupes"; Selected = $false; Function = "Restore-ADGroups"; File = "Groups.csv" }
    "4" = @{ Name = "Ordinateurs"; Selected = $false; Function = "Restore-ADComputers"; File = "Computers.csv" }
    "5" = @{ Name = "Membres des groupes"; Selected = $false; Function = "Restore-ADGroupMemberships"; File = "GroupMemberships.csv" }
    "6" = @{ Name = "Contacts"; Selected = $false; Function = "Restore-ADContacts"; File = "Contacts.csv" }
}

# Fonction pour afficher les sauvegardes disponibles
function Show-AvailableBackups {
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host "            SELECTION DE LA SAUVEGARDE A RESTAURER" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host ""
    
    if (-not (Test-Path $BackupPath)) {
        Write-Host "Dossier de sauvegarde non trouve: $BackupPath" -ForegroundColor Red
        return $null
    }
    
    $backupFolders = Get-ChildItem -Path $BackupPath -Directory | Sort-Object CreationTime -Descending
    
    if ($backupFolders.Count -eq 0) {
        Write-Host "Aucune sauvegarde trouvee dans: $BackupPath" -ForegroundColor Red
        return $null
    }
    
    Write-Host "Sauvegardes disponibles:" -ForegroundColor Cyan
    Write-Host ""
    
    for ($i = 0; $i -lt $backupFolders.Count; $i++) {
        $folder = $backupFolders[$i]
        $summaryFile = Join-Path $folder.FullName "BackupSummary.json"
        $csvCount = (Get-ChildItem -Path $folder.FullName -Filter "*.csv" -ErrorAction SilentlyContinue).Count
        
        Write-Host " [$($i + 1)] $($folder.Name)" -ForegroundColor White
        Write-Host "     Date: $($folder.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
        Write-Host "     Fichiers CSV: $csvCount" -ForegroundColor Gray
        
        if (Test-Path $summaryFile) {
            try {
                $summary = Get-Content $summaryFile | ConvertFrom-Json
                Write-Host "     Taille: $($summary.TotalSize) MB" -ForegroundColor Gray
            } catch {
                Write-Host "     Taille: Non disponible" -ForegroundColor Gray
            }
        }
        Write-Host ""
    }
    
    Write-Host " [Q] Quitter" -ForegroundColor Red
    Write-Host ""
    
    do {
        $choice = Read-Host "Selectionnez une sauvegarde (1-$($backupFolders.Count) ou Q)"
        
        if ($choice.ToUpper() -eq "Q") {
            return $null
        }
        
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $backupFolders.Count) {
            return $backupFolders[[int]$choice - 1].FullName
        }
        
        Write-Host "Choix invalide!" -ForegroundColor Red
    } while ($true)
}

# Selection de la sauvegarde
$selectedBackupFolder = Show-AvailableBackups
if (-not $selectedBackupFolder) {
    Write-Host "Aucune sauvegarde selectionnee. Arret du script." -ForegroundColor Yellow
    exit 0
}

# Initialisation du module avec le dossier selectionne
Initialize-ADBackupModule -BackupPath $selectedBackupFolder -LogFileName "restore_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Write-ADLog "Debut de la restauration interactive depuis $selectedBackupFolder"

# Boucle principale
$allSelected = $false

do {
    try {
        $choice = Show-ColorMenu -Title "RESTAURATION INTERACTIVE ACTIVE DIRECTORY" -Options $restoreOptions -SpecialOptions @(
            "[A] TOUT selectionner/deselectionner",
            "[V] Verifier les conflits",
            "[S] Demarrer la restauration", 
            "[B] Retour selection sauvegarde",
            "[Q] Quitter"
        ) -Prompt "Votre choix"
        
        switch ($choice.ToUpper()) {
            "A" {
                # Basculer tout (seulement les fichiers disponibles)
                $allSelected = -not $allSelected
                foreach ($key in $restoreOptions.Keys) {
                    $filePath = Join-Path $selectedBackupFolder $restoreOptions[$key].File
                    if (Test-Path $filePath) {
                        $restoreOptions[$key].Selected = $allSelected
                    }
                }
                $status = if ($allSelected) { "selectionnes" } else { "deselectionnes" }
                Write-Host "Tous les elements disponibles ont ete $status!" -ForegroundColor Green
                Start-Sleep 1
            }
            "S" {
                $selectedCount = ($restoreOptions.Values | Where-Object { $_.Selected }).Count
                if ($selectedCount -eq 0) {
                    Write-Host "Aucun element selectionne!" -ForegroundColor Red
                    Start-Sleep 2
                    continue
                }
                
                Write-Host "ATTENTION: La restauration va modifier Active Directory!" -ForegroundColor Red
                $confirm = Read-Host "Etes-vous sur de vouloir continuer? (O/N)"
                
                if ($confirm.ToUpper() -eq "O") {
                    Write-Host "Demarrage de la restauration..." -ForegroundColor Green
                    $startTime = Get-Date
                    $totalRestored = 0
                    $totalSkipped = 0
                    
                    foreach ($key in ($restoreOptions.Keys | Sort-Object { [int]$_ })) {
                        if ($restoreOptions[$key].Selected) {
                            try {
                                Show-OperationProgress -Activity "Restauration en cours" -Status $restoreOptions[$key].Name -PercentComplete ((([int]$key) / $restoreOptions.Count) * 100)
                                $result = & $restoreOptions[$key].Function -BackupPath $selectedBackupFolder
                                $totalRestored += $result.Restored
                                $totalSkipped += $result.Skipped
                            } catch {
                                Write-ADLog "Erreur: $($_.Exception.Message)" "ERROR"
                            }
                        }
                    }
                    
                    Write-Progress -Activity "Restauration en cours" -Completed
                    $duration = (Get-Date) - $startTime
                    
                    Write-ADLog "Restauration terminee: $totalRestored restaures, $totalSkipped ignores en $([math]::Round($duration.TotalMinutes, 1)) minutes"
                    Write-Host ""
                    Write-Host "========== RESTAURATION TERMINEE ==========" -ForegroundColor Green
                    Write-Host "Duree: $([math]::Round($duration.TotalMinutes, 1)) minutes" -ForegroundColor White
                    Write-Host "Objets restaures: $totalRestored" -ForegroundColor White
                    Write-Host "Objets ignores: $totalSkipped" -ForegroundColor White
                    Write-Host "==========================================" -ForegroundColor Green
                    Write-Host ""
                    Write-Host "Appuyez sur une touche pour continuer..." -ForegroundColor Yellow
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    return
                } else {
                    Write-Host "Restauration annulee." -ForegroundColor Yellow
                    Start-Sleep 1
                }
            }
            "Q" {
                Write-Host "Annulation de la restauration." -ForegroundColor Yellow
                return
            }
            default {
                # Gestion des selections numeriques
                if ($restoreOptions.ContainsKey($choice)) {
                    $filePath = Join-Path $selectedBackupFolder $restoreOptions[$choice].File
                    if (Test-Path $filePath) {
                        $restoreOptions[$choice].Selected = -not $restoreOptions[$choice].Selected
                        $status = if ($restoreOptions[$choice].Selected) { "selectionne" } else { "deselectionne" }
                        Write-Host "$($restoreOptions[$choice].Name) $status" -ForegroundColor Green
                        Start-Sleep 1
                    } else {
                        Write-Host "Fichier de sauvegarde non disponible pour: $($restoreOptions[$choice].Name)" -ForegroundColor Red
                        Start-Sleep 2
                    }
                } else {
                    Write-Host "Choix invalide!" -ForegroundColor Red
                    Start-Sleep 1
                }
            }
        }
    } catch {
        Write-ADLog "Erreur inattendue: $($_.Exception.Message)" "ERROR"
        Start-Sleep 3
    }
} while ($true)
