<#
.SYNOPSIS
    Script interactif de restauration selective Active Directory (version modulaire)
.DESCRIPTION
    Permet de choisir specifiquement quels objets AD restaurer depuis une sauvegarde
.AUTHOR
    Thibaut Maurras
.VERSION
    1.0
.DATE
    2025-01-20
.PREREQUISITES
    - Module ActiveDirectory
    - Privileges Administrateur
    - Fichiers de sauvegarde CSV
.EXAMPLE
    .\Restore-ActiveDirectory.ps1
    .\Restore-ActiveDirectory.ps1 -BackupPath "D:\Backups\AD"
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

# ...existing code for functions (Show-AvailableBackups, Test-RestoreConflicts)...

# Selection de la sauvegarde
$selectedBackupFolder = Show-AvailableBackups
if (-not $selectedBackupFolder) {
    Write-Host "Aucune sauvegarde selectionnee. Arret du script." -ForegroundColor Yellow
    exit 0
}

# Initialisation du module avec le dossier selectionne
Initialize-ADBackupModule -BackupPath $selectedBackupFolder -LogFileName "restore_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Write-ADLog "Debut de la restauration interactive depuis $selectedBackupFolder"

# Boucle principale avec modules UI
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
                    # ...existing completion display...
                    return
                }
            }
            # ...existing switch cases...
        }
    } catch {
        Write-ADLog "Erreur inattendue: $($_.Exception.Message)" "ERROR"
        Start-Sleep 3
    }
} while ($true)
