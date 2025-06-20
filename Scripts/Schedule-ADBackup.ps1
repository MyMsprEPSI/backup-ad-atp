<#
.SYNOPSIS
    Script de programmation des sauvegardes automatiques Active Directory (version modulaire)
.DESCRIPTION
    Permet de creer, modifier ou supprimer des taches planifiees pour les sauvegardes AD
.AUTHOR
    Thibaut Maurras
.VERSION
    1.0
.DATE
    2025-01-20
.PREREQUISITES
    - Privileges Administrateur
    - Module ScheduledTasks (Windows 8/2012+)
.EXAMPLE
    .\Schedule-ADBackup.ps1
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Chemin de destination des sauvegardes")]
    [string]$BackupPath = "C:\ADBackup"
)

# Verification des privileges administrateur
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Ce script necessite des privileges administrateur. Relancez en tant qu'administrateur."
    exit 1
}

# Import du module ScheduledTasks
try {
    Import-Module ScheduledTasks -ErrorAction Stop
}
catch {
    Write-Error "Impossible de charger le module ScheduledTasks. Verifiez votre version de Windows."
    exit 1
}

# Import des modules UI
$ModulePath = Join-Path $PSScriptRoot "..\Core"
Import-Module (Join-Path $ModulePath "UIHelpers.psm1") -Force

# ...existing functions (New-ADBackupTask, Show-ExistingTasks, etc.)...

# Boucle principale simplifiee
do {
    try {
        $menuOptions = @{
            "1" = @{ Name = "Creer une nouvelle tache planifiee"; Selected = $false }
            "2" = @{ Name = "Voir les taches existantes"; Selected = $false }
            "3" = @{ Name = "Supprimer une tache"; Selected = $false }
            "4" = @{ Name = "Tester une tache immediatement"; Selected = $false }
            "5" = @{ Name = "Activer/Desactiver une tache"; Selected = $false }
            "6" = @{ Name = "Voir l'historique d'execution"; Selected = $false }
        }
        
        $choice = Show-ColorMenu -Title "PROGRAMMATION SAUVEGARDES ACTIVE DIRECTORY" -Options $menuOptions -SpecialOptions @("[Q] Quitter") -Prompt "Votre choix"
        
        switch ($choice) {
            "1" { New-ADBackupTask }
            "2" { Show-ExistingTasks }
            "3" { Remove-ADBackupTask }
            "4" { Start-ADBackupTask }
            "5" { Toggle-ADBackupTask }
            "6" { 
                Write-Host "Consultez l'Observateur d'evenements Windows :" -ForegroundColor Cyan
                Write-Host "Journaux Windows > Applications et services > Microsoft > Windows > TaskScheduler" -ForegroundColor White
                Read-Host "Appuyez sur Entree pour continuer"
            }
            "Q" { return }
            default { Write-Host "Choix invalide!" -ForegroundColor Red; Start-Sleep 1 }
        }
    }
    catch {
        Write-Host "Erreur inattendue: $($_.Exception.Message)" -ForegroundColor Red
        Start-Sleep 2
    }
} while ($true)
"4" { Remove-ADBackupTask }
"5" { Start-ADBackupTask }
"6" { Toggle-ADBackupTask }
"7" { 
    Write-Host "Verifiez l'historique dans l'Observateur d'evenements Windows :" -ForegroundColor Cyan
    Write-Host "Journaux Windows > Applications et services > Microsoft > Windows > TaskScheduler" -ForegroundColor White
    Read-Host "Appuyez sur Entree pour continuer"
}
"Q" { return }
default { Write-Host "Choix invalide!" -ForegroundColor Red; Start-Sleep 1 }
}
}
catch {
    Write-Host "Erreur inattendue: $($_.Exception.Message)" -ForegroundColor Red
    Start-Sleep 2
}
} while ($true)
