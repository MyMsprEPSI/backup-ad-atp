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

# Import des modules (avec fallback si modules non disponibles)
$ModulePath = Join-Path $PSScriptRoot "..\Core"
try {
    if (Test-Path (Join-Path $ModulePath "ADBackupCore.psm1")) {
        Import-Module (Join-Path $ModulePath "ADBackupCore.psm1") -Force
    }
    if (Test-Path (Join-Path $ModulePath "UIHelpers.psm1")) {
        Import-Module (Join-Path $ModulePath "UIHelpers.psm1") -Force
    }
}
catch {
    Write-Warning "Modules non disponibles, utilisation des fonctions integrees"
}

# Configuration
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFolder = Join-Path $BackupPath "Interactive_$timestamp"
$logFile = Join-Path $backupFolder "backup.log"

try {
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    # Initialisation avec fallback
    if (Get-Command Initialize-ADBackupModule -ErrorAction SilentlyContinue) {
        Initialize-ADBackupModule -BackupPath $backupFolder
    }
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

# Fonctions de logging avec fallback
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    if (Get-Command Write-ADLog -ErrorAction SilentlyContinue) {
        Write-ADLog -Message $Message -Level $Level
    }
    else {
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
        Write-Host $logEntry -ForegroundColor $(
            switch ($Level) {
                "INFO" { "White" }
                "WARNING" { "Yellow" }
                "ERROR" { "Red" }
            }
        )
        
        if ($logFile) {
            try {
                Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
            }
            catch {
                Write-Warning "Impossible d'ecrire dans le fichier de log: $($_.Exception.Message)"
            }
        }
    }
}

# ...existing backup functions...

# Boucle principale avec fallback pour l'UI
Write-Log "Debut de la sauvegarde interactive AD dans $backupFolder"

$allSelected = $false

do {
    # Affichage du menu avec ou sans modules UI
    if (Get-Command Show-ColorMenu -ErrorAction SilentlyContinue) {
        $choice = Show-ColorMenu -Title "SAUVEGARDE INTERACTIVE ACTIVE DIRECTORY" -Options $backupOptions -SpecialOptions @(
            "[A] TOUT selectionner/deselectionner",
            "[P] Presets rapides", 
            "[I] Informations sur l'AD",
            "[S] Demarrer la sauvegarde",
            "[Q] Quitter"
        )
    }
    else {
        # Interface simple sans module UI
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
        
        $choice = Read-Host "Votre choix"
    }
    
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
            
            Write-Log "Sauvegarde interactive terminee en $([math]::Round($duration.TotalMinutes, 1)) minutes ($($selectedCount - $errorCount) succes, $errorCount erreurs)"
            Write-Host ""
            Write-Host "========== SAUVEGARDE TERMINEE ==========" -ForegroundColor Green
            Write-Host "Dossier: $backupFolder" -ForegroundColor White
            Write-Host "Duree: $([math]::Round($duration.TotalMinutes, 1)) minutes" -ForegroundColor White
            Write-Host "Succes: $($selectedCount - $errorCount)/$selectedCount" -ForegroundColor $(if ($errorCount -eq 0) { "Green" } else { "Yellow" })
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
