<#
.SYNOPSIS
    Script principal de sauvegarde Active Directory (version modulaire)
.DESCRIPTION
    Sauvegarde complete ou rapide de tous les objets AD essentiels
.AUTHOR
    Thibaut Maurras
.VERSION
    1.0
.DATE
    2025-01-20
.PREREQUISITES
    - Module ActiveDirectory
    - Privileges Administrateur
.EXAMPLE
    .\Backup-ActiveDirectory.ps1
    .\Backup-ActiveDirectory.ps1 -FullBackup -BackupPath "D:\Backups"
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Chemin de destination pour les sauvegardes")]
    [string]$BackupPath = "C:\ADBackup",
    
    [Parameter(HelpMessage = "Effectue une sauvegarde complete avec base de donnees")]
    [switch]$FullBackup
)

# Import des modules
$ModulePath = Join-Path $PSScriptRoot "..\Core"
Import-Module (Join-Path $ModulePath "ADBackupCore.psm1") -Force
Import-Module (Join-Path $ModulePath "BackupFunctions.psm1") -Force

# Configuration des chemins
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFolder = Join-Path $BackupPath $timestamp

try {
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    Initialize-ADBackupModule -BackupPath $backupFolder
}
catch {
    Write-Error "Impossible de creer le dossier de sauvegarde: $($_.Exception.Message)"
    exit 1
}

try {
    Write-ADLog "Debut de la sauvegarde AD dans $backupFolder"

    # Sauvegarde automatique des objets essentiels (ordre logique)
    Write-ADLog "=== SAUVEGARDE OBJETS ESSENTIELS ==="
    Backup-ADOUs -OutputPath $backupFolder
    Backup-ADUsers -OutputPath $backupFolder  
    Backup-ADGroups -OutputPath $backupFolder
    Backup-ADComputers -OutputPath $backupFolder
    Backup-ADGroupMemberships -OutputPath $backupFolder
    
    Write-ADLog "=== SAUVEGARDE OBJETS COMPLEMENTAIRES ==="
    Backup-ADContacts -OutputPath $backupFolder
    Backup-ADServiceAccounts -OutputPath $backupFolder
    Backup-ADDomainControllers -OutputPath $backupFolder
    
    Write-ADLog "=== SAUVEGARDE INFRASTRUCTURE ==="
    Backup-ADSites -OutputPath $backupFolder
    Backup-ADTrusts -OutputPath $backupFolder
    Backup-ADGPO -OutputPath $backupFolder

    # Sauvegarde complete de la base de donnees AD (si demandee)
    if ($FullBackup) {
        Write-ADLog "=== SAUVEGARDE COMPLETE BASE DE DONNEES ==="
        
        # Creation d'un dossier temporaire pour wbadmin
        $systemStateBackup = "C:\SystemStateBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        
        try {
            Write-ADLog "Demarrage de la sauvegarde systeme vers $systemStateBackup..."
            $wbResult = Start-Process -FilePath "wbadmin" -ArgumentList "start systemstatebackup -backuptarget:$systemStateBackup -quiet" -Wait -PassThru -NoNewWindow
            
            if ($wbResult.ExitCode -eq 0) {
                Write-ADLog "Sauvegarde systeme reussie"
                # Deplacer vers le dossier de sauvegarde principal
                $finalSystemStateBackup = Join-Path $backupFolder "SystemState"
                Move-Item $systemStateBackup $finalSystemStateBackup -Force -ErrorAction SilentlyContinue
                Write-ADLog "Sauvegarde systeme deplacee vers $finalSystemStateBackup"
            }
            else {
                Write-ADLog "Erreur sauvegarde systeme (code: $($wbResult.ExitCode)) - Sauvegarde alternative..." "WARNING"
                
                # Alternative: export des cles de registre importantes
                $ntdsBackup = Join-Path $backupFolder "NTDS_Manual"
                New-Item -Path $ntdsBackup -ItemType Directory -Force | Out-Null
                
                reg export "HKLM\SYSTEM\CurrentControlSet\Services\NTDS" (Join-Path $ntdsBackup "NTDS_Registry.reg") /y 2>$null
                reg export "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" (Join-Path $ntdsBackup "Netlogon_Registry.reg") /y 2>$null
                
                Write-ADLog "Sauvegarde manuelle NTDS terminee"
            }
        }
        catch {
            Write-ADLog "Erreur critique sauvegarde systeme: $($_.Exception.Message)" "ERROR"
        }
        finally {
            # Nettoyage
            if (Test-Path $systemStateBackup) {
                Remove-Item $systemStateBackup -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Creation du rapport de synthese
    Write-ADLog "=== CREATION RAPPORT DE SYNTHESE ==="
    $endTime = Get-Date
    $duration = $endTime - (Get-Date $timestamp)
    
    $summary = @{
        Date         = Get-Date
        BackupFolder = $backupFolder
        BackupType   = if ($FullBackup) { "Complete" } else { "Rapide" }
        Duration     = [math]::Round($duration.TotalMinutes, 2)
        FilesCreated = (Get-ChildItem $backupFolder -File -ErrorAction SilentlyContinue).Count
        TotalSize    = [math]::Round(((Get-ChildItem $backupFolder -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB), 2)
    }
    $summary | ConvertTo-Json | Out-File (Join-Path $backupFolder "BackupSummary.json") -Encoding UTF8
    
    # Nettoyage automatique (> 30 jours)
    Write-ADLog "=== NETTOYAGE AUTOMATIQUE ==="
    try {
        $cutoffDate = (Get-Date).AddDays(-30)
        $oldBackups = Get-ChildItem -Path $BackupPath -Directory | Where-Object { $_.CreationTime -lt $cutoffDate }
        foreach ($oldBackup in $oldBackups) {
            Remove-Item $oldBackup.FullName -Recurse -Force
            Write-ADLog "Suppression ancienne sauvegarde: $($oldBackup.Name)"
        }
    }
    catch {
        Write-ADLog "Erreur nettoyage: $($_.Exception.Message)" "WARNING"
    }
    
    Write-ADLog "=== SAUVEGARDE TERMINEE AVEC SUCCES ==="
    Write-ADLog "Dossier: $backupFolder"
    Write-ADLog "Duree: $([math]::Round($summary.Duration, 1)) minutes"
    Write-ADLog "Taille: $($summary.TotalSize) MB"
    
}
catch {
    Write-ADLog "ERREUR CRITIQUE: $($_.Exception.Message)" "ERROR"
    throw
}
