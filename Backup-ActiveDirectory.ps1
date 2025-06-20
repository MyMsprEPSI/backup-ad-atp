<#
.SYNOPSIS
    Script de sauvegarde Active Directory
.DESCRIPTION
    Effectue une sauvegarde complète des objets AD et de la base de données système
.NOTES
    Nécessite des privilèges administrateur et le module ActiveDirectory
#>

param(
    [string]$BackupPath = "C:\ADBackup",
    [int]$RetentionDays = 30,
    [switch]$FullBackup
)

# Import du module Active Directory
Import-Module ActiveDirectory -ErrorAction Stop

# Configuration des chemins
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFolder = Join-Path $BackupPath $timestamp
$logFile = Join-Path $backupFolder "backup.log"

# Fonction de journalisation
function Write-Log {
    param($Message, $Level = "INFO")
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Write-Output $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

try {
    # Création du dossier de sauvegarde
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    Write-Log "Début de la sauvegarde AD dans $backupFolder"

    # Sauvegarde des utilisateurs
    Write-Log "Sauvegarde des utilisateurs..."
    Get-ADUser -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "Users.csv") -NoTypeInformation

    # Sauvegarde des groupes
    Write-Log "Sauvegarde des groupes..."
    Get-ADGroup -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "Groups.csv") -NoTypeInformation

    # Sauvegarde des unités organisationnelles
    Write-Log "Sauvegarde des OUs..."
    Get-ADOrganizationalUnit -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "OUs.csv") -NoTypeInformation

    # Sauvegarde des ordinateurs
    Write-Log "Sauvegarde des ordinateurs..."
    Get-ADComputer -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "Computers.csv") -NoTypeInformation

    # Sauvegarde des GPO (nécessite le module GroupPolicy)
    if (Get-Module -ListAvailable -Name GroupPolicy) {
        Write-Log "Sauvegarde des GPO..."
        Import-Module GroupPolicy
        $gpoBackupPath = Join-Path $backupFolder "GPOBackup"
        New-Item -Path $gpoBackupPath -ItemType Directory -Force | Out-Null
        Get-GPO -All | ForEach-Object {
            Backup-GPO -Name $_.DisplayName -Path $gpoBackupPath
        }
    }

    # Sauvegarde complète de la base de données AD (si demandée)
    if ($FullBackup) {
        Write-Log "Sauvegarde complète de la base de données AD..."
        $systemStateBackup = Join-Path $backupFolder "SystemState"
        wbadmin start systemstatebackup -backuptarget:$systemStateBackup -quiet
    }

    # Nettoyage des anciennes sauvegardes
    Write-Log "Nettoyage des sauvegardes anciennes (> $RetentionDays jours)..."
    Get-ChildItem -Path $BackupPath -Directory | 
    Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$RetentionDays) } |
    Remove-Item -Recurse -Force

    Write-Log "Sauvegarde terminée avec succès"
}
catch {
    Write-Log "Erreur lors de la sauvegarde: $($_.Exception.Message)" "ERROR"
    throw
}
