<#
.SYNOPSIS
    Planifie la sauvegarde automatique d'Active Directory
.DESCRIPTION
    Crée une tâche planifiée pour exécuter la sauvegarde AD quotidiennement
#>

param(
    [string]$TaskName = "AD-Backup-Daily",
    [string]$ScheduleTime = "02:00",
    [string]$ScriptPath = (Join-Path $PSScriptRoot "Backup-ActiveDirectory.ps1")
)

# Création de l'action
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`" -FullBackup"

# Création du déclencheur (quotidien à 2h du matin)
$trigger = New-ScheduledTaskTrigger -Daily -At $ScheduleTime

# Configuration de la tâche
$settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun

# Création de la tâche planifiée
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest

Write-Output "Tâche planifiée '$TaskName' créée avec succès pour s'exécuter quotidiennement à $ScheduleTime"
