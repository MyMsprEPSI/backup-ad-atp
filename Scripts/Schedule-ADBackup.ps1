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

<#
.SYNOPSIS
    Cree une nouvelle tache planifiee
#>
function New-ADBackupTask {
    Write-Host "===============================================================" -ForegroundColor Green
    Write-Host "              CREATION NOUVELLE TACHE PLANIFIEE" -ForegroundColor Green
    Write-Host "===============================================================" -ForegroundColor Green
    Write-Host ""
    
    # Collecte des parametres
    $taskName = Read-Host "Nom de la tache (defaut: AD-Backup-Auto)"
    if ([string]::IsNullOrEmpty($taskName)) { $taskName = "AD-Backup-Auto" }
    
    Write-Host ""
    Write-Host "Types de sauvegarde disponibles:"
    Write-Host " [1] Rapide (utilisateurs, groupes, OUs, ordinateurs)"
    Write-Host " [2] Complete (avec base de donnees systeme)"
    Write-Host " [3] Interactive (preset complet)"
    $backupChoice = Read-Host "Choisissez le type (1-3)"
    
    $scriptToRun = switch ($backupChoice) {
        "1" { "Scripts\Backup-ActiveDirectory.ps1" }
        "2" { "Scripts\Backup-ActiveDirectory.ps1 -FullBackup" }
        "3" { "Scripts\Backup-Interactive.ps1" }
        default { "Scripts\Backup-ActiveDirectory.ps1" }
    }
    
    Write-Host ""
    Write-Host "Frequences disponibles:"
    Write-Host " [1] Quotidienne"
    Write-Host " [2] Hebdomadaire"
    Write-Host " [3] Mensuelle"
    $freqChoice = Read-Host "Choisissez la frequence (1-3)"
    
    $time = Read-Host "Heure d'execution (format HH:mm, defaut: 02:00)"
    if ([string]::IsNullOrEmpty($time)) { $time = "02:00" }
    
    # Parametres specifiques selon la frequence
    $trigger = $null
    switch ($freqChoice) {
        "1" {
            $trigger = New-ScheduledTaskTrigger -Daily -At $time
        }
        "2" {
            Write-Host "Jours de la semaine: Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday"
            $day = Read-Host "Jour de la semaine (defaut: Sunday)"
            if ([string]::IsNullOrEmpty($day)) { $day = "Sunday" }
            $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $day -At $time
        }
        "3" {
            $dayNum = Read-Host "Jour du mois (1-31, defaut: 1)"
            if ([string]::IsNullOrEmpty($dayNum)) { $dayNum = 1 }
            $trigger = New-ScheduledTaskTrigger -Daily -At $time
        }
        default {
            $trigger = New-ScheduledTaskTrigger -Daily -At $time
        }
    }
    
    try {
        # Creation de l'action avec chemin correct
        $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) $scriptToRun
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        
        # Configuration de la tache
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -WakeToRun
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Enregistrement de la tache
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Sauvegarde automatique Active Directory - Cree le $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        
        Write-Host ""
        Write-Host "Tache '$taskName' creee avec succes!" -ForegroundColor Green
        Write-Host "Prochaine execution: $((Get-ScheduledTask -TaskName $taskName | Get-ScheduledTaskInfo).NextRunTime)" -ForegroundColor Cyan
        
    }
    catch {
        Write-Host "Erreur lors de la creation de la tache: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    Read-Host "Appuyez sur Entree pour continuer"
}

<#
.SYNOPSIS
    Affiche les taches AD existantes
#>
function Show-ExistingTasks {
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "                TACHES PLANIFIEES EXISTANTES" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        $adTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*AD*" -or $_.TaskName -like "*Backup*" -or $_.Description -like "*Active Directory*" }
        
        if ($adTasks.Count -eq 0) {
            Write-Host "Aucune tache de sauvegarde AD trouvee." -ForegroundColor Yellow
        }
        else {
            foreach ($task in $adTasks) {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName
                $trigger = (Get-ScheduledTask -TaskName $task.TaskName).Triggers[0]
                
                Write-Host "Nom: $($task.TaskName)" -ForegroundColor White
                Write-Host "Etat: $($task.State)" -ForegroundColor $(if ($task.State -eq "Ready") { "Green" } else { "Red" })
                Write-Host "Derniere execution: $($taskInfo.LastRunTime)" -ForegroundColor Gray
                Write-Host "Prochaine execution: $($taskInfo.NextRunTime)" -ForegroundColor Gray
                Write-Host "Dernier resultat: $($taskInfo.LastTaskResult)" -ForegroundColor $(if ($taskInfo.LastTaskResult -eq 0) { "Green" } else { "Red" })
                
                if ($trigger) {
                    Write-Host "Declencheur: $($trigger.CimClass.CimClassName)" -ForegroundColor Gray
                    if ($trigger.StartBoundary) {
                        Write-Host "Heure: $($trigger.StartBoundary.ToString('HH:mm'))" -ForegroundColor Gray
                    }
                }
                
                Write-Host "Description: $($task.Description)" -ForegroundColor Gray
                Write-Host "----------------------------------------" -ForegroundColor DarkGray
            }
        }
        
    }
    catch {
        Write-Host "Erreur lors de la recuperation des taches: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    Read-Host "Appuyez sur Entree pour continuer"
}

<#
.SYNOPSIS
    Supprime une tache planifiee
#>
function Remove-ADBackupTask {
    Write-Host "===============================================================" -ForegroundColor Red
    Write-Host "                SUPPRESSION TACHE PLANIFIEE" -ForegroundColor Red
    Write-Host "===============================================================" -ForegroundColor Red
    Write-Host ""
    
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*AD*" -or $_.TaskName -like "*Backup*" }
        
        if ($tasks.Count -eq 0) {
            Write-Host "Aucune tache de sauvegarde trouvee." -ForegroundColor Yellow
            return
        }
        
        Write-Host "Taches disponibles pour suppression:"
        for ($i = 0; $i -lt $tasks.Count; $i++) {
            Write-Host " [$($i + 1)] $($tasks[$i].TaskName) - $($tasks[$i].State)" -ForegroundColor White
        }
        
        Write-Host ""
        $choice = Read-Host "Numero de la tache a supprimer (0 pour annuler)"
        
        if ($choice -eq "0" -or $choice -eq "") {
            Write-Host "Suppression annulee." -ForegroundColor Yellow
            return
        }
        
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $tasks.Count) {
            $taskToDelete = $tasks[[int]$choice - 1]
            
            Write-Host ""
            Write-Host "ATTENTION: Vous allez supprimer la tache '$($taskToDelete.TaskName)'" -ForegroundColor Red
            $confirm = Read-Host "Etes-vous sur? (O/N)"
            
            if ($confirm.ToUpper() -eq "O") {
                Unregister-ScheduledTask -TaskName $taskToDelete.TaskName -Confirm:$false
                Write-Host "Tache '$($taskToDelete.TaskName)' supprimee avec succes!" -ForegroundColor Green
            }
            else {
                Write-Host "Suppression annulee." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "Choix invalide!" -ForegroundColor Red
        }
        
    }
    catch {
        Write-Host "Erreur lors de la suppression: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    Read-Host "Appuyez sur Entree pour continuer"
}

<#
.SYNOPSIS
    Execute une tache immediatement pour test
#>
function Start-ADBackupTask {
    Write-Host "===============================================================" -ForegroundColor Magenta
    Write-Host "                TEST EXECUTION IMMEDIATE" -ForegroundColor Magenta
    Write-Host "===============================================================" -ForegroundColor Magenta
    Write-Host ""
    
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*AD*" -or $_.TaskName -like "*Backup*" }
        
        if ($tasks.Count -eq 0) {
            Write-Host "Aucune tache de sauvegarde trouvee." -ForegroundColor Yellow
            return
        }
        
        Write-Host "Taches disponibles pour test:"
        for ($i = 0; $i -lt $tasks.Count; $i++) {
            Write-Host " [$($i + 1)] $($tasks[$i].TaskName) - $($tasks[$i].State)" -ForegroundColor White
        }
        
        Write-Host ""
        $choice = Read-Host "Numero de la tache a executer (0 pour annuler)"
        
        if ($choice -eq "0" -or $choice -eq "") {
            Write-Host "Execution annulee." -ForegroundColor Yellow
            return
        }
        
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $tasks.Count) {
            $taskToRun = $tasks[[int]$choice - 1]
            
            Write-Host ""
            Write-Host "Demarrage de la tache '$($taskToRun.TaskName)'..." -ForegroundColor Green
            Start-ScheduledTask -TaskName $taskToRun.TaskName
            
            Write-Host "Tache demarree. Verifiez l'etat dans quelques minutes." -ForegroundColor Green
            
        }
        else {
            Write-Host "Choix invalide!" -ForegroundColor Red
        }
        
    }
    catch {
        Write-Host "Erreur lors de l'execution: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    Read-Host "Appuyez sur Entree pour continuer"
}

<#
.SYNOPSIS
    Active ou desactive une tache
#>
function Toggle-ADBackupTask {
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host "              ACTIVER/DESACTIVER TACHE PLANIFIEE" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*AD*" -or $_.TaskName -like "*Backup*" }
        
        if ($tasks.Count -eq 0) {
            Write-Host "Aucune tache de sauvegarde trouvee." -ForegroundColor Yellow
            return
        }
        
        Write-Host "Taches disponibles:"
        for ($i = 0; $i -lt $tasks.Count; $i++) {
            $status = if ($tasks[$i].State -eq "Ready") { "ACTIVE" } else { "INACTIVE" }
            $color = if ($tasks[$i].State -eq "Ready") { "Green" } else { "Red" }
            Write-Host " [$($i + 1)] $($tasks[$i].TaskName) - " -NoNewline -ForegroundColor White
            Write-Host $status -ForegroundColor $color
        }
        
        Write-Host ""
        $choice = Read-Host "Numero de la tache a modifier (0 pour annuler)"
        
        if ($choice -eq "0" -or $choice -eq "") {
            Write-Host "Operation annulee." -ForegroundColor Yellow
            return
        }
        
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $tasks.Count) {
            $taskToToggle = $tasks[[int]$choice - 1]
            
            if ($taskToToggle.State -eq "Ready") {
                Disable-ScheduledTask -TaskName $taskToToggle.TaskName -Confirm:$false
                Write-Host "Tache '$($taskToToggle.TaskName)' desactivee." -ForegroundColor Yellow
            }
            else {
                Enable-ScheduledTask -TaskName $taskToToggle.TaskName
                Write-Host "Tache '$($taskToToggle.TaskName)' activee." -ForegroundColor Green
            }
            
        }
        else {
            Write-Host "Choix invalide!" -ForegroundColor Red
        }
        
    }
    catch {
        Write-Host "Erreur lors de la modification: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    Read-Host "Appuyez sur Entree pour continuer"
}

# Boucle principale du menu
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
            "Q" { 
                Write-Host "Au revoir!" -ForegroundColor Green
                return 
            }
            default { 
                Write-Host "Choix invalide!" -ForegroundColor Red
                Start-Sleep 1
            }
        }
    }
    catch {
        Write-Host "Erreur inattendue: $($_.Exception.Message)" -ForegroundColor Red
        Start-Sleep 2
    }
} while ($true)
