# FICHIER SUPPRIME - Utiliser Scripts\Restore-Interactive.ps1
Write-Host "Ce fichier est obsolete." -ForegroundColor Red
Write-Host "Utilisez: Scripts\Restore-Interactive.ps1" -ForegroundColor Yellow
exit 0
.SYNOPSIS
Script interactif de restauration selective Active Directory
.DESCRIPTION
Permet de choisir specifiquement quels objets AD restaurer depuis une sauvegarde
.NOTES
Necessite des privileges administrateur et le module ActiveDirectory
.AUTHOR
Thibaut Maurras
.VERSION
1.0
.DATE
2025 - 01 - 20
.PREREQUISITES
- Module ActiveDirectory
- Privileges Administrateur
- Fichiers de sauvegarde CSV
.EXAMPLE
.\Restore-Interactive.ps1
.\Restore-Interactive.ps1 -BackupPath "D:\Backups\AD"
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Chemin racine des sauvegardes")]
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

# Variables globales
$selectedBackupFolder = $null
$logFile = $null
$restoreOptions = @{
    "1" = @{ Name = "Unites Organisationnelles"; Selected = $false; Function = "Restore-OUs"; File = "OUs.csv" }
    "2" = @{ Name = "Utilisateurs"; Selected = $false; Function = "Restore-Users"; File = "Users.csv" }
    "3" = @{ Name = "Groupes"; Selected = $false; Function = "Restore-Groups"; File = "Groups.csv" }
    "4" = @{ Name = "Ordinateurs"; Selected = $false; Function = "Restore-Computers"; File = "Computers.csv" }
    "5" = @{ Name = "Membres des groupes"; Selected = $false; Function = "Restore-GroupMemberships"; File = "GroupMemberships.csv" }
    "6" = @{ Name = "Contacts"; Selected = $false; Function = "Restore-Contacts"; File = "Contacts.csv" }
}

<#
.SYNOPSIS
    Journalise les messages avec horodatage
.DESCRIPTION
    Ecrit les messages a la fois dans la console et dans le fichier de log
.PARAMETER Message
    Message a journaliser
.PARAMETER Level
    Niveau de log (INFO, WARNING, ERROR)
#>
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
    
    if ($logFile) {
        try {
            Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
        }
        catch {
            Write-Warning "Impossible d'ecrire dans le fichier de log: $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Affiche la liste des sauvegardes disponibles
.DESCRIPTION
    Scanne le dossier de sauvegarde et retourne les dossiers disponibles
#>
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
            }
            catch {
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

<#
.SYNOPSIS
    Affiche le menu de selection des elements a restaurer
#>
function Show-RestoreMenu {
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host "          RESTAURATION INTERACTIVE ACTIVE DIRECTORY" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Sauvegarde selectionnee: $(Split-Path $selectedBackupFolder -Leaf)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Selectionnez les elements a restaurer:" -ForegroundColor Cyan
    Write-Host ""
    
    # Verification des fichiers disponibles et affichage
    foreach ($key in ($restoreOptions.Keys | Sort-Object { [int]$_ })) {
        $option = $restoreOptions[$key]
        $filePath = Join-Path $selectedBackupFolder $option.File
        $fileExists = Test-Path $filePath
        
        $indicator = if ($option.Selected) { "[X]" } else { "[ ]" }
        $status = if ($fileExists) { "" } else { " (INDISPONIBLE)" }
        $color = if (-not $fileExists) { "DarkGray" } 
        elseif ($option.Selected) { "Green" } 
        else { "White" }
        
        Write-Host " $indicator [$key] $($option.Name)$status" -ForegroundColor $color
        
        if ($fileExists -and $option.Selected) {
            try {
                $itemCount = (Import-Csv $filePath).Count
                Write-Host "     -> $itemCount elements a restaurer" -ForegroundColor Gray
            }
            catch {
                Write-Host "     -> Erreur lecture fichier" -ForegroundColor Red
            }
        }
    }
    
    Write-Host ""
    Write-Host " [A] TOUT selectionner/deselectionner" -ForegroundColor Green
    Write-Host " [V] Verifier les elements selectionnees" -ForegroundColor Magenta
    Write-Host " [S] Demarrer la restauration" -ForegroundColor Green
    Write-Host " [B] Retour selection sauvegarde" -ForegroundColor Yellow
    Write-Host " [Q] Quitter" -ForegroundColor Red
    Write-Host ""
}

<#
.SYNOPSIS
    Verifie les conflits potentiels avant restauration
#>
function Test-RestoreConflicts {
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor Magenta
    Write-Host "              VERIFICATION DES CONFLITS" -ForegroundColor Magenta
    Write-Host "===============================================================" -ForegroundColor Magenta
    Write-Host ""
    
    $conflicts = @()
    
    foreach ($key in $restoreOptions.Keys) {
        if ($restoreOptions[$key].Selected) {
            $filePath = Join-Path $selectedBackupFolder $restoreOptions[$key].File
            if (Test-Path $filePath) {
                try {
                    $items = Import-Csv $filePath
                    Write-Host "Verification: $($restoreOptions[$key].Name)..." -ForegroundColor White
                    
                    switch ($key) {
                        "1" {
                            # OUs
                            foreach ($item in $items) {
                                if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($item.DistinguishedName)'" -ErrorAction SilentlyContinue) {
                                    $conflicts += "OU existante: $($item.Name)"
                                }
                            }
                        }
                        "2" {
                            # Users
                            foreach ($item in $items) {
                                if (Get-ADUser -Filter "SamAccountName -eq '$($item.SamAccountName)'" -ErrorAction SilentlyContinue) {
                                    $conflicts += "Utilisateur existant: $($item.SamAccountName)"
                                }
                            }
                        }
                        "3" {
                            # Groups
                            foreach ($item in $items) {
                                if (Get-ADGroup -Filter "SamAccountName -eq '$($item.SamAccountName)'" -ErrorAction SilentlyContinue) {
                                    $conflicts += "Groupe existant: $($item.SamAccountName)"
                                }
                            }
                        }
                        "4" {
                            # Computers
                            foreach ($item in $items) {
                                if (Get-ADComputer -Filter "SamAccountName -eq '$($item.SamAccountName)'" -ErrorAction SilentlyContinue) {
                                    $conflicts += "Ordinateur existant: $($item.SamAccountName)"
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Host "Erreur verification $($restoreOptions[$key].Name): $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
    
    if ($conflicts.Count -eq 0) {
        Write-Host "Aucun conflit detecte!" -ForegroundColor Green
    }
    else {
        Write-Host "ATTENTION: $($conflicts.Count) conflits detectes:" -ForegroundColor Red
        Write-Host ""
        foreach ($conflict in $conflicts[0..9]) {
            # Limite a 10 pour l'affichage
            Write-Host "  - $conflict" -ForegroundColor Yellow
        }
        if ($conflicts.Count -gt 10) {
            Write-Host "  ... et $($conflicts.Count - 10) autres conflits" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "Les objets existants seront ignores lors de la restauration." -ForegroundColor Cyan
    }
    
    Write-Host ""
    Write-Host "Appuyez sur une touche pour continuer..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Fonctions de restauration specifiques
<#
.SYNOPSIS
    Restaure les unites organisationnelles
#>
function Restore-OUs {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Restauration des unites organisationnelles..."
        $filePath = Join-Path $selectedBackupFolder "OUs.csv"
        $ous = Import-Csv $filePath | Sort-Object @{Expression = { ($_.DistinguishedName -split ',').Count }; Ascending = $true }
        $restored = 0
        $skipped = 0
        
        foreach ($ou in $ous) {
            try {
                if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($ou.DistinguishedName)'" -ErrorAction SilentlyContinue)) {
                    $parentPath = ($ou.DistinguishedName -split ',', 2)[1]
                    New-ADOrganizationalUnit -Name $ou.Name -Path $parentPath -Description $ou.Description -ErrorAction Stop
                    $restored++
                    Write-Log "OU restauree: $($ou.Name)"
                }
                else {
                    $skipped++
                }
            }
            catch {
                Write-Log "Erreur restauration OU $($ou.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-Log "[$restored OUs restaurees, $skipped ignorees (existantes)]"
    }
    catch {
        Write-Log "Erreur lors de la restauration des OUs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Restaure les utilisateurs
#>
function Restore-Users {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Restauration des utilisateurs..."
        $filePath = Join-Path $selectedBackupFolder "Users.csv"
        $users = Import-Csv $filePath
        $restored = 0
        $skipped = 0
        
        foreach ($user in $users) {
            try {
                if (-not (Get-ADUser -Filter "SamAccountName -eq '$($user.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                    $userParams = @{
                        Name              = $user.Name
                        SamAccountName    = $user.SamAccountName
                        UserPrincipalName = $user.UserPrincipalName
                        Path              = ($user.DistinguishedName -split ',', 2)[1]
                        Enabled           = $false  # Desactive par securite
                        AccountPassword   = (ConvertTo-SecureString "TempPassword123!" -AsPlainText -Force)
                    }
                    
                    if ($user.GivenName) { $userParams.GivenName = $user.GivenName }
                    if ($user.Surname) { $userParams.Surname = $user.Surname }
                    if ($user.DisplayName) { $userParams.DisplayName = $user.DisplayName }
                    if ($user.Description) { $userParams.Description = $user.Description }
                    if ($user.EmailAddress) { $userParams.EmailAddress = $user.EmailAddress }
                    
                    New-ADUser @userParams -ErrorAction Stop
                    $restored++
                    Write-Log "Utilisateur restaure: $($user.SamAccountName)"
                }
                else {
                    $skipped++
                }
            }
            catch {
                Write-Log "Erreur restauration utilisateur $($user.SamAccountName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-Log "[$restored utilisateurs restaures, $skipped ignores (existants)]"
    }
    catch {
        Write-Log "Erreur lors de la restauration des utilisateurs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Restaure les groupes
#>
function Restore-Groups {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Restauration des groupes..."
        $filePath = Join-Path $selectedBackupFolder "Groups.csv"
        $groups = Import-Csv $filePath
        $restored = 0
        $skipped = 0
        
        foreach ($group in $groups) {
            try {
                if (-not (Get-ADGroup -Filter "SamAccountName -eq '$($group.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                    $groupParams = @{
                        Name           = $group.Name
                        SamAccountName = $group.SamAccountName
                        GroupScope     = $group.GroupScope
                        Path           = ($group.DistinguishedName -split ',', 2)[1]
                    }
                    
                    if ($group.Description) { $groupParams.Description = $group.Description }
                    if ($group.GroupCategory) { $groupParams.GroupCategory = $group.GroupCategory }
                    
                    New-ADGroup @groupParams -ErrorAction Stop
                    $restored++
                    Write-Log "Groupe restaure: $($group.SamAccountName)"
                }
                else {
                    $skipped++
                }
            }
            catch {
                Write-Log "Erreur restauration groupe $($group.SamAccountName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-Log "[$restored groupes restaures, $skipped ignores (existants)]"
    }
    catch {
        Write-Log "Erreur lors de la restauration des groupes: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Restaure les ordinateurs
#>
function Restore-Computers {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Restauration des ordinateurs..."
        $filePath = Join-Path $selectedBackupFolder "Computers.csv"
        $computers = Import-Csv $filePath
        $restored = 0
        $skipped = 0
        
        foreach ($computer in $computers) {
            try {
                if (-not (Get-ADComputer -Filter "SamAccountName -eq '$($computer.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                    $computerParams = @{
                        Name           = $computer.Name
                        SamAccountName = $computer.SamAccountName
                        Path           = ($computer.DistinguishedName -split ',', 2)[1]
                    }
                    
                    if ($computer.Description) { $computerParams.Description = $computer.Description }
                    
                    New-ADComputer @computerParams -ErrorAction Stop
                    $restored++
                    Write-Log "Ordinateur restaure: $($computer.SamAccountName)"
                }
                else {
                    $skipped++
                }
            }
            catch {
                Write-Log "Erreur restauration ordinateur $($computer.SamAccountName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-Log "[$restored ordinateurs restaures, $skipped ignores (existants)]"
    }
    catch {
        Write-Log "Erreur lors de la restauration des ordinateurs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Restaure les appartenances aux groupes
#>
function Restore-GroupMemberships {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Restauration des appartenances aux groupes..."
        $filePath = Join-Path $selectedBackupFolder "GroupMemberships.csv"
        $memberships = Import-Csv $filePath
        $restored = 0
        $skipped = 0
        
        foreach ($membership in $memberships) {
            try {
                $group = Get-ADGroup -Filter "SamAccountName -eq '$($membership.GroupName)'" -ErrorAction SilentlyContinue
                $member = Get-ADObject -Filter "SamAccountName -eq '$($membership.MemberName)'" -ErrorAction SilentlyContinue
                
                if ($group -and $member) {
                    $existingMember = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue | Where-Object { $_.SamAccountName -eq $membership.MemberName }
                    if (-not $existingMember) {
                        Add-ADGroupMember -Identity $group -Members $member -ErrorAction Stop
                        $restored++
                        Write-Log "Membre ajoute: $($membership.MemberName) -> $($membership.GroupName)"
                    }
                    else {
                        $skipped++
                    }
                }
                else {
                    Write-Log "Groupe ou membre introuvable: $($membership.GroupName)/$($membership.MemberName)" "WARNING"
                }
            }
            catch {
                Write-Log "Erreur ajout membre $($membership.MemberName) au groupe $($membership.GroupName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-Log "[$restored appartenances restaurees, $skipped ignorees]"
    }
    catch {
        Write-Log "Erreur lors de la restauration des appartenances: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Restaure les contacts
#>
function Restore-Contacts {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Restauration des contacts..."
        $filePath = Join-Path $selectedBackupFolder "Contacts.csv"
        $contacts = Import-Csv $filePath
        $restored = 0
        $skipped = 0
        
        foreach ($contact in $contacts) {
            try {
                if (-not (Get-ADObject -Filter "DistinguishedName -eq '$($contact.DistinguishedName)'" -ErrorAction SilentlyContinue)) {
                    New-ADObject -Name $contact.Name -Type contact -Path ($contact.DistinguishedName -split ',', 2)[1] -ErrorAction Stop
                    $restored++
                    Write-Log "Contact restaure: $($contact.Name)"
                }
                else {
                    $skipped++
                }
            }
            catch {
                Write-Log "Erreur restauration contact $($contact.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-Log "[$restored contacts restaures, $skipped ignores]"
    }
    catch {
        Write-Log "Erreur lors de la restauration des contacts: $($_.Exception.Message)" "ERROR"
        throw
    }
}

# Boucle principale
Write-Host "===============================================================" -ForegroundColor Yellow
Write-Host "          RESTAURATION INTERACTIVE ACTIVE DIRECTORY" -ForegroundColor Yellow
Write-Host "===============================================================" -ForegroundColor Yellow

# Selection de la sauvegarde
$selectedBackupFolder = Show-AvailableBackups
if (-not $selectedBackupFolder) {
    Write-Host "Aucune sauvegarde selectionnee. Arret du script." -ForegroundColor Yellow
    exit 0
}

# Creation du fichier de log pour cette session
$logFile = Join-Path $selectedBackupFolder "restore_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Write-Log "Debut de la restauration interactive depuis $selectedBackupFolder"

# Variables pour la boucle principale
$allSelected = $false
$validNumericOptions = $restoreOptions.Keys
$validSpecialOptions = @("A", "V", "S", "B", "Q")
$allValidOptions = $validNumericOptions + $validSpecialOptions

do {
    try {
        Show-RestoreMenu
        
        # Affichage du compteur de selections
        $selectedCount = ($restoreOptions.Values | Where-Object { $_.Selected }).Count
        $availableCount = ($restoreOptions.Values | Where-Object { Test-Path (Join-Path $selectedBackupFolder $_.File) }).Count
        Write-Host "Elements selectionnes: $selectedCount/$availableCount (disponibles)" -ForegroundColor Cyan
        Write-Host ""
        
        $choice = Read-Host "Votre choix"
        
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
            "V" {
                # Verification des conflits
                if ($selectedCount -eq 0) {
                    Write-Host "Aucun element selectionne!" -ForegroundColor Red
                    Start-Sleep 2
                }
                else {
                    Test-RestoreConflicts
                }
            }
            "S" {
                # Demarrer la restauration
                if ($selectedCount -eq 0) {
                    Write-Host "Aucun element selectionne pour la restauration!" -ForegroundColor Red
                    Start-Sleep 2
                }
                else {
                    Write-Host ""
                    Write-Host "ATTENTION: La restauration va modifier Active Directory!" -ForegroundColor Red
                    Write-Host "Etes-vous sur de vouloir continuer? (O/N): " -ForegroundColor Yellow -NoNewline
                    $confirm = Read-Host
                    
                    if ($confirm.ToUpper() -eq "O") {
                        Write-Host "Demarrage de la restauration de $selectedCount elements..." -ForegroundColor Green
                        $startTime = Get-Date
                        $errorCount = 0
                        
                        foreach ($key in ($restoreOptions.Keys | Sort-Object { [int]$_ })) {
                            if ($restoreOptions[$key].Selected) {
                                try {
                                    Write-Progress -Activity "Restauration en cours" -Status "Traitement: $($restoreOptions[$key].Name)" -PercentComplete ((([int]$key) / ($restoreOptions.Count)) * 100)
                                    & $restoreOptions[$key].Function
                                }
                                catch {
                                    $errorCount++
                                    Write-Log "Erreur lors de la restauration de $($restoreOptions[$key].Name): $($_.Exception.Message)" "ERROR"
                                }
                            }
                        }
                        Write-Progress -Activity "Restauration en cours" -Completed
                        
                        $endTime = Get-Date
                        $duration = $endTime - $startTime
                        
                        Write-Log "Restauration interactive terminee en $([math]::Round($duration.TotalMinutes, 1)) minutes ($($selectedCount - $errorCount) succes, $errorCount erreurs)"
                        Write-Host ""
                        Write-Host "========== RESTAURATION TERMINEE ==========" -ForegroundColor Green
                        Write-Host "Duree: $([math]::Round($duration.TotalMinutes, 1)) minutes" -ForegroundColor White
                        Write-Host "Succes: $($selectedCount - $errorCount)/$selectedCount" -ForegroundColor $(if ($errorCount -eq 0) { "Green" } else { "Yellow" })
                        Write-Host "Fichier de log: $logFile" -ForegroundColor White
                        Write-Host "==========================================" -ForegroundColor Green
                        Write-Host ""
                        Write-Host "Appuyez sur une touche pour continuer..." -ForegroundColor Yellow
                        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        return
                    }
                    else {
                        Write-Host "Restauration annulee." -ForegroundColor Yellow
                        Start-Sleep 1
                    }
                }
            }
            "B" {
                # Retour selection sauvegarde
                $selectedBackupFolder = Show-AvailableBackups
                if (-not $selectedBackupFolder) {
                    Write-Host "Aucune sauvegarde selectionnee. Arret du script." -ForegroundColor Yellow
                    return
                }
                # Reset des selections
                foreach ($key in $restoreOptions.Keys) {
                    $restoreOptions[$key].Selected = $false
                }
                $logFile = Join-Path $selectedBackupFolder "restore_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                Write-Log "Changement de sauvegarde vers $selectedBackupFolder"
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
                    }
                    else {
                        Write-Host "Fichier de sauvegarde non disponible pour: $($restoreOptions[$choice].Name)" -ForegroundColor Red
                        Start-Sleep 2
                    }
                }
                else {
                    Write-Host "Choix invalide!" -ForegroundColor Red
                    Start-Sleep 1
                }
            }
        }
    }
    catch {
        Write-Log "Erreur inattendue dans la boucle principale: $($_.Exception.Message)" "ERROR"
        Write-Host "Une erreur s'est produite. Consultez le fichier de log pour plus de details." -ForegroundColor Red
        Start-Sleep 3
    }
} while ($true)
