<#
.SYNOPSIS
    Script de restauration des objets Active Directory
.DESCRIPTION
    Restaure les objets AD à partir des fichiers CSV de sauvegarde
#>

param(
    [Parameter(Mandatory)]
    [string]$BackupFolder,
    [string[]]$ObjectTypes = @("OUs", "Users", "Groups", "Computers", "Contacts", "GroupMemberships"),
    [switch]$RestoreGPOLinks
)

Import-Module ActiveDirectory -ErrorAction Stop

function Restore-ADOUs {
    param($CsvPath)
    
    Write-Output "Restauration des OUs..."
    Import-Csv $CsvPath | Sort-Object DistinguishedName | ForEach-Object {
        try {
            $ouPath = $_.DistinguishedName.Split(',', 2)[1]
            if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($_.DistinguishedName)'" -ErrorAction SilentlyContinue)) {
                New-ADOrganizationalUnit -Name $_.Name -Path $ouPath -Description $_.Description
                Write-Output "OU restaurée: $($_.Name)"
            }
        }
        catch {
            Write-Warning "Erreur lors de la restauration de l'OU $($_.Name): $($_.Exception.Message)"
        }
    }
}

function Restore-ADUsers {
    param($CsvPath)
    
    Write-Output "Restauration des utilisateurs..."
    Import-Csv $CsvPath | ForEach-Object {
        try {
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$($_.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                $userParams = @{
                    Name              = $_.Name
                    SamAccountName    = $_.SamAccountName
                    UserPrincipalName = $_.UserPrincipalName
                    Path              = $_.DistinguishedName.Split(',', 2)[1]
                    Enabled           = $false  # Désactivé par sécurité
                }
                
                if ($_.GivenName) { $userParams.GivenName = $_.GivenName }
                if ($_.Surname) { $userParams.Surname = $_.Surname }
                if ($_.DisplayName) { $userParams.DisplayName = $_.DisplayName }
                if ($_.Description) { $userParams.Description = $_.Description }
                if ($_.EmailAddress) { $userParams.EmailAddress = $_.EmailAddress }
                
                New-ADUser @userParams
                Write-Output "Utilisateur restauré: $($_.SamAccountName)"
            }
        }
        catch {
            Write-Warning "Erreur lors de la restauration de l'utilisateur $($_.SamAccountName): $($_.Exception.Message)"
        }
    }
}

function Restore-ADGroups {
    param($CsvPath)
    
    Write-Output "Restauration des groupes..."
    Import-Csv $CsvPath | ForEach-Object {
        try {
            if (-not (Get-ADGroup -Filter "SamAccountName -eq '$($_.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                $groupParams = @{
                    Name           = $_.Name
                    SamAccountName = $_.SamAccountName
                    GroupScope     = $_.GroupScope
                    Path           = $_.DistinguishedName.Split(',', 2)[1]
                }
                
                if ($_.Description) { $groupParams.Description = $_.Description }
                if ($_.GroupCategory) { $groupParams.GroupCategory = $_.GroupCategory }
                
                New-ADGroup @groupParams
                Write-Output "Groupe restauré: $($_.SamAccountName)"
            }
        }
        catch {
            Write-Warning "Erreur lors de la restauration du groupe $($_.SamAccountName): $($_.Exception.Message)"
        }
    }
}

function Restore-ADComputers {
    param($CsvPath)
    
    Write-Output "Restauration des ordinateurs..."
    Import-Csv $CsvPath | ForEach-Object {
        try {
            if (-not (Get-ADComputer -Filter "SamAccountName -eq '$($_.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                $computerParams = @{
                    Name           = $_.Name
                    SamAccountName = $_.SamAccountName
                    Path           = $_.DistinguishedName.Split(',', 2)[1]
                }
                
                if ($_.Description) { $computerParams.Description = $_.Description }
                
                New-ADComputer @computerParams
                Write-Output "Ordinateur restauré: $($_.SamAccountName)"
            }
        }
        catch {
            Write-Warning "Erreur lors de la restauration de l'ordinateur $($_.SamAccountName): $($_.Exception.Message)"
        }
    }
}

function Restore-GroupMemberships {
    param($CsvPath)
    
    Write-Output "Restauration des appartenances aux groupes..."
    Import-Csv $CsvPath | ForEach-Object {
        try {
            $group = Get-ADGroup -Filter "SamAccountName -eq '$($_.GroupName)'" -ErrorAction SilentlyContinue
            $member = Get-ADObject -Filter "SamAccountName -eq '$($_.MemberName)'" -ErrorAction SilentlyContinue
            
            if ($group -and $member) {
                Add-ADGroupMember -Identity $group -Members $member -ErrorAction SilentlyContinue
                Write-Output "Membre ajouté: $($_.MemberName) -> $($_.GroupName)"
            }
        }
        catch {
            Write-Warning "Erreur lors de l'ajout de $($_.MemberName) au groupe $($_.GroupName): $($_.Exception.Message)"
        }
    }
}

# Restauration des objets selon le type spécifié
foreach ($type in $ObjectTypes) {
    $csvFile = Join-Path $BackupFolder "$type.csv"
    if (Test-Path $csvFile) {
        Write-Output "Restauration des $type..."
        switch ($type) {
            "OUs" { Restore-ADOUs -CsvPath $csvFile }
            "Users" { Restore-ADUsers -CsvPath $csvFile }
            "Groups" { Restore-ADGroups -CsvPath $csvFile }
            "Computers" { Restore-ADComputers -CsvPath $csvFile }
            "GroupMemberships" { Restore-GroupMemberships -CsvPath $csvFile }
        }
    }
    else {
        Write-Warning "Fichier non trouvé: $csvFile"
    }
}

# Restauration des liens GPO si demandée
if ($RestoreGPOLinks) {
    $gpoLinksFile = Join-Path $BackupFolder "GPOLinks.csv"
    if (Test-Path $gpoLinksFile) {
        Write-Output "Restauration des liens GPO..."
        Import-Csv $gpoLinksFile | ForEach-Object {
            try {
                # Cette partie nécessiterait une logique plus complexe pour restaurer les liens GPO
                Write-Output "Lien GPO à restaurer: $($_.OUDN) -> $($_.GPOLink)"
            }
            catch {
                Write-Warning "Erreur lors de la restauration du lien GPO: $($_.Exception.Message)"
            }
        }
    }
}

Write-Output "Restauration terminée!"
