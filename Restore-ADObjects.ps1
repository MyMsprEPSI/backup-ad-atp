<#
.SYNOPSIS
    Script de restauration des objets Active Directory
.DESCRIPTION
    Restaure les objets AD à partir des fichiers CSV de sauvegarde
#>

param(
    [Parameter(Mandatory)]
    [string]$BackupFolder,
    [string[]]$ObjectTypes = @("Users", "Groups", "OUs", "Computers")
)

Import-Module ActiveDirectory -ErrorAction Stop

function Restore-ADUsers {
    param($CsvPath)
    
    Import-Csv $CsvPath | ForEach-Object {
        try {
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$($_.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                New-ADUser -Name $_.Name -SamAccountName $_.SamAccountName -UserPrincipalName $_.UserPrincipalName -Path $_.DistinguishedName.Split(',', 2)[1]
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
    
    Import-Csv $CsvPath | ForEach-Object {
        try {
            if (-not (Get-ADGroup -Filter "SamAccountName -eq '$($_.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                New-ADGroup -Name $_.Name -SamAccountName $_.SamAccountName -GroupScope $_.GroupScope -Path $_.DistinguishedName.Split(',', 2)[1]
                Write-Output "Groupe restauré: $($_.SamAccountName)"
            }
        }
        catch {
            Write-Warning "Erreur lors de la restauration du groupe $($_.SamAccountName): $($_.Exception.Message)"
        }
    }
}

# Restauration des objets selon le type spécifié
foreach ($type in $ObjectTypes) {
    $csvFile = Join-Path $BackupFolder "$type.csv"
    if (Test-Path $csvFile) {
        Write-Output "Restauration des $type..."
        switch ($type) {
            "Users" { Restore-ADUsers -CsvPath $csvFile }
            "Groups" { Restore-ADGroups -CsvPath $csvFile }
        }
    }
}
