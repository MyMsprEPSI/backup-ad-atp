<#
.SYNOPSIS
    Module contenant les fonctions de restauration AD
#>

# Import du module principal
Import-Module (Join-Path $PSScriptRoot "ADBackupCore.psm1") -Force

<#
.SYNOPSIS
    Restaure les unites organisationnelles
#>
function Restore-ADOUs {
    [CmdletBinding()]
    param([string]$BackupPath)
    
    try {
        Write-ADLog "Restauration des unites organisationnelles..."
        $filePath = Join-Path $BackupPath "OUs.csv"
        
        if (-not (Test-Path $filePath)) {
            Write-ADLog "Fichier OUs.csv non trouve" "WARNING"
            return @{ Restored = 0; Skipped = 0 }
        }
        
        $ous = Import-Csv $filePath | Sort-Object @{Expression={($_.DistinguishedName -split ',').Count}; Ascending=$true}
        $restored = 0
        $skipped = 0
        
        foreach ($ou in $ous) {
            try {
                if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($ou.DistinguishedName)'" -ErrorAction SilentlyContinue)) {
                    $parentPath = ($ou.DistinguishedName -split ',', 2)[1]
                    New-ADOrganizationalUnit -Name $ou.Name -Path $parentPath -Description $ou.Description -ErrorAction Stop
                    $restored++
                    Write-ADLog "OU restauree: $($ou.Name)"
                } else {
                    $skipped++
                }
            } catch {
                Write-ADLog "Erreur restauration OU $($ou.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-ADLog "[$restored OUs restaurees, $skipped ignorees]"
        return @{ Restored = $restored; Skipped = $skipped }
    } catch {
        Write-ADLog "Erreur restauration OUs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Restaure les utilisateurs
#>
function Restore-ADUsers {
    [CmdletBinding()]
    param([string]$BackupPath)
    
    try {
        Write-ADLog "Restauration des utilisateurs..."
        $filePath = Join-Path $BackupPath "Users.csv"
        
        if (-not (Test-Path $filePath)) {
            Write-ADLog "Fichier Users.csv non trouve" "WARNING"
            return @{ Restored = 0; Skipped = 0 }
        }
        
        $users = Import-Csv $filePath
        $restored = 0
        $skipped = 0
        
        foreach ($user in $users) {
            try {
                if (-not (Get-ADUser -Filter "SamAccountName -eq '$($user.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                    $userParams = @{
                        Name = $user.Name
                        SamAccountName = $user.SamAccountName
                        UserPrincipalName = $user.UserPrincipalName
                        Path = ($user.DistinguishedName -split ',', 2)[1]
                        Enabled = $false
                        AccountPassword = (ConvertTo-SecureString "TempPassword123!" -AsPlainText -Force)
                    }
                    
                    if ($user.GivenName) { $userParams.GivenName = $user.GivenName }
                    if ($user.Surname) { $userParams.Surname = $user.Surname }
                    if ($user.DisplayName) { $userParams.DisplayName = $user.DisplayName }
                    if ($user.Description) { $userParams.Description = $user.Description }
                    if ($user.EmailAddress) { $userParams.EmailAddress = $user.EmailAddress }
                    
                    New-ADUser @userParams -ErrorAction Stop
                    $restored++
                    Write-ADLog "Utilisateur restaure: $($user.SamAccountName)"
                } else {
                    $skipped++
                }
            } catch {
                Write-ADLog "Erreur restauration utilisateur $($user.SamAccountName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-ADLog "[$restored utilisateurs restaures, $skipped ignores]"
        return @{ Restored = $restored; Skipped = $skipped }
    } catch {
        Write-ADLog "Erreur restauration utilisateurs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Restaure les groupes
#>
function Restore-ADGroups {
    [CmdletBinding()]
    param([string]$BackupPath)
    
    try {
        Write-ADLog "Restauration des groupes..."
        $filePath = Join-Path $BackupPath "Groups.csv"
        
        if (-not (Test-Path $filePath)) {
            Write-ADLog "Fichier Groups.csv non trouve" "WARNING"
            return @{ Restored = 0; Skipped = 0 }
        }
        
        $groups = Import-Csv $filePath
        $restored = 0
        $skipped = 0
        
        foreach ($group in $groups) {
            try {
                if (-not (Get-ADGroup -Filter "SamAccountName -eq '$($group.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                    $groupParams = @{
                        Name = $group.Name
                        SamAccountName = $group.SamAccountName
                        GroupScope = $group.GroupScope
                        Path = ($group.DistinguishedName -split ',', 2)[1]
                    }
                    
                    if ($group.Description) { $groupParams.Description = $group.Description }
                    if ($group.GroupCategory) { $groupParams.GroupCategory = $group.GroupCategory }
                    
                    New-ADGroup @groupParams -ErrorAction Stop
                    $restored++
                    Write-ADLog "Groupe restaure: $($group.SamAccountName)"
                } else {
                    $skipped++
                }
            } catch {
                Write-ADLog "Erreur restauration groupe $($group.SamAccountName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-ADLog "[$restored groupes restaures, $skipped ignores]"
        return @{ Restored = $restored; Skipped = $skipped }
    } catch {
        Write-ADLog "Erreur restauration groupes: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Restaure les ordinateurs
#>
function Restore-ADComputers {
    [CmdletBinding()]
    param([string]$BackupPath)
    
    try {
        Write-ADLog "Restauration des ordinateurs..."
        $filePath = Join-Path $BackupPath "Computers.csv"
        
        if (-not (Test-Path $filePath)) {
            Write-ADLog "Fichier Computers.csv non trouve" "WARNING"
            return @{ Restored = 0; Skipped = 0 }
        }
        
        $computers = Import-Csv $filePath
        $restored = 0
        $skipped = 0
        
        foreach ($computer in $computers) {
            try {
                if (-not (Get-ADComputer -Filter "SamAccountName -eq '$($computer.SamAccountName)'" -ErrorAction SilentlyContinue)) {
                    $computerParams = @{
                        Name = $computer.Name
                        SamAccountName = $computer.SamAccountName
                        Path = ($computer.DistinguishedName -split ',', 2)[1]
                    }
                    
                    if ($computer.Description) { $computerParams.Description = $computer.Description }
                    
                    New-ADComputer @computerParams -ErrorAction Stop
                    $restored++
                    Write-ADLog "Ordinateur restaure: $($computer.SamAccountName)"
                } else {
                    $skipped++
                }
            } catch {
                Write-ADLog "Erreur restauration ordinateur $($computer.SamAccountName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-ADLog "[$restored ordinateurs restaures, $skipped ignores]"
        return @{ Restored = $restored; Skipped = $skipped }
    } catch {
        Write-ADLog "Erreur restauration ordinateurs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Restaure les appartenances aux groupes
#>
function Restore-ADGroupMemberships {
    [CmdletBinding()]
    param([string]$BackupPath)
    
    try {
        Write-ADLog "Restauration des appartenances aux groupes..."
        $filePath = Join-Path $BackupPath "GroupMemberships.csv"
        
        if (-not (Test-Path $filePath)) {
            Write-ADLog "Fichier GroupMemberships.csv non trouve" "WARNING"
            return @{ Restored = 0; Skipped = 0 }
        }
        
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
                        Write-ADLog "Membre ajoute: $($membership.MemberName) -> $($membership.GroupName)"
                    } else {
                        $skipped++
                    }
                } else {
                    Write-ADLog "Groupe ou membre introuvable: $($membership.GroupName)/$($membership.MemberName)" "WARNING"
                }
            } catch {
                Write-ADLog "Erreur ajout membre $($membership.MemberName) au groupe $($membership.GroupName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-ADLog "[$restored appartenances restaurees, $skipped ignorees]"
        return @{ Restored = $restored; Skipped = $skipped }
    } catch {
        Write-ADLog "Erreur restauration appartenances: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Restaure les contacts
#>
function Restore-ADContacts {
    [CmdletBinding()]
    param([string]$BackupPath)
    
    try {
        Write-ADLog "Restauration des contacts..."
        $filePath = Join-Path $BackupPath "Contacts.csv"
        
        if (-not (Test-Path $filePath)) {
            Write-ADLog "Fichier Contacts.csv non trouve" "WARNING"
            return @{ Restored = 0; Skipped = 0 }
        }
        
        $contacts = Import-Csv $filePath
        $restored = 0
        $skipped = 0
        
        foreach ($contact in $contacts) {
            try {
                if (-not (Get-ADObject -Filter "DistinguishedName -eq '$($contact.DistinguishedName)'" -ErrorAction SilentlyContinue)) {
                    New-ADObject -Name $contact.Name -Type contact -Path ($contact.DistinguishedName -split ',', 2)[1] -ErrorAction Stop
                    $restored++
                    Write-ADLog "Contact restaure: $($contact.Name)"
                } else {
                    $skipped++
                }
            } catch {
                Write-ADLog "Erreur restauration contact $($contact.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-ADLog "[$restored contacts restaures, $skipped ignores]"
        return @{ Restored = $restored; Skipped = $skipped }
    } catch {
        Write-ADLog "Erreur restauration contacts: $($_.Exception.Message)" "ERROR"
        throw
    }
}

Export-ModuleMember -Function Restore-AD*
