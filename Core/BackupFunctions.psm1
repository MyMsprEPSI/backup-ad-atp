<#
.SYNOPSIS
    Module contenant les fonctions de sauvegarde AD
#>

# Import du module principal
Import-Module (Join-Path $PSScriptRoot "ADBackupCore.psm1") -Force

<#
.SYNOPSIS
    Sauvegarde les utilisateurs Active Directory
#>
function Backup-ADUsers {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des utilisateurs..."
        $users = Get-ADUser -Filter * -Properties * -ErrorAction Stop
        $users | Export-Csv -Path (Join-Path $OutputPath "Users.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($users.Count) utilisateurs sauvegardes]"
        return $users.Count
    }
    catch {
        Write-ADLog "Erreur sauvegarde utilisateurs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les groupes Active Directory
#>
function Backup-ADGroups {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des groupes..."
        $groups = Get-ADGroup -Filter * -Properties * -ErrorAction Stop
        $groups | Export-Csv -Path (Join-Path $OutputPath "Groups.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($groups.Count) groupes sauvegardes]"
        return $groups.Count
    }
    catch {
        Write-ADLog "Erreur sauvegarde groupes: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les unites organisationnelles
#>
function Backup-ADOUs {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des unites organisationnelles..."
        $ous = Get-ADOrganizationalUnit -Filter * -Properties * -ErrorAction Stop
        $ous | Export-Csv -Path (Join-Path $OutputPath "OUs.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($ous.Count) OUs sauvegardees]"
        return $ous.Count
    }
    catch {
        Write-ADLog "Erreur sauvegarde OUs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les ordinateurs
#>
function Backup-ADComputers {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des ordinateurs..."
        $computers = Get-ADComputer -Filter * -Properties * -ErrorAction Stop
        $computers | Export-Csv -Path (Join-Path $OutputPath "Computers.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($computers.Count) ordinateurs sauvegardes]"
        return $computers.Count
    }
    catch {
        Write-ADLog "Erreur sauvegarde ordinateurs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les serveurs
#>
function Backup-ADServers {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des serveurs..."
        $servers = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' -Properties * -ErrorAction Stop
        $servers | Export-Csv -Path (Join-Path $OutputPath "Servers.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($servers.Count) serveurs sauvegardes]"
        return $servers.Count
    }
    catch {
        Write-ADLog "Erreur sauvegarde serveurs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les controleurs de domaine
#>
function Backup-ADDomainControllers {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des controleurs de domaine..."
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
        $dcs | Export-Csv -Path (Join-Path $OutputPath "DomainControllers.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($dcs.Count) controleurs de domaine sauvegardes]"
        return $dcs.Count
    }
    catch {
        Write-ADLog "Erreur sauvegarde DCs: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les contacts
#>
function Backup-ADContacts {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des contacts..."
        $contacts = Get-ADObject -Filter 'ObjectClass -eq "contact"' -Properties * -ErrorAction Stop
        $contacts | Export-Csv -Path (Join-Path $OutputPath "Contacts.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($contacts.Count) contacts sauvegardes]"
        return $contacts.Count
    }
    catch {
        Write-ADLog "Erreur sauvegarde contacts: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les comptes de service
#>
function Backup-ADServiceAccounts {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des comptes de service..."
        $serviceAccounts = Get-ADServiceAccount -Filter * -Properties * -ErrorAction SilentlyContinue
        if ($serviceAccounts) {
            $serviceAccounts | Export-Csv -Path (Join-Path $OutputPath "ServiceAccounts.csv") -NoTypeInformation -Encoding UTF8
            Write-ADLog "[$($serviceAccounts.Count) comptes de service sauvegardes]"
            return $serviceAccounts.Count
        } else {
            Write-ADLog "[Aucun compte de service trouve]" "WARNING"
            return 0
        }
    }
    catch {
        Write-ADLog "Erreur sauvegarde comptes de service: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les membres de groupes
#>
function Backup-ADGroupMemberships {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des membres de groupes..."
        $groupMemberships = @()
        $groups = Get-ADGroup -Filter * -ErrorAction Stop
        $totalGroups = $groups.Count
        $currentGroup = 0
        
        foreach ($group in $groups) {
            $currentGroup++
            Write-Progress -Activity "Sauvegarde des appartenances" -Status "Groupe: $($group.Name)" -PercentComplete (($currentGroup / $totalGroups) * 100)
            
            Get-ADGroupMember -Identity $group.SamAccountName -ErrorAction SilentlyContinue | ForEach-Object {
                $groupMemberships += [PSCustomObject]@{
                    GroupName   = $group.SamAccountName
                    GroupDN     = $group.DistinguishedName
                    MemberName  = $_.SamAccountName
                    MemberDN    = $_.DistinguishedName
                    ObjectClass = $_.ObjectClass
                }
            }
        }
        Write-Progress -Activity "Sauvegarde des appartenances" -Completed
        $groupMemberships | Export-Csv -Path (Join-Path $OutputPath "GroupMemberships.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($groupMemberships.Count) relations d'appartenance sauvegardees]"
        return $groupMemberships.Count
    }
    catch {
        Write-ADLog "Erreur sauvegarde appartenances: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les sites et sous-reseaux
#>
function Backup-ADSites {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des sites et sous-reseaux..."
        
        # Sauvegarde des sites
        $sites = Get-ADReplicationSite -Filter * -Properties * -ErrorAction Stop
        $sites | Export-Csv -Path (Join-Path $OutputPath "Sites.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($sites.Count) sites sauvegardes]"
        
        # Sauvegarde des sous-reseaux
        $subnets = Get-ADReplicationSubnet -Filter * -Properties * -ErrorAction Stop
        $subnets | Export-Csv -Path (Join-Path $OutputPath "Subnets.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($subnets.Count) sous-reseaux sauvegardes]"
        
        return ($sites.Count + $subnets.Count)
    }
    catch {
        Write-ADLog "Erreur sauvegarde sites/sous-reseaux: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les trusts
#>
function Backup-ADTrusts {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des trusts..."
        $trusts = Get-ADTrust -Filter * -ErrorAction Stop
        $trusts | Export-Csv -Path (Join-Path $OutputPath "Trusts.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($trusts.Count) trusts sauvegardes]"
        return $trusts.Count
    }
    catch {
        Write-ADLog "Erreur sauvegarde trusts: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les GPO
#>
function Backup-ADGPO {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des GPO..."
        
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-ADLog "Module GroupPolicy non disponible" "WARNING"
            return 0
        }
        
        Import-Module GroupPolicy -ErrorAction Stop
        $gpoBackupPath = Join-Path $OutputPath "GPOBackup"
        New-Item -Path $gpoBackupPath -ItemType Directory -Force | Out-Null
        
        $gpos = Get-GPO -All -ErrorAction Stop
        $successCount = 0
        
        foreach ($gpo in $gpos) {
            try {
                Backup-GPO -Guid $gpo.Id -Path $gpoBackupPath -ErrorAction Stop | Out-Null
                Write-ADLog "GPO sauvegarde: $($gpo.DisplayName)"
                $successCount++
            }
            catch {
                Write-ADLog "Erreur GPO $($gpo.DisplayName): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-ADLog "[$successCount/$($gpos.Count) GPO sauvegardees]"
        return $successCount
    }
    catch {
        Write-ADLog "Erreur sauvegarde GPO: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde le schema AD
#>
function Backup-ADSchema {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde du schema AD..."
        $rootDSE = Get-ADRootDSE -ErrorAction Stop
        
        # Sauvegarde des attributs de schema
        $schemaAttributes = Get-ADObject -SearchBase $rootDSE.SchemaNamingContext -Filter 'ObjectClass -eq "attributeSchema"' -Properties * -ErrorAction Stop
        $schemaAttributes | Export-Csv -Path (Join-Path $OutputPath "SchemaAttributes.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($schemaAttributes.Count) attributs de schema sauvegardes]"
        
        # Sauvegarde des classes de schema
        $schemaClasses = Get-ADObject -SearchBase $rootDSE.SchemaNamingContext -Filter 'ObjectClass -eq "classSchema"' -Properties * -ErrorAction Stop
        $schemaClasses | Export-Csv -Path (Join-Path $OutputPath "SchemaClasses.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($schemaClasses.Count) classes de schema sauvegardees]"
        
        return ($schemaAttributes.Count + $schemaClasses.Count)
    }
    catch {
        Write-ADLog "Erreur sauvegarde schema: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les liens de replication
#>
function Backup-ADReplication {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des liens de replication..."
        $replConnections = Get-ADReplicationConnection -Filter * -ErrorAction Stop
        $replConnections | Export-Csv -Path (Join-Path $OutputPath "ReplicationConnections.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($replConnections.Count) liens de replication sauvegardes]"
        return $replConnections.Count
    }
    catch {
        Write-ADLog "Erreur sauvegarde replication: $($_.Exception.Message)" "ERROR"
        throw
    }
}

<#
.SYNOPSIS
    Sauvegarde les modeles de certificats
#>
function Backup-ADCertificates {
    [CmdletBinding()]
    param([string]$OutputPath)
    
    try {
        Write-ADLog "Sauvegarde des modeles de certificats..."
        $rootDSE = Get-ADRootDSE -ErrorAction Stop
        $certTemplatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.ConfigurationNamingContext)"
        
        $certTemplates = Get-ADObject -SearchBase $certTemplatesPath -Filter * -Properties * -ErrorAction Stop
        $certTemplates | Export-Csv -Path (Join-Path $OutputPath "CertificateTemplates.csv") -NoTypeInformation -Encoding UTF8
        Write-ADLog "[$($certTemplates.Count) modeles de certificats sauvegardes]"
        return $certTemplates.Count
    }
    catch {
        if ($_.Exception.Message -like "*objet introuvable*" -or $_.Exception.Message -like "*not found*") {
            Write-ADLog "Aucun modele de certificat trouve (PKI non deploye)" "WARNING"
            return 0
        }
        else {
            Write-ADLog "Erreur sauvegarde certificats: $($_.Exception.Message)" "ERROR"
            throw
        }
    }
}

Export-ModuleMember -Function Backup-AD*
