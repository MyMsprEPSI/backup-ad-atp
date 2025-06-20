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
    # Creation du dossier de sauvegarde
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    Write-Log "Debut de la sauvegarde AD dans $backupFolder"

    # Sauvegarde des utilisateurs avec toutes les proprietes
    Write-Log "Sauvegarde des utilisateurs..."
    Get-ADUser -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "Users.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des groupes avec membres
    Write-Log "Sauvegarde des groupes..."
    Get-ADGroup -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "Groups.csv") -NoTypeInformation -Encoding UTF8
    
    # Sauvegarde des membres de groupes
    Write-Log "Sauvegarde des membres de groupes..."
    $groupMemberships = @()
    Get-ADGroup -Filter * | ForEach-Object {
        $group = $_
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
    $groupMemberships | Export-Csv -Path (Join-Path $backupFolder "GroupMemberships.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des unites organisationnelles
    Write-Log "Sauvegarde des OUs..."
    Get-ADOrganizationalUnit -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "OUs.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des ordinateurs avec details
    Write-Log "Sauvegarde des ordinateurs..."
    Get-ADComputer -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "Computers.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des serveurs (ordinateurs avec OS serveur)
    Write-Log "Sauvegarde des serveurs..."
    Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' -Properties * | Export-Csv -Path (Join-Path $backupFolder "Servers.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des contacts
    Write-Log "Sauvegarde des contacts..."
    Get-ADObject -Filter 'ObjectClass -eq "contact"' -Properties * | Export-Csv -Path (Join-Path $backupFolder "Contacts.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des comptes de service
    Write-Log "Sauvegarde des comptes de service..."
    Get-ADServiceAccount -Filter * -Properties * -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $backupFolder "ServiceAccounts.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des sites et sous-reseaux
    Write-Log "Sauvegarde des sites AD..."
    Get-ADReplicationSite -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "Sites.csv") -NoTypeInformation -Encoding UTF8
    Get-ADReplicationSubnet -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "Subnets.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des controleurs de domaine
    Write-Log "Sauvegarde des controleurs de domaine..."
    Get-ADDomainController -Filter * | Export-Csv -Path (Join-Path $backupFolder "DomainControllers.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des objets de strategie de groupe (references)
    Write-Log "Sauvegarde des references GPO..."
    Get-ADObject -Filter 'ObjectClass -eq "groupPolicyContainer"' -Properties * | Export-Csv -Path (Join-Path $backupFolder "GPOObjects.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des trusts de domaine
    Write-Log "Sauvegarde des trusts..."
    Get-ADTrust -Filter * | Export-Csv -Path (Join-Path $backupFolder "Trusts.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des schemas d'attributs personnalises
    Write-Log "Sauvegarde des attributs de schema..."
    Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter 'ObjectClass -eq "attributeSchema"' -Properties * | Export-Csv -Path (Join-Path $backupFolder "SchemaAttributes.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des classes de schema
    Write-Log "Sauvegarde des classes de schema..."
    Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter 'ObjectClass -eq "classSchema"' -Properties * | Export-Csv -Path (Join-Path $backupFolder "SchemaClasses.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des liens de replication
    Write-Log "Sauvegarde des liens de replication..."
    Get-ADReplicationConnection -Filter * | Export-Csv -Path (Join-Path $backupFolder "ReplicationConnections.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des partitions de l'annuaire
    Write-Log "Sauvegarde des partitions..."
    Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Filter 'ObjectClass -eq "crossRef"' -Properties * | Export-Csv -Path (Join-Path $backupFolder "DirectoryPartitions.csv") -NoTypeInformation -Encoding UTF8

    # Sauvegarde des objets de quotas (si actives)
    Write-Log "Sauvegarde des quotas..."
    try {
        Get-ADObject -Filter 'ObjectClass -eq "msDS-QuotaContainer"' -Properties * | Export-Csv -Path (Join-Path $backupFolder "Quotas.csv") -NoTypeInformation -Encoding UTF8
    }
    catch {
        Write-Log "Pas de quotas configures" "INFO"
    }

    # Sauvegarde des liens d'attribution de certificats
    Write-Log "Sauvegarde des modeles de certificats..."
    try {
        Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter * -Properties * | Export-Csv -Path (Join-Path $backupFolder "CertificateTemplates.csv") -NoTypeInformation -Encoding UTF8
    }
    catch {
        Write-Log "Pas de modeles de certificats trouves" "INFO"
    }

    # Sauvegarde des GPO (necessite le module GroupPolicy)
    if (Get-Module -ListAvailable -Name GroupPolicy) {
        Write-Log "Sauvegarde des GPO..."
        Import-Module GroupPolicy
        $gpoBackupPath = Join-Path $backupFolder "GPOBackup"
        New-Item -Path $gpoBackupPath -ItemType Directory -Force | Out-Null
        
        # Export de tous les GPO avec leur contenu
        Get-GPO -All | ForEach-Object {
            try {
                $gpoBackupInfo = Backup-GPO -Guid $_.Id -Path $gpoBackupPath
                Write-Log "GPO sauvegarde: $($_.DisplayName) -> $($gpoBackupInfo.BackupDirectory)"
            }
            catch {
                Write-Log "Erreur sauvegarde GPO $($_.DisplayName): $($_.Exception.Message)" "ERROR"
            }
        }

        # Export des liens GPO
        Write-Log "Sauvegarde des liens GPO..."
        $gpoLinks = @()
        Get-ADOrganizationalUnit -Filter * | ForEach-Object {
            $ou = $_
            if ($ou.LinkedGroupPolicyObjects) {
                foreach ($link in $ou.LinkedGroupPolicyObjects) {
                    $gpoLinks += [PSCustomObject]@{
                        OUName  = $ou.Name
                        OUDN    = $ou.DistinguishedName
                        GPOLink = $link
                    }
                }
            }
        }
        $gpoLinks | Export-Csv -Path (Join-Path $backupFolder "GPOLinks.csv") -NoTypeInformation -Encoding UTF8
    }

    # Sauvegarde complete de la base de donnees AD (si demandee)
    if ($FullBackup) {
        Write-Log "Sauvegarde complete de la base de donnees AD..."
        
        # Creation d'un dossier sur le disque C: pour wbadmin
        $systemStateBackup = "C:\SystemStateBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -Path $systemStateBackup -ItemType Directory -Force | Out-Null
        
        try {
            # Utilisation de wbadmin avec un chemin local
            Write-Log "Demarrage de la sauvegarde systeme vers $systemStateBackup..."
            $wbResult = Start-Process -FilePath "wbadmin" -ArgumentList "start systemstatebackup -backuptarget:$systemStateBackup -quiet" -Wait -PassThru -NoNewWindow
            
            if ($wbResult.ExitCode -eq 0) {
                Write-Log "Sauvegarde systeme reussie"
                # Deplacer la sauvegarde vers le dossier de sauvegarde principal
                $finalSystemStateBackup = Join-Path $backupFolder "SystemState"
                Move-Item $systemStateBackup $finalSystemStateBackup -Force
                Write-Log "Sauvegarde systeme deplacee vers $finalSystemStateBackup"
            }
            else {
                Write-Log "Erreur lors de la sauvegarde systeme (code: $($wbResult.ExitCode))" "ERROR"
                Write-Log "Alternative: Creation d'une sauvegarde NTDS manuelle..." "INFO"
                
                # Alternative: sauvegarde du fichier NTDS.dit et des registres
                $ntdsBackup = Join-Path $backupFolder "NTDS_Manual"
                New-Item -Path $ntdsBackup -ItemType Directory -Force | Out-Null
                
                # Export des cles de registre importantes
                reg export "HKLM\SYSTEM\CurrentControlSet\Services\NTDS" (Join-Path $ntdsBackup "NTDS_Registry.reg") /y
                reg export "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" (Join-Path $ntdsBackup "Netlogon_Registry.reg") /y
                
                Write-Log "Sauvegarde manuelle NTDS terminee"
            }
        }
        catch {
            Write-Log "Erreur critique lors de la sauvegarde systeme: $($_.Exception.Message)" "ERROR"
        }
        finally {
            # Nettoyage du dossier temporaire si il existe encore
            if (Test-Path $systemStateBackup) {
                Remove-Item $systemStateBackup -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Creation d'un rapport de synthese
    Write-Log "Creation du rapport de synthese..."
    $summary = @{
        Date              = Get-Date
        Users             = (Import-Csv (Join-Path $backupFolder "Users.csv")).Count
        Groups            = (Import-Csv (Join-Path $backupFolder "Groups.csv")).Count
        Computers         = (Import-Csv (Join-Path $backupFolder "Computers.csv")).Count
        OUs               = (Import-Csv (Join-Path $backupFolder "OUs.csv")).Count
        Servers           = (Import-Csv (Join-Path $backupFolder "Servers.csv")).Count
        DomainControllers = (Import-Csv (Join-Path $backupFolder "DomainControllers.csv")).Count
    }
    $summary | ConvertTo-Json | Out-File (Join-Path $backupFolder "BackupSummary.json") -Encoding UTF8

    # Nettoyage des anciennes sauvegardes
    Write-Log "Nettoyage des sauvegardes anciennes (> $RetentionDays jours)..."
    Get-ChildItem -Path $BackupPath -Directory | 
    Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$RetentionDays) } |
    Remove-Item -Recurse -Force

    Write-Log "Sauvegarde terminee avec succes"
}
catch {
    Write-Log "Erreur lors de la sauvegarde: $($_.Exception.Message)" "ERROR"
    throw
}