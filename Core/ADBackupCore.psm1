<#
.SYNOPSIS
    Module principal pour les fonctions de sauvegarde/restauration Active Directory
.DESCRIPTION
    Contient toutes les fonctions communes utilisees par les scripts de sauvegarde et restauration
.AUTHOR
    Thibaut Maurras
.VERSION
    1.0
#>

# Variables globales du module
$Script:LogFile = $null
$Script:BackupFolder = $null

<#
.SYNOPSIS
    Initialise le module avec les parametres de base
#>
function Initialize-ADBackupModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath,
        
        [string]$LogFileName = "backup.log"
    )
    
    $Script:BackupFolder = $BackupPath
    $Script:LogFile = Join-Path $BackupPath $LogFileName
    
    # Verification des prerequis
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        throw "Module ActiveDirectory non disponible"
    }
    
    Import-Module ActiveDirectory -ErrorAction Stop
}

<#
.SYNOPSIS
    Fonction de logging centralisee
#>
function Write-ADLog {
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
    
    if ($Script:LogFile) {
        try {
            Add-Content -Path $Script:LogFile -Value $logEntry -ErrorAction Stop
        } catch {
            Write-Warning "Impossible d'ecrire dans le fichier de log: $($_.Exception.Message)"
        }
    }
}

# Export des fonctions publiques
Export-ModuleMember -Function Initialize-ADBackupModule, Write-ADLog
