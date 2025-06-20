<#
.SYNOPSIS
    Module contenant les fonctions d'interface utilisateur
#>

<#
.SYNOPSIS
    Affiche un menu avec options colorees
#>
function Show-ColorMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        
        [Parameter(Mandatory)]
        [hashtable]$Options,
        
        [string[]]$SpecialOptions = @(),
        
        [string]$Prompt = "Votre choix"
    )
    
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host "        $Title" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor Yellow
    Write-Host ""
    
    # Affichage des options principales
    foreach ($key in ($Options.Keys | Sort-Object { [int]$_ })) {
        $option = $Options[$key]
        $indicator = if ($option.Selected) { "[X]" } else { "[ ]" }
        $color = if ($option.Selected) { "Green" } else { "White" }
        Write-Host " $indicator [$key] $($option.Name)" -ForegroundColor $color
    }
    
    Write-Host ""
    
    # Affichage des options speciales
    foreach ($special in $SpecialOptions) {
        Write-Host " $special" -ForegroundColor Cyan
    }
    
    Write-Host ""
    return Read-Host $Prompt
}

<#
.SYNOPSIS
    Affiche une barre de progression avec details
#>
function Show-OperationProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Activity,
        
        [Parameter(Mandatory)]
        [string]$Status,
        
        [Parameter(Mandatory)]
        [int]$PercentComplete,
        
        [int]$SecondsRemaining = -1
    )
    
    $progressParams = @{
        Activity = $Activity
        Status = $Status
        PercentComplete = $PercentComplete
    }
    
    if ($SecondsRemaining -gt 0) {
        $progressParams.SecondsRemaining = $SecondsRemaining
    }
    
    Write-Progress @progressParams
}

Export-ModuleMember -Function Show-ColorMenu, Show-OperationProgress
