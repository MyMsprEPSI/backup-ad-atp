<#
.SYNOPSIS
    Module de gestion des presets de sauvegarde
#>

<#
.SYNOPSIS
    Charge les presets depuis le fichier JSON
#>
function Get-BackupPresets {
    [CmdletBinding()]
    param()
    
    $presetFile = Join-Path $PSScriptRoot "BackupPresets.json"
    
    if (Test-Path $presetFile) {
        try {
            $content = Get-Content $presetFile -Raw | ConvertFrom-Json
            return $content.presets
        } catch {
            Write-Warning "Erreur lecture fichier presets: $($_.Exception.Message)"
            return $null
        }
    } else {
        Write-Warning "Fichier de presets non trouve: $presetFile"
        return $null
    }
}

<#
.SYNOPSIS
    Applique un preset aux options de sauvegarde
#>
function Set-BackupPreset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$BackupOptions,
        
        [Parameter(Mandatory)]
        [string]$PresetName
    )
    
    $presets = Get-BackupPresets
    if (-not $presets) { return $false }
    
    $preset = $presets.$PresetName
    if (-not $preset) {
        Write-Warning "Preset '$PresetName' non trouve"
        return $false
    }
    
    # Reset toutes les selections
    foreach ($key in $BackupOptions.Keys) {
        $BackupOptions[$key].Selected = $false
    }
    
    # Applique le preset
    foreach ($item in $preset.items) {
        if ($BackupOptions.ContainsKey($item)) {
            $BackupOptions[$item].Selected = $true
        }
    }
    
    return $true
}

Export-ModuleMember -Function Get-BackupPresets, Set-BackupPreset
