
$ClientHealthSourcePath = "\\atklsccm.kostweingroup.intern\sources$\Applications\PSADT_ClientHealthAndClean\Files"
$ClientHealthTargetPath = "$ENV:ProgramData\Kostwein\ClientHealth"
$CHScriptName = "ClientHealth.ps1"
$CHConfigName = "config.xml"

function Get-FileAge {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String] $FullFilePathName
    )

    if (Test-Path -Path $FullFilePathName) {
        $GetFile = Get-ChildItem -Path $FullFilePathName -File
        $GetFileAge = $GetFile.LastWriteTime

        return $GetFileAge
    }

    return $null
    
}

if (Test-Path -Path $ClientHealthTargetPath -ErrorAction SilentlyContinue) {

    $CHScriptFileTargetPath = Join-Path -Path $ClientHealthTargetPath -ChildPath $CHScriptName
    $CHScriptFileTargetAge = Get-FileAge -FullFilePathName $CHScriptFileTargetPath

    $CHConfigFileTargetPath = Join-Path -Path $ClientHealthTargetPath -ChildPath $CHConfigName
    $CHConfigFileTargetAge = Get-FileAge -FullFilePathName $CHConfigFileTargetPath

    if (Test-Path -Path $ClientHealthSourcePath -ErrorAction SilentlyContinue) {
        $CHScriptFilePath = Join-Path -Path $ClientHealthSourcePath -ChildPath $CHScriptName
        $CHScriptFileAge = Get-FileAge -FullFilePathName $CHScriptFilePath

        $CHConfigFilePath = Join-Path -Path $ClientHealthSourcePath -ChildPath $CHConfigName
        $CHConfigFileAge = Get-FileAge -FullFilePathName $CHConfigFilePath
    }

    $CHScriptCompare = $CHScriptFileAge.Subtract($CHScriptFileTargetAge)
    $CHConfigCompare = $CHConfigFileAge.Subtract($CHConfigFileTargetAge)

    if ($CHScriptCompare.TotalSeconds -gt 1 -or $CHConfigCompare.TotalSeconds -gt 1) {
        Exit 0 #ClientHealth exists but outdated
    } else {
        Write-Host "Installed"
    }
    
} else {
    Exit 0 #ClientHealth not installed
}

