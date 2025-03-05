
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
	[Parameter(HelpMessage = 'Path to XML Configuration File')]
	[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
	[string] $ConfigPath,
	[Parameter(HelpMessage = 'Name of XML Configuration File')]
	[ValidatePattern('.xml$')]
	[String] $ConfigFileName = 'KOWClientHealthConfig.xml'
)


##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region    VariableDeclaration


# Script ConfigMgr Client Health Version
$Version = '3.0.0'

[String]$ScriptPath = $MyInvocation.MyCommand.Definition
[String]$ScriptName = [IO.Path]::GetFileNameWithoutExtension($ScriptPath)
[String]$ScriptFileName = Split-Path -Path $ScriptPath -Leaf
[String]$ScriptRoot = Split-Path -Path $ScriptPath -Parent

[String]$InvokingScript = (Get-Variable -Name 'MyInvocation').Value.ScriptName
#  Get the invoking script directory
If ($InvokingScript) {
	#  If this script was invoked by another script
	[String]$ScriptParentPath = Split-Path -Path $InvokingScript -Parent
} Else {
	#  If this script was not invoked by another script, fall back to the directory one level above this script
	[String]$ScriptParentPath = (Get-Item -LiteralPath $ScriptRoot).Parent.FullName
}

## Variables: Import Variables from XML config file
#If no config file was passed in, use the default.
If (!$PSBoundParameters.ContainsKey('Config')) {

	$ClientHealthConfigFile = Join-Path -Path $ScriptRoot -ChildPath $ConfigFileName

	Write-Verbose "No config provided, defaulting to $ClientHealthConfigFile"

} else {
	$ClientHealthConfigFile = Join-Path -Path $ConfigPath -ChildPath $ConfigFileName
}

. "$ScriptRoot\Functions\CMStaticValues.ps1"

if (Test-Path -Path $ClientHealthConfigFile) {
	. "$ScriptRoot\Functions\Get-Configuration.ps1"
}


$CHRegistryPath = Join-Path -Path $configRegPath -ChildPath 'ConfigMgrClientHealth'



#endregion VariableDeclaration
##*=============================================
##* END VARIABLE DECLARATION
##*=============================================
