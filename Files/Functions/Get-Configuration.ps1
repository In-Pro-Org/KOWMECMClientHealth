
Function Get-Configuration {
	<#
        .SYNOPSIS
        Test the validity of an XML file
    #>
	[OutputType([Boolean])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[string] $xmlFilePath
	)

	# Check the file exists
	if (!(Test-Path -Path $xmlFilePath)) {
		throw "$xmlFilePath is not valid. Please provide a valid path to the .xml config file"
	}

	# Check for Load or Parse errors when loading the XML file
	$xml = New-Object System.Xml.XmlDocument
	$Config = [System.Xml.XmlDocument]::new()

	try {
		$xml.Load((Get-ChildItem -Path $xmlFilePath).FullName)
		return $true

	} catch [System.Xml.XmlException] {
		Write-Error "$xmlFilePath : $($_.toString())"
		Write-Error "Configuration file $Config is NOT valid XML. Script will not execute."

		return $false
	}
}


if (Test-Path -Path $ClientHealthConfigFile) {
	[Xml.XmlDocument]$xmlConfigFile = Get-Content -LiteralPath $ClientHealthConfigFile -Encoding 'UTF8'
	[Xml.XmlElement]$xmlConfig = $xmlConfigFile.KOWClientHealth_Config
}

[Xml.XmlElement]$xmlClientHealthOptions = $xmlConfig.ClientHealth_Options
[Boolean]$configRequireAdmin = [Boolean]::Parse($xmlClientHealthOptions.ClientHealth_RequireAdmin)
[String]$configTempPath = $ExecutionContext.InvokeCommand.ExpandString($xmlClientHealthOptions.ClientHealth_TempPath)
[String]$configRegPath = $xmlClientHealthOptions.ClientHealth_RegPath
[String]$configLogDir = $ExecutionContext.InvokeCommand.ExpandString($xmlClientHealthOptions.ClientHealth_LogPath)
[String]$configLogStyle = $xmlClientHealthOptions.ClientHealth_LogStyle
[Boolean]$configLogWriteToHost = [Boolean]::Parse($xmlClientHealthOptions.ClientHealth_LogWriteToHost)
[Boolean]$configLogDebugMessage = [Boolean]::Parse($xmlClientHealthOptions.ClientHealth_LogDebugMessage)
[Boolean]$configLogAppend = [Boolean]::Parse($xmlClientHealthOptions.ClientHealth_LogAppend)
[Double]$configLogMaxSize = $xmlClientHealthOptions.ClientHealth_LogMaxSize
[Int]$configLogMaxHistory = $xmlClientHealthOptions.ClientHealth_LogMaxHistory

[Xml.XmlElement]$xmlClientOptions = $xmlConfig.Client_Options

[Xml.XmlElement]$xmlClientInstallOptions = $xmlConfig.ClientInstall_Options

[Xml.XmlElement]$xmlClientCheckOptions = $xmlConfig.ClientCheck_Options

[Xml.XmlElement]$xmlClientServicesOptions = $xmlConfig.ClientServices_Options

[Xml.XmlElement]$xmlRemediationOptions = $xmlConfig.Remediation_Options

[Xml.XmlElement]$xmlLoggingOptions = $xmlConfig.Logging_Options

