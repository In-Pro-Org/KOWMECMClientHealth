
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
	[Parameter(HelpMessage = 'Path to XML Configuration File')]
	[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
	[ValidatePattern('.xml$')]
	[string]$Config,
	[Parameter(HelpMessage = 'URI to ConfigMgr Client Health Webservice')]
	[string]$Webservice
)


##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region    VariableDeclaration


# ConfigMgr Client Health Version
$Version = '3.0.0'
#$PowerShellVersion = [int]$PSVersionTable.PSVersion.Major
#$global:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

$Script:LogFolder = "$env:ProgramData\Kostwein\Logs"
$Script:ErrorLog = 'ScriptError.log'
$logName = 'ClientHealth.log'

## Variables: Script Name and Script Paths
[String]$ScriptPath = $MyInvocation.MyCommand.Definition
[String]$ScriptName = [IO.Path]::GetFileNameWithoutExtension($ScriptPath)
[String]$ScriptFileName = Split-Path -Path $ScriptPath -Leaf
[String]$ScriptRoot = Split-Path -Path $ScriptPath -Parent
[String]$invokingScript = (Get-Variable -Name 'MyInvocation').Value.ScriptName
#  Get the invoking script directory
If ($invokingScript) {
	#  If this script was invoked by another script
	[String]$scriptParentPath = Split-Path -Path $invokingScript -Parent
} Else {
	#  If this script was not invoked by another script, fall back to the directory one level above this script
	[String]$scriptParentPath = (Get-Item -LiteralPath $scriptRoot).Parent.FullName
}

## Variables: Datetime and Culture
[DateTime]$currentDateTime = Get-Date
[String]$currentTime = Get-Date -Date $currentDateTime -UFormat '%T'
[String]$currentDate = Get-Date -Date $currentDateTime -UFormat '%d-%m-%Y'
[Timespan]$currentTimeZoneBias = [TimeZone]::CurrentTimeZone.GetUtcOffset($currentDateTime)
[Globalization.CultureInfo]$culture = Get-Culture
[String]$currentLanguage = $culture.TwoLetterISOLanguageName.ToUpper()
[Globalization.CultureInfo]$uiculture = Get-UICulture
[String]$currentUILanguage = $uiculture.TwoLetterISOLanguageName.ToUpper()

## Variables: Environment Variables
[PSObject]$envHost = $Host
[String]$envComputerName = [Environment]::MachineName.ToUpper()
[String]$envProgramData = [Environment]::GetFolderPath('CommonApplicationData')
[String]$envTemp = [IO.Path]::GetTempPath()
[String]$envWinDir = $env:WINDIR
[String]$envSystemDrive = $env:SYSTEMDRIVE

## Variables: Domain Membership
[Boolean]$IsMachinePartOfDomain = (Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').PartOfDomain
[String]$envMachineWorkgroup = ''
[String]$envMachineADDomain = ''
[String]$envLogonServer = ''
[String]$MachineDomainController = ''
[String]$envComputerNameFQDN = $envComputerName

If ($IsMachinePartOfDomain) {
	[String]$envMachineADDomain = (Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
	Try {
		$envComputerNameFQDN = ([Net.Dns]::GetHostEntry('localhost')).HostName
	} Catch {
		# Function GetHostEntry failed, but we can construct the FQDN in another way
		$envComputerNameFQDN = $envComputerNameFQDN + '.' + $envMachineADDomain
	}

	Try {
		[String]$envLogonServer = $env:LOGONSERVER | Where-Object { (($_) -and (-not $_.Contains('\\MicrosoftAccount'))) } | ForEach-Object { $_.TrimStart('\') } | ForEach-Object { ([Net.Dns]::GetHostEntry($_)).HostName }
	} Catch {
		continue
	}
	# If running in system context or if GetHostEntry fails, fall back on the logonserver value stored in the registry
	If (-not $envLogonServer) {
		[String]$envLogonServer = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History' -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty 'DCName' -ErrorAction 'SilentlyContinue'
	}
	## Remove backslashes at the beginning
	While ($envLogonServer.StartsWith('\')) {
		$envLogonServer = $envLogonServer.Substring(1)
	}

	Try {
		[String]$MachineDomainController = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
	} Catch {
		continue
	}
} Else {
	[String]$envMachineWorkgroup = (Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToUpper() }
}
[String]$envMachineDNSDomain = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
[String]$envUserDNSDomain = $env:USERDNSDOMAIN | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
Try {
	[String]$envUserDomain = [Environment]::UserDomainName.ToUpper()
} Catch {
	continue
}

## Variables: PowerShell And CLR (.NET) Versions
[Hashtable]$envPSVersionTable = $PSVersionTable
#  PowerShell Version
[Version]$envPSVersion = $envPSVersionTable.PSVersion
[String]$envPSVersionMajor = $envPSVersion.Major
[String]$envPSVersionMinor = $envPSVersion.Minor
[String]$envPSVersionBuild = $envPSVersion.Build
[String]$envPSVersionRevision = $envPSVersion.Revision
[String]$envPSVersion = $envPSVersion.ToString()
#  CLR (.NET) Version used by PowerShell
#[Version]$envCLRVersion = $envPSVersionTable.CLRVersion
#[String]$envCLRVersionMajor = $envCLRVersion.Major
#[String]$envCLRVersionMinor = $envCLRVersion.Minor
#[String]$envCLRVersionBuild = $envCLRVersion.Build
#[String]$envCLRVersionRevision = $envCLRVersion.Revision
#[String]$envCLRVersion = $envCLRVersion.ToString()

## Variables: Permissions/Accounts
[Security.Principal.WindowsIdentity]$CurrentProcessToken = [Security.Principal.WindowsIdentity]::GetCurrent()
[Security.Principal.SecurityIdentifier]$CurrentProcessSID = $CurrentProcessToken.User
[String]$ProcessNTAccount = $CurrentProcessToken.Name
[String]$ProcessNTAccountSID = $CurrentProcessSID.Value
[Boolean]$IsAdmin = [Boolean]($CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-32-544')
[Boolean]$IsLocalSystemAccount = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'LocalSystemSid')
[Boolean]$IsLocalServiceAccount = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'LocalServiceSid')
[Boolean]$IsNetworkServiceAccount = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'NetworkServiceSid')
[Boolean]$IsServiceAccount = [Boolean]($CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-6')

## Variables: Import Variables from XML config file
#If no config file was passed in, use the default.
If ((!$PSBoundParameters.ContainsKey('Config')) -and (!$PSBoundParameters.ContainsKey('Webservice'))) {
	$ClientHealthConfigFile = Join-Path -Path $ScriptRoot -ChildPath 'KOWClientHealthConfig.xml'
	Write-Verbose "No config provided, defaulting to $ClientHealthConfigFile"
} else {
	$ClientHealthConfigFile = $Config
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

$CHRegistryPath = Join-Path -Path $configRegPath -ChildPath 'ConfigMgrClientHealth'

$Services = @(
	'BITS', # Background Intelligent Transfer Service
	'gpsvc', # Group Policy
	'Winmgmt', # WMI
	'wuauserv', # Windows Update Agent
	'Schedule', # Task Scheduler
	'CcmExec', # CCM Client
	'CmRcService'  # CCM Remote Connection
)

$DLLComponents = @(
	'actxprxy.dll',
	'atl.dll',
	'Bitsprx2.dll',
	'Bitsprx3.dll',
	'browseui.dll',
	'cryptdlg.dll',
	'dssenh.dll',
	'gpkcsp.dll',
	'initpki.dll',
	'jscript.dll',
	'mshtml.dll',
	'msi.dll',
	'mssip32.dll',
	'msxml3.dll',
	'msxml3r.dll',
	'msxml6.dll',
	'msxml6r.dll',
	'muweb.dll',
	'ole32.dll',
	'oleaut32.dll',
	'Qmgr.dll',
	'Qmgrprxy.dll',
	'rsaenh.dll',
	'sccbase.dll',
	'scrrun.dll',
	'shdocvw.dll',
	'shell32.dll',
	'slbcsp.dll',
	'softpub.dll',
	'urlmon.dll',
	'userenv.dll',
	'vbscript.dll',
	'Winhttp.dll',
	'wintrust.dll',
	'wuapi.dll',
	'wuaueng.dll',
	'wuaueng1.dll',
	'wucltui.dll',
	'wucltux.dll',
	'wups.dll',
	'wups2.dll',
	'wuweb.dll',
	'wuwebv.dll',
	'wbem\wmisvc.dll',
	'Xpob2res.dll'
)

#endregion VariableDeclaration
##*=============================================
##* END VARIABLE DECLARATION
##*=============================================



##*=============================================
##* FUNCTION LISTINGS
##*=============================================
#region    Functions

function New-FunctionTemplate {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $ParameterName
	)

	begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	process {

	}
	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}

}

Function Write-FunctionHeaderOrFooter {
	<#
	.SYNOPSIS
	Write the function header or footer to the log upon first entering or exiting a function.

	.DESCRIPTION
	Write the "Function Start" message, the bound parameters the function was invoked with, or the "Function End" message when entering or exiting a function.
	Messages are debug messages so will only be logged if LogDebugMessage option is enabled in XML config file.

	.PARAMETER CmdletName
	The name of the function this function is invoked from.

	.PARAMETER CmdletBoundParameters
	The bound parameters of the function this function is invoked from.

	.PARAMETER Header
	Write the function header.

	.PARAMETER Footer
	Write the function footer.

	.INPUTS
	None

	You cannot pipe objects to this function.

	.OUTPUTS
	None

	This function does not generate any output.

	.EXAMPLE
	Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

	.EXAMPLE
	Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer

	.NOTES
	This is an internal script function and should typically not be called directly.

	.LINK
	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[String] $CmdletName,
		[Parameter(Mandatory = $true, ParameterSetName = 'Header')]
		[AllowEmptyCollection()]
		[Hashtable] $CmdletBoundParameters,
		[Parameter(Mandatory = $true, ParameterSetName = 'Header')]
		[Switch] $Header,
		[Parameter(Mandatory = $true, ParameterSetName = 'Footer')]
		[Switch] $Footer
	)

	If ($Header) {
		Write-Log -Message 'Function Start' -Source ${CmdletName} -DebugMessage

		## Get the parameters that the calling function was invoked with
		[String]$CmdletBoundParameters = $CmdletBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' }, @{ Label = 'Type'; Expression = { $_.Value.GetType().Name }; Alignment = 'Left' } -AutoSize -Wrap | Out-String

		If ($CmdletBoundParameters) {
			Write-Log -Message "Function invoked with bound parameter(s): `r`n$CmdletBoundParameters" -Source ${CmdletName} -DebugMessage
		} Else {
			Write-Log -Message 'Function invoked without any bound parameters.' -Source ${CmdletName} -DebugMessage
		}

	} ElseIf ($Footer) {
		Write-Log -Message 'Function End' -Source ${CmdletName} -DebugMessage
	}
}

Function Write-Log {
	<#
	.SYNOPSIS
	Write messages to a log file in CMTrace.exe compatible format or Legacy text file format.

	.DESCRIPTION
	Write messages to a log file in CMTrace.exe compatible format or Legacy text file format and optionally display in the console.

	.PARAMETER Message
	The message to write to the log file or output to the console.

	.PARAMETER Severity
	Defines message type. When writing to console or CMTrace.exe log format, it allows highlighting of message type.
	Options: 1 = Information (default), 2 = Warning (highlighted in yellow), 3 = Error (highlighted in red)

	.PARAMETER Source
	The source of the message being logged.

	.PARAMETER ScriptSection
	The heading for the portion of the script that is being executed. Default is: $script:installPhase.

	.PARAMETER LogType
	Choose whether to write a CMTrace.exe compatible log file or a Legacy text log file.

	.PARAMETER LogFileDirectory
	Set the directory where the log file will be saved.

	.PARAMETER LogFileName
	Set the name of the log file.

	.PARAMETER AppendToLogFile
	Append to existing log file rather than creating a new one upon toolkit initialization. Default value is defined in AppDeployToolkitConfig.xml.

	.PARAMETER MaxLogHistory
	Maximum number of previous log files to retain. Default value is defined in AppDeployToolkitConfig.xml.

	.PARAMETER MaxLogFileSizeMB
	Maximum file size limit for log file in megabytes (MB). Default value is defined in AppDeployToolkitConfig.xml.

	.PARAMETER ContinueOnError
	Suppress writing log message to console on failure to write message to log file. Default is: $true.

	.PARAMETER WriteHost
	Write the log message to the console.

	.PARAMETER PassThru
	Return the message that was passed to the function

	.PARAMETER DebugMessage
	Specifies that the message is a debug message. Debug messages only get logged if -LogDebugMessage is set to $true.

	.PARAMETER LogDebugMessage
	Debug messages only get logged if this parameter is set to $true in the config XML file.

	.INPUTS
	System.String

	The message to write to the log file or output to the console.

	.OUTPUTS
	None

	This function does not generate any output.

	.EXAMPLE
	Write-Log -Message "Installing patch MS15-031" -Source 'Add-Patch' -LogType 'CMTrace'

	.EXAMPLE
	Write-Log -Message "Script is running on Windows 8" -Source 'Test-ValidOS' -LogType 'Legacy'

	.EXAMPLE
	Write-Log -Message "Log only message" -WriteHost $false

	.NOTES

	.LINK
	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[AllowEmptyCollection()]
		[Alias('Text')]
		[String[]]$Message,
		[Parameter(Mandatory = $false, Position = 1)]
		[ValidateRange(0, 3)]
		[Int16]$Severity = 1,
		[Parameter(Mandatory = $false, Position = 2)]
		[ValidateNotNull()]
		[String]$Source = $([String]$parentFunctionName = [IO.Path]::GetFileNameWithoutExtension((Get-Variable -Name 'MyInvocation' -Scope 1 -ErrorAction 'SilentlyContinue').Value.MyCommand.Name); If ($parentFunctionName) {
				$parentFunctionName
			} Else {
				'Unknown'
			}),
		[Parameter(Mandatory = $false, Position = 3)]
		[ValidateNotNullorEmpty()]
		[String]$ScriptSection = $script:installPhase,
		[Parameter(Mandatory = $false, Position = 4)]
		[ValidateSet('CMTrace', 'Legacy')]
		[String]$LogType = $configLogStyle,
		[Parameter(Mandatory = $false, Position = 5)]
		[ValidateNotNullorEmpty()]
		[String]$LogFileDirectory = $(If ($configCompressLogs) {
				$logTempFolder
			} Else {
				$configLogDir
			}),
		[Parameter(Mandatory = $false, Position = 6)]
		[ValidateNotNullorEmpty()]
		[String]$LogFileName = $logName,
		[Parameter(Mandatory = $false, Position = 7)]
		[ValidateNotNullorEmpty()]
		[Boolean]$AppendToLogFile = $configLogAppend,
		[Parameter(Mandatory = $false, Position = 8)]
		[ValidateNotNullorEmpty()]
		[Int]$MaxLogHistory = $configLogMaxHistory,
		[Parameter(Mandatory = $false, Position = 9)]
		[ValidateNotNullorEmpty()]
		[Decimal]$MaxLogFileSizeMB = $configLogMaxSize,
		[Parameter(Mandatory = $false, Position = 10)]
		[ValidateNotNullorEmpty()]
		[Boolean]$ContinueOnError = $true,
		[Parameter(Mandatory = $false, Position = 11)]
		[ValidateNotNullorEmpty()]
		[Boolean]$WriteHost = $configLogWriteToHost,
		[Parameter(Mandatory = $false, Position = 12)]
		[Switch]$PassThru = $false,
		[Parameter(Mandatory = $false, Position = 13)]
		[Switch]$DebugMessage = $false,
		[Parameter(Mandatory = $false, Position = 14)]
		[Boolean]$LogDebugMessage = $configLogDebugMessage
	)

	Begin {
		## Get the name of this function
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

		$CallStack = (Get-PSCallStack)
		$SourceCallStack = $CallStack | Where-Object { $_.Command -eq $Source }
		$SourceLine = $SourceCallStack.ScriptLineNumber.ToString()
		$Context = [string]::Format('{0}:{1}', $Source, $($SourceLine))

		## Logging Variables
		#  Log file date/time
		[DateTime]$DateTimeNow = Get-Date
		#[String]$LogTime = $DateTimeNow.ToString('HH\:mm\:ss.fff')
		[String]$LogTime = $DateTimeNow.ToString('HH\:mm\:ss')
		[String]$LogDate = $DateTimeNow.ToString('dd.MM.yyyy')

		If (-not (Test-Path -LiteralPath 'variable:LogTimeZoneBias')) {
			[Int32]$script:LogTimeZoneBias = [TimeZone]::CurrentTimeZone.GetUtcOffset($DateTimeNow).TotalMinutes
		}

		[String]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias

		#  Initialize variables
		[Boolean]$ExitLoggingFunction = $false

		If (-not (Test-Path -LiteralPath 'variable:DisableLogging')) {
			$DisableLogging = $false
		}

		If ([System.String]::IsNullOrWhiteSpace($LogFileName)) {
			$DisableLogging = $true
		}

		#  Check if the script section is defined
		[Boolean]$ScriptSectionDefined = [Boolean](-not [String]::IsNullOrEmpty($ScriptSection))

		#  Get the file name of the source script
		$ScriptSource = If (![System.String]::IsNullOrWhiteSpace($script:MyInvocation.ScriptName)) {
			Split-Path -Path $script:MyInvocation.ScriptName -Leaf -ErrorAction SilentlyContinue
		} Else {
			Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction SilentlyContinue
		}

		## Create script block for generating CMTrace.exe compatible log entry
		[ScriptBlock]$CMTraceLogString = {
			Param (
				[String]$lMessage,
				[String]$lSource,
				[Int16]$lSeverity,
				[String]$lContext
			)
			#"<![LOG[$lMessage]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$lSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$lSeverity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
			"<![LOG[$lMessage]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$lSource`" " + "context=`"$lContext`" " + "type=`"$lSeverity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
		}

		## Create script block for writing log entry to the console
		[ScriptBlock]$WriteLogLineToHost = {
			Param (
				[String]$lTextLogLine,
				[Int16]$lSeverity
			)

			If ($WriteHost) {
				#  Only output using color options if running in a host which supports colors.
				If ($Host.UI.RawUI.ForegroundColor) {
					Switch ($lSeverity) {
						3 {
							Write-Host -Object $lTextLogLine -ForegroundColor 'Red' -BackgroundColor 'Black'
						}
						2 {
							Write-Host -Object $lTextLogLine -ForegroundColor 'Yellow' -BackgroundColor 'Black'
						}
						1 {
							Write-Host -Object $lTextLogLine
						}
						0 {
							Write-Host -Object $lTextLogLine -ForegroundColor 'Green' -BackgroundColor 'Black'
						}
					}
				}
				#  If executing "powershell.exe -File <filename>.ps1 > log.txt", then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
				Else {
					Write-Output -InputObject ($lTextLogLine)
				}
			}
		}

		## Exit function if it is a debug message and logging debug messages is not enabled in the config XML file
		If (($DebugMessage) -and (-not $LogDebugMessage)) {
			[Boolean]$ExitLoggingFunction = $true; Return
		}

		## Exit function if logging to file is disabled and logging to console host is disabled
		If (($DisableLogging) -and (-not $WriteHost)) {
			[Boolean]$ExitLoggingFunction = $true; Return
		}

		## Exit Begin block if logging is disabled
		If ($DisableLogging) {
			Return
		}

		## Exit function function if it is an [Initialization] message and the toolkit has been relaunched
		If (($AsyncToolkitLaunch) -and ($ScriptSection -eq 'Initialization')) {
			[Boolean]$ExitLoggingFunction = $true; Return
		}

		## Create the directory where the log file will be saved
		If (-not (Test-Path -LiteralPath $LogFileDirectory -PathType 'Container')) {
			Try {
				$null = New-Item -Path $LogFileDirectory -Type 'Directory' -Force -ErrorAction 'Stop'
			} Catch {
				[Boolean]$ExitLoggingFunction = $true
				#  If error creating directory, write message to console
				If (-not $ContinueOnError) {
					Write-Host -Object "[$LogDate $LogTime] [${CmdletName}] $ScriptSection :: Failed to create the log directory [$LogFileDirectory]. `r`n$(Resolve-Error)" -ForegroundColor 'Red'
				}
				Return
			}
		}

		## Assemble the fully qualified path to the log file
		[String]$LogFilePath = Join-Path -Path $LogFileDirectory -ChildPath $LogFileName

		if (Test-Path -Path $LogFilePath -PathType Leaf) {
			Try {
				$LogFile = Get-Item $LogFilePath
				[Decimal]$LogFileSizeMB = $LogFile.Length / 1MB

				# Check if log file needs to be rotated
				if ((!$script:LogFileInitialized -and !$AppendToLogFile) -or ($MaxLogFileSizeMB -gt 0 -and $LogFileSizeMB -gt $MaxLogFileSizeMB)) {

					# Get new log file path
					$LogFileNameWithoutExtension = [IO.Path]::GetFileNameWithoutExtension($LogFileName)
					$LogFileExtension = [IO.Path]::GetExtension($LogFileName)
					$Timestamp = $LogFile.LastWriteTime.ToString('yyyy-MM-dd-HH-mm-ss')
					$ArchiveLogFileName = '{0}_{1}{2}' -f $LogFileNameWithoutExtension, $Timestamp, $LogFileExtension
					[String]$ArchiveLogFilePath = Join-Path -Path $LogFileDirectory -ChildPath $ArchiveLogFileName

					if ($MaxLogFileSizeMB -gt 0 -and $LogFileSizeMB -gt $MaxLogFileSizeMB) {
						[Hashtable]$ArchiveLogParams = @{ ScriptSection = $ScriptSection; Source = ${CmdletName}; Severity = 2; LogFileDirectory = $LogFileDirectory; LogFileName = $LogFileName; LogType = $LogType; MaxLogFileSizeMB = 0; AppendToLogFile = $true; WriteHost = $WriteHost; ContinueOnError = $ContinueOnError; PassThru = $false }

						## Log message about archiving the log file
						$ArchiveLogMessage = "Maximum log file size [$MaxLogFileSizeMB MB] reached. Rename log file to [$ArchiveLogFileName]."
						Write-Log -Message $ArchiveLogMessage @ArchiveLogParams
					}

					# Rename the file
					Move-Item -Path $LogFilePath -Destination $ArchiveLogFilePath -Force -ErrorAction 'Stop'

					if ($MaxLogFileSizeMB -gt 0 -and $LogFileSizeMB -gt $MaxLogFileSizeMB) {
						## Start new log file and Log message about archiving the old log file
						$NewLogMessage = "Previous log file was renamed to [$ArchiveLogFileName] because maximum log file size of [$MaxLogFileSizeMB MB] was reached."
						Write-Log -Message $NewLogMessage @ArchiveLogParams
					}

					# Get all log files (including any .lo_ files that may have been created by previous toolkit versions) sorted by last write time
					$LogFiles = @(Get-ChildItem -LiteralPath $LogFileDirectory -Filter ('{0}_*{1}' -f $LogFileNameWithoutExtension, $LogFileExtension)) + @(Get-Item -LiteralPath ([IO.Path]::ChangeExtension($LogFilePath, 'lo_')) -ErrorAction Ignore) | Sort-Object LastWriteTime

					# Keep only the max number of log files
					if ($LogFiles.Count -gt $MaxLogHistory) {
						$LogFiles | Select-Object -First ($LogFiles.Count - $MaxLogHistory) | Remove-Item -ErrorAction 'Stop'
					}
				}

			} Catch {
				Write-Host -Object "[$LogDate $LogTime] [${CmdletName}] $ScriptSection :: Failed to rotate the log file [$LogFilePath]. `r`n$(Resolve-Error)" -ForegroundColor 'Red'

				# Treat log rotation errors as non-terminating by default
				If (-not $ContinueOnError) {
					[Boolean]$ExitLoggingFunction = $true
					Return
				}
			}
		}

		$script:LogFileInitialized = $true

	}
	Process {
		## Exit function if logging is disabled
		If ($ExitLoggingFunction) {
			Return
		}

		ForEach ($Msg in $Message) {
			## If the message is not $null or empty, create the log entry for the different logging methods
			[String]$CMTraceMsg = ''
			[String]$ConsoleLogLine = ''
			[String]$LegacyTextLogLine = ''

			If ($Msg) {
				#  Create the CMTrace log message
				If ($ScriptSectionDefined) {
					[String]$CMTraceMsg = "[$ScriptSection] :: $Msg"
				}

				#  Create a Console and Legacy "text" log entry
				[String]$LegacyMsg = "[$LogDate $LogTime]"

				If ($ScriptSectionDefined) {
					[String]$LegacyMsg += " [$ScriptSection]"
				}

				If ($Source) {
					[String]$ConsoleLogLine = "$LegacyMsg [$Source][$SourceLine] :: $Msg"

					Switch ($Severity) {
						3 {
							[String]$LegacyTextLogLine = "$LegacyMsg [$Source] [Error] :: $Msg"
						}
						2 {
							[String]$LegacyTextLogLine = "$LegacyMsg [$Source] [Warning] :: $Msg"
						}
						1 {
							[String]$LegacyTextLogLine = "$LegacyMsg [$Source] [Info] :: $Msg"
						}
						0 {
							[String]$LegacyTextLogLine = "$LegacyMsg [$Source] [Success] :: $Msg"
						}
					}

				} Else {

					[String]$ConsoleLogLine = "$LegacyMsg :: $Msg"

					Switch ($Severity) {
						3 {
							[String]$LegacyTextLogLine = "$LegacyMsg [Error] :: $Msg"
						}
						2 {
							[String]$LegacyTextLogLine = "$LegacyMsg [Warning] :: $Msg"
						}
						1 {
							[String]$LegacyTextLogLine = "$LegacyMsg [Info] :: $Msg"
						}
						0 {
							[String]$LegacyTextLogLine = "$LegacyMsg [Success] :: $Msg"
						}
					}
				}
			}

			## Execute script block to create the CMTrace.exe compatible log entry
			[String]$CMTraceLogLine = & $CMTraceLogString -lMessage $CMTraceMsg -lSource $Source -lSeverity $Severity -lContext $Context

			## Choose which log type to write to file
			If ($LogType -ieq 'CMTrace') {
				[String]$LogLine = $CMTraceLogLine
			} Else {
				[String]$LogLine = $LegacyTextLogLine
			}

			## Write the log entry to the log file if logging is not currently disabled
			If (-not $DisableLogging) {
				Try {
					$LogLine | Out-File -FilePath $LogFilePath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop'
				} Catch {
					If (-not $ContinueOnError) {
						Write-Host -Object "[$LogDate $LogTime] [$ScriptSection] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogFilePath]. `r`n$(Resolve-Error)" -ForegroundColor 'Red'
					}
				}
			}

			## Execute script block to write the log entry to the console if $WriteHost is $true
			& $WriteLogLineToHost -lTextLogLine $ConsoleLogLine -lSeverity $Severity
		}
	}
	End {
		If ($PassThru) {
			Write-Output -InputObject ($Message)
		}
	}
}

Function Resolve-Error {
	<#
	.SYNOPSIS

	Enumerate error record details.

	.DESCRIPTION

	Enumerate an error record, or a collection of error record, properties. By default, the details for the last error will be enumerated.

	.PARAMETER ErrorRecord

	The error record to resolve. The default error record is the latest one: $global:Error(0). This parameter will also accept an array of error records.

	.PARAMETER Property

	The list of properties to display from the error record. Use "*" to display all properties.

	Default list of error properties is: Message, FullyQualifiedErrorId, ScriptStackTrace, PositionMessage, InnerException

	.PARAMETER GetErrorRecord

	Get error record details as represented by $_.

	.PARAMETER GetErrorInvocation

	Get error record invocation information as represented by $_.InvocationInfo.

	.PARAMETER GetErrorException

	Get error record exception details as represented by $_.Exception.

	.PARAMETER GetErrorInnerException

	Get error record inner exception details as represented by $_.Exception.InnerException. Will retrieve all inner exceptions if there is more than one.

	.INPUTS

	System.Array.

	Accepts an array of error records.

	.OUTPUTS

	System.String

	Displays the error record details.

	.EXAMPLE

	Resolve-Error

	.EXAMPLE

	Resolve-Error -Property *

	.EXAMPLE

	Resolve-Error -Property InnerException

	.EXAMPLE

	Resolve-Error -GetErrorInvocation:$false

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[AllowEmptyCollection()]
		[Array]$ErrorRecord,
		[Parameter(Mandatory = $false, Position = 1)]
		[ValidateNotNullorEmpty()]
		[String[]]$Property = ('Message', 'InnerException', 'FullyQualifiedErrorId', 'ScriptStackTrace', 'PositionMessage'),
		[Parameter(Mandatory = $false, Position = 2)]
		[Switch]$GetErrorRecord = $true,
		[Parameter(Mandatory = $false, Position = 3)]
		[Switch]$GetErrorInvocation = $true,
		[Parameter(Mandatory = $false, Position = 4)]
		[Switch]$GetErrorException = $true,
		[Parameter(Mandatory = $false, Position = 5)]
		[Switch]$GetErrorInnerException = $true
	)

	Begin {
		## If function was called without specifying an error record, then choose the latest error that occurred
		If (-not $ErrorRecord) {
			If ($global:Error.Count -eq 0) {
				#Write-Warning -Message "The `$Error collection is empty"
				Return
			} Else {
				[Array]$ErrorRecord = $global:Error[0]
			}
		}

		## Allows selecting and filtering the properties on the error object if they exist
		[ScriptBlock]$SelectProperty = {
			Param (
				[Parameter(Mandatory = $true)]
				[ValidateNotNullorEmpty()]
				$InputObject,
				[Parameter(Mandatory = $true)]
				[ValidateNotNullorEmpty()]
				[String[]]$Property
			)

			[String[]]$ObjectProperty = $InputObject | Get-Member -MemberType '*Property' | Select-Object -ExpandProperty 'Name'
			ForEach ($Prop in $Property) {
				If ($Prop -eq '*') {
					[String[]]$PropertySelection = $ObjectProperty
					Break
				} ElseIf ($ObjectProperty -contains $Prop) {
					[String[]]$PropertySelection += $Prop
				}
			}
			Write-Output -InputObject ($PropertySelection)
		}

		#  Initialize variables to avoid error if 'Set-StrictMode' is set
		$LogErrorRecordMsg = $null
		$LogErrorInvocationMsg = $null
		$LogErrorExceptionMsg = $null
		$LogErrorMessageTmp = $null
		$LogInnerMessage = $null
	}
	Process {
		If (-not $ErrorRecord) {
			Return
		}
		ForEach ($ErrRecord in $ErrorRecord) {
			## Capture Error Record
			If ($GetErrorRecord) {
				[String[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord -Property $Property
				$LogErrorRecordMsg = $ErrRecord | Select-Object -Property $SelectedProperties
			}

			## Error Invocation Information
			If ($GetErrorInvocation) {
				If ($ErrRecord.InvocationInfo) {
					[String[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord.InvocationInfo -Property $Property
					$LogErrorInvocationMsg = $ErrRecord.InvocationInfo | Select-Object -Property $SelectedProperties
				}
			}

			## Capture Error Exception
			If ($GetErrorException) {
				If ($ErrRecord.Exception) {
					[String[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord.Exception -Property $Property
					$LogErrorExceptionMsg = $ErrRecord.Exception | Select-Object -Property $SelectedProperties
				}
			}

			## Display properties in the correct order
			If ($Property -eq '*') {
				#  If all properties were chosen for display, then arrange them in the order the error object displays them by default.
				If ($LogErrorRecordMsg) {
					[Array]$LogErrorMessageTmp += $LogErrorRecordMsg
				}
				If ($LogErrorInvocationMsg) {
					[Array]$LogErrorMessageTmp += $LogErrorInvocationMsg
				}
				If ($LogErrorExceptionMsg) {
					[Array]$LogErrorMessageTmp += $LogErrorExceptionMsg
				}
			} Else {
				#  Display selected properties in our custom order
				If ($LogErrorExceptionMsg) {
					[Array]$LogErrorMessageTmp += $LogErrorExceptionMsg
				}
				If ($LogErrorRecordMsg) {
					[Array]$LogErrorMessageTmp += $LogErrorRecordMsg
				}
				If ($LogErrorInvocationMsg) {
					[Array]$LogErrorMessageTmp += $LogErrorInvocationMsg
				}
			}

			If ($LogErrorMessageTmp) {
				$LogErrorMessage = 'Error Record:'
				$LogErrorMessage += "`n-------------"
				$LogErrorMsg = $LogErrorMessageTmp | Format-List | Out-String
				$LogErrorMessage += $LogErrorMsg
			}

			## Capture Error Inner Exception(s)
			If ($GetErrorInnerException) {
				If ($ErrRecord.Exception -and $ErrRecord.Exception.InnerException) {
					$LogInnerMessage = 'Error Inner Exception(s):'
					$LogInnerMessage += "`n-------------------------"

					$ErrorInnerException = $ErrRecord.Exception.InnerException
					$Count = 0

					While ($ErrorInnerException) {
						[String]$InnerExceptionSeperator = '~' * 40

						[String[]]$SelectedProperties = & $SelectProperty -InputObject $ErrorInnerException -Property $Property
						$LogErrorInnerExceptionMsg = $ErrorInnerException | Select-Object -Property $SelectedProperties | Format-List | Out-String

						If ($Count -gt 0) {
							$LogInnerMessage += $InnerExceptionSeperator
						}
						$LogInnerMessage += $LogErrorInnerExceptionMsg

						$Count++
						$ErrorInnerException = $ErrorInnerException.InnerException
					}
				}
			}

			If ($LogErrorMessage) {
				$Output = $LogErrorMessage
			}
			If ($LogInnerMessage) {
				$Output += $LogInnerMessage
			}

			Write-Output -InputObject $Output

			If (Test-Path -LiteralPath 'variable:Output') {
				Clear-Variable -Name 'Output'
			}
			If (Test-Path -LiteralPath 'variable:LogErrorMessage') {
				Clear-Variable -Name 'LogErrorMessage'
			}
			If (Test-Path -LiteralPath 'variable:LogInnerMessage') {
				Clear-Variable -Name 'LogInnerMessage'
			}
			If (Test-Path -LiteralPath 'variable:LogErrorMessageTmp') {
				Clear-Variable -Name 'LogErrorMessageTmp'
			}
		}
	}
	End {
	}
}

<#
function Write-Log {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, HelpMessage = 'Message to write to the log file')]
		[AllowEmptyString()]
		[String] $Message,
		[Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 1, HelpMessage = 'Location of the log file to write to')]
		[String] $LogFolder = "$workingFolder_Root\Logs", #$workingFolder is defined as a Global parameter in the main script
		[Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 2, HelpMessage = 'Name of the log file to write to. Main is the default log file')]
		[String] $Log = 'Main.log',
		[Parameter(Mandatory = $false, ValueFromPipeline = $false, HelpMessage = 'LogId name of the script of the calling function')]
		[String] $LogId = $($MyInvocation.MyCommand).Name,
		[Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 3, HelpMessage = 'Severity of the log entry 1-3')]
		[ValidateSet(1, 2, 3)]
		[string] $Severity = 1,
		[Parameter(Mandatory = $false, ValueFromPipeline = $false, HelpMessage = 'The component (script name) passed as LogID to the Write-Log function including line number of invociation')]
		[string] $Component = [string]::Format('{0}:{1}', $logID, $($MyInvocation.ScriptLineNumber)),
		[Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 4, HelpMessage = 'If specified, the log file will be reset')]
		[Switch] $ResetLogFile
	)

	Begin {
		$dateTime = Get-Date
		$date = $dateTime.ToString('dd.MM.yyyy', [Globalization.CultureInfo]::InvariantCulture)
		$time = $dateTime.ToString('HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
		$logToWrite = Join-Path -Path $LogFolder -ChildPath $Log
	}

	Process {

		if ($PSBoundParameters.ContainsKey('ResetLogFile')) {

			try {

				# Check if the logfile exists. We only need to reset it if it already exists
				if (Test-Path -Path $logToWrite) {

					# Create a StreamWriter instance and open the file for writing
					$streamWriter = New-Object -TypeName System.IO.StreamWriter -ArgumentList $logToWrite

					# Write an empty string to the file without the append parameter
					$streamWriter.Write('')

					# Close the StreamWriter, which also flushes the content to the file
					$streamWriter.Close()
					Write-Host ("Log file '{0}' wiped" -f $logToWrite) -ForegroundColor Yellow

				} else {
					Write-Host ("Log file not found at '{0}'. Not restting log file" -f $logToWrite) -ForegroundColor Yellow
				}

			} catch {
				Write-Error -Message ('Unable to wipe log file. Error message: {0}' -f $_.Exception.Message)
				throw
			}

		}

		try {

			# Extract log object and construct format for log line entry
			foreach ($messageLine in $Message) {
				$logDetail = [string]::Format('<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="">', $messageLine, $time, $date, $Component, $Context, $Severity, $PID)

				# Attempt log write
				try {
					$streamWriter = New-Object -TypeName System.IO.StreamWriter -ArgumentList $logToWrite, 'Append'
					$streamWriter.WriteLine($logDetail)
					$streamWriter.Close()
				} catch {
					Write-Error -Message ("Unable to append log entry to '{0}' file. Error message: {1}" -f $logToWrite, $_.Exception.Message)

					throw
				}
			}

		} catch [System.Exception] {
			Write-Warning -Message ("Unable to append log entry to '{0}' file" -f $logToWrite)
			throw
		}
	}
}
#>

Function Get-HardwarePlatform {
	<#
	.SYNOPSIS
	Retrieves information about the hardware platform (physical or virtual)

	.DESCRIPTION
	Retrieves information about the hardware platform (physical or virtual)

	.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.

	.INPUTS
	None

	You cannot pipe objects to this function.

	.OUTPUTS
	System.String

	Returns the hardware platform (physical or virtual)

	.EXAMPLE
	Get-HardwarePlatform

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Boolean] $ContinueOnError = $true
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message 'Retrieving hardware platform information.' -Source ${CmdletName}

			$hwBios = Get-CimInstance -ClassName 'Win32_BIOS' -ErrorAction 'Stop' | Select-Object -Property 'Version', 'SerialNumber'
			$hwMakeModel = Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction 'Stop' | Select-Object -Property 'Model', 'Manufacturer'

			If ($hwBIOS.Version -match 'VRTUAL') {
				$hwType = 'Virtual:Hyper-V'
			} ElseIf ($hwBIOS.Version -match 'A M I') {
				$hwType = 'Virtual:Virtual PC'
			} ElseIf ($hwBIOS.Version -like '*Xen*') {
				$hwType = 'Virtual:Xen'
			} ElseIf ($hwBIOS.SerialNumber -like '*VMware*') {
				$hwType = 'Virtual:VMWare'
			} ElseIf ($hwBIOS.SerialNumber -like '*Parallels*') {
				$hwType = 'Virtual:Parallels'
			} ElseIf (($hwMakeModel.Manufacturer -like '*Microsoft*') -and ($hwMakeModel.Model -notlike '*Surface*')) {
				$hwType = 'Virtual:Hyper-V'
			} ElseIf ($hwMakeModel.Manufacturer -like '*VMWare*') {
				$hwType = 'Virtual:VMWare'
			} ElseIf ($hwMakeModel.Manufacturer -like '*Parallels*') {
				$hwType = 'Virtual:Parallels'
			} ElseIf ($hwMakeModel.Model -like '*Virtual*') {
				$hwType = 'Virtual'
			} Else {
				$hwType = 'Physical'
			}

			Write-Output -InputObject ($hwType)

		} Catch {
			Write-Log -Message "Failed to retrieve hardware platform information. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to retrieve hardware platform information: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}

Function Get-FreeDiskSpace {
	<#
	.SYNOPSIS
	Retrieves the free disk space in MB on a particular drive (defaults to system drive)

	.DESCRIPTION
	Retrieves the free disk space in MB on a particular drive (defaults to system drive)

	.PARAMETER Drive
	Drive to check free disk space on

	.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.

	.INPUTS
	None

	You cannot pipe objects to this function.

	.OUTPUTS
	System.Double

	Returns the free disk space in MB

	.EXAMPLE
	Get-FreeDiskSpace -Drive 'C:'

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[String] $Drive = $envSystemDrive,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Boolean] $ContinueOnError = $true
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message "Retrieving free disk space for drive [$Drive]." -Source ${CmdletName}

			$disk = Get-CimInstance -ClassName 'Win32_LogicalDisk' -Filter "DeviceID='$Drive'" -ErrorAction 'Stop'

			[Double]$freeDiskSpace = [Math]::Round($disk.FreeSpace / 1MB)

			Write-Log -Message "Free disk space for drive [$Drive]: [$freeDiskSpace MB]." -Source ${CmdletName}
			Write-Output -InputObject ($freeDiskSpace)

		} Catch {
			Write-Log -Message "Failed to retrieve free disk space for drive [$Drive]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}

			If (-not $ContinueOnError) {
				Throw "Failed to retrieve free disk space for drive [$Drive]: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}

#region    SCCM Tools

Function Invoke-SCCMTask {
	<#
	.SYNOPSIS
	Triggers SCCM to invoke the requested schedule task id.

	.DESCRIPTION
	Triggers SCCM to invoke the requested schedule task id.

	.PARAMETER ScheduleId
	Name of the schedule id to trigger.

	Options: HardwareInventory, SoftwareInventory, HeartbeatDiscovery, SoftwareInventoryFileCollection, RequestMachinePolicy, EvaluateMachinePolicy,
	LocationServicesCleanup, SoftwareMeteringReport, SourceUpdate, PolicyAgentCleanup, RequestMachinePolicy2, CertificateMaintenance, PeerDistributionPointStatus,
	PeerDistributionPointProvisioning, ComplianceIntervalEnforcement, SoftwareUpdatesAgentAssignmentEvaluation, UploadStateMessage, StateMessageManager,
	SoftwareUpdatesScan, AMTProvisionCycle, UpdateStorePolicy, StateSystemBulkSend, ApplicationManagerPolicyAction, PowerManagementStartSummarizer

	.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.

	.INPUTS
	None

	You cannot pipe objects to this function.

	.OUTPUTS
	None

	This function does not return any objects.

	.EXAMPLE
	Invoke-SCCMTask 'SoftwareUpdatesScan'

	.EXAMPLE
	Invoke-SCCMTask

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateSet('HardwareInventory', 'SoftwareInventory', 'HeartbeatDiscovery', 'SoftwareInventoryFileCollection', 'RequestMachinePolicy', 'EvaluateMachinePolicy', 'LocationServicesCleanup', 'SoftwareMeteringReport', 'SourceUpdate', 'PolicyAgentCleanup', 'RequestMachinePolicy2', 'CertificateMaintenance', 'PeerDistributionPointStatus', 'PeerDistributionPointProvisioning', 'ComplianceIntervalEnforcement', 'SoftwareUpdatesAgentAssignmentEvaluation', 'UploadStateMessage', 'StateMessageManager', 'SoftwareUpdatesScan', 'AMTProvisionCycle', 'UpdateStorePolicy', 'StateSystemBulkSend', 'ApplicationManagerPolicyAction', 'PowerManagementStartSummarizer')]
		[String]$ScheduleID,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Boolean]$ContinueOnError = $true
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message "Invoke SCCM Schedule Task ID [$ScheduleId]..." -Source ${CmdletName}

			## Make sure SCCM client is installed and running
			Write-Log -Message 'Checking to see if SCCM Client service [ccmexec] is installed and running.' -Source ${CmdletName}
			If (Test-ServiceExists -Name 'ccmexec') {
				If ($(Get-Service -Name 'ccmexec' -ErrorAction 'SilentlyContinue').Status -ne 'Running') {
					Throw "SCCM Client Service [ccmexec] exists but it is not in a 'Running' state."
				}
			} Else {
				Throw 'SCCM Client Service [ccmexec] does not exist. The SCCM Client may not be installed.'
			}

			## Determine the SCCM Client Version
			Try {

				[Version]$SCCMClientVersion = Get-CimInstance -Namespace 'ROOT\CCM' -ClassName 'CCM_InstalledComponent' -ErrorAction 'Stop' | Where-Object { $_.Name -eq 'SmsClient' } | Select-Object -ExpandProperty 'Version' -ErrorAction 'Stop'

				If ($SCCMClientVersion) {
					Write-Log -Message "Installed SCCM Client Version Number [$SCCMClientVersion]." -Source ${CmdletName}
				} Else {
					Write-Log -Message "Failed to determine the SCCM client version number. `r`n$(Resolve-Error)" -Severity 2 -Source ${CmdletName}
					Throw 'Failed to determine the SCCM client version number.'
				}
			} Catch {
				Write-Log -Message "Failed to determine the SCCM client version number. `r`n$(Resolve-Error)" -Severity 2 -Source ${CmdletName}
				Throw 'Failed to determine the SCCM client version number.'
			}

			## Create a hashtable of Schedule IDs compatible with SCCM Client 2007
			[Hashtable]$ScheduleIds = @{
				HardwareInventory                        = '{00000000-0000-0000-0000-000000000001}'; # Hardware Inventory Collection Task
				SoftwareInventory                        = '{00000000-0000-0000-0000-000000000002}'; # Software Inventory Collection Task
				HeartbeatDiscovery                       = '{00000000-0000-0000-0000-000000000003}'; # Heartbeat Discovery Cycle
				SoftwareInventoryFileCollection          = '{00000000-0000-0000-0000-000000000010}'; # Software Inventory File Collection Task
				RequestMachinePolicy                     = '{00000000-0000-0000-0000-000000000021}'; # Request Machine Policy Assignments
				EvaluateMachinePolicy                    = '{00000000-0000-0000-0000-000000000022}'; # Evaluate Machine Policy Assignments
				RefreshDefaultMp                         = '{00000000-0000-0000-0000-000000000023}'; # Refresh Default MP Task
				RefreshLocationServices                  = '{00000000-0000-0000-0000-000000000024}'; # Refresh Location Services Task
				LocationServicesCleanup                  = '{00000000-0000-0000-0000-000000000025}'; # Location Services Cleanup Task
				SoftwareMeteringReport                   = '{00000000-0000-0000-0000-000000000031}'; # Software Metering Report Cycle
				SourceUpdate                             = '{00000000-0000-0000-0000-000000000032}'; # Source Update Manage Update Cycle
				PolicyAgentCleanup                       = '{00000000-0000-0000-0000-000000000040}'; # Policy Agent Cleanup Cycle
				RequestMachinePolicy2                    = '{00000000-0000-0000-0000-000000000042}'; # Request Machine Policy Assignments
				CertificateMaintenance                   = '{00000000-0000-0000-0000-000000000051}'; # Certificate Maintenance Cycle
				PeerDistributionPointStatus              = '{00000000-0000-0000-0000-000000000061}'; # Peer Distribution Point Status Task
				PeerDistributionPointProvisioning        = '{00000000-0000-0000-0000-000000000062}'; # Peer Distribution Point Provisioning Status Task
				ComplianceIntervalEnforcement            = '{00000000-0000-0000-0000-000000000071}'; # Compliance Interval Enforcement
				SoftwareUpdatesAgentAssignmentEvaluation = '{00000000-0000-0000-0000-000000000108}'; # Software Updates Agent Assignment Evaluation Cycle
				UploadStateMessage                       = '{00000000-0000-0000-0000-000000000111}'; # Send Unsent State Messages
				StateMessageManager                      = '{00000000-0000-0000-0000-000000000112}'; # State Message Manager Task
				SoftwareUpdatesScan                      = '{00000000-0000-0000-0000-000000000113}'; # Force Update Scan
				AMTProvisionCycle                        = '{00000000-0000-0000-0000-000000000120}'; # AMT Provision Cycle
			}

			## If SCCM 2012 Client or higher, modify hashtabe containing Schedule IDs so that it only has the ones compatible with this version of the SCCM client
			If ($SCCMClientVersion.Major -ge 5) {
				$ScheduleIds.Remove('PeerDistributionPointStatus')
				$ScheduleIds.Remove('PeerDistributionPointProvisioning')
				$ScheduleIds.Remove('ComplianceIntervalEnforcement')
				$ScheduleIds.Add('UpdateStorePolicy', '{00000000-0000-0000-0000-000000000114}') # Update Store Policy
				$ScheduleIds.Add('StateSystemBulkSend', '{00000000-0000-0000-0000-000000000116}') # State System Policy Bulk Send Low
				$ScheduleIds.Add('ApplicationManagerPolicyAction', '{00000000-0000-0000-0000-000000000121}') # Application Manager Policy Action
				$ScheduleIds.Add('PowerManagementStartSummarizer', '{00000000-0000-0000-0000-000000000131}') # Power Management Start Summarizer
			}

			## Determine if the requested Schedule ID is available on this version of the SCCM Client
			If (-not $ScheduleIds.ContainsKey($ScheduleId)) {
				Throw "The requested ScheduleId [$ScheduleId] is not available with this version of the SCCM Client [$SCCMClientVersion]."
			}

			## Trigger SCCM task
			Write-Log -Message "Triggering SCCM Task ID [$ScheduleId]." -Source ${CmdletName}
			[Management.ManagementClass]$SmsClient = [WMIClass]'ROOT\CCM:SMS_Client'
			$null = $SmsClient.TriggerSchedule($ScheduleIds.$ScheduleID)

		} Catch {
			Write-Log -Message "Failed to trigger SCCM Schedule Task ID [$($ScheduleIds.$ScheduleId)]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to trigger SCCM Schedule Task ID [$($ScheduleIds.$ScheduleId)]: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}

Function Install-SCCMSoftwareUpdates {
	<#
	.SYNOPSIS

	Scans for outstanding SCCM updates to be installed and installs the pending updates.

	.DESCRIPTION

	Scans for outstanding SCCM updates to be installed and installs the pending updates.

	Only compatible with SCCM 2012 Client or higher. This function can take several minutes to run.

	.PARAMETER SoftwareUpdatesScanWaitInSeconds

	The amount of time to wait in seconds for the software updates scan to complete. Default is: 180 seconds.

	.PARAMETER WaitForPendingUpdatesTimeout

	The amount of time to wait for missing and pending updates to install before exiting the function. Default is: 45 minutes.

	.PARAMETER ContinueOnError

	Continue if an error is encountered. Default is: $true.

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	None

	This function does not return any objects.

	.EXAMPLE

	Install-SCCMSoftwareUpdates

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Int32]$SoftwareUpdatesScanWaitInSeconds = 180,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Timespan]$WaitForPendingUpdatesTimeout = $(New-TimeSpan -Minutes 45),
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Boolean]$ContinueOnError = $true
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message 'Scanning for and installing pending SCCM software updates.' -Source ${CmdletName}

			## Make sure SCCM client is installed and running
			Write-Log -Message 'Checking to see if SCCM Client service [ccmexec] is installed and running.' -Source ${CmdletName}
			If (Test-ServiceExists -Name 'ccmexec') {
				If ($(Get-Service -Name 'ccmexec' -ErrorAction 'SilentlyContinue').Status -ne 'Running') {
					Throw "SCCM Client Service [ccmexec] exists but it is not in a 'Running' state."
				}
			} Else {
				Throw 'SCCM Client Service [ccmexec] does not exist. The SCCM Client may not be installed.'
			}

			## Determine the SCCM Client Version
			Try {
				[Version]$SCCMClientVersion = Get-WmiObject -Namespace 'ROOT\CCM' -Class 'CCM_InstalledComponent' -ErrorAction 'Stop' | Where-Object { $_.Name -eq 'SmsClient' } | Select-Object -ExpandProperty 'Version' -ErrorAction 'Stop'
				If ($SCCMClientVersion) {
					Write-Log -Message "Installed SCCM Client Version Number [$SCCMClientVersion]." -Source ${CmdletName}
				} Else {
					Write-Log -Message "Failed to determine the SCCM client version number. `r`n$(Resolve-Error)" -Severity 2 -Source ${CmdletName}
					Throw 'Failed to determine the SCCM client version number.'
				}
			} Catch {
				Write-Log -Message "Failed to determine the SCCM client version number. `r`n$(Resolve-Error)" -Severity 2 -Source ${CmdletName}
				Throw 'Failed to determine the SCCM client version number.'
			}
			#  If SCCM 2007 Client or lower, exit function
			If ($SCCMClientVersion.Major -le 4) {
				Throw 'SCCM 2007 or lower, which is incompatible with this function, was detected on this system.'
			}

			$StartTime = Get-Date
			## Trigger SCCM client scan for Software Updates
			Write-Log -Message 'Triggering SCCM client scan for Software Updates...' -Source ${CmdletName}
			Invoke-SCCMTask -ScheduleId 'SoftwareUpdatesScan'

			Write-Log -Message "The SCCM client scan for Software Updates has been triggered. The script is suspended for [$SoftwareUpdatesScanWaitInSeconds] seconds to let the update scan finish." -Source ${CmdletName}
			Start-Sleep -Seconds $SoftwareUpdatesScanWaitInSeconds

			## Find the number of missing updates
			Try {
				Write-Log -Message 'Getting the number of missing updates...' -Source ${CmdletName}
				[Management.ManagementObject[]]$CMMissingUpdates = @(Get-WmiObject -Namespace 'ROOT\CCM\ClientSDK' -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -ErrorAction 'Stop')
			} Catch {
				Write-Log -Message "Failed to find the number of missing software updates. `r`n$(Resolve-Error)" -Severity 2 -Source ${CmdletName}
				Throw 'Failed to find the number of missing software updates.'
			}

			## Install missing updates and wait for pending updates to finish installing
			If ($CMMissingUpdates.Count) {
				#  Install missing updates
				Write-Log -Message "Installing missing updates. The number of missing updates is [$($CMMissingUpdates.Count)]." -Source ${CmdletName}
				$CMInstallMissingUpdates = (Get-WmiObject -Namespace 'ROOT\CCM\ClientSDK' -Class 'CCM_SoftwareUpdatesManager' -List).InstallUpdates($CMMissingUpdates)

				#  Wait for pending updates to finish installing or the timeout value to expire
				Do {
					Start-Sleep -Seconds 60
					[Array]$CMInstallPendingUpdates = @(Get-WmiObject -Namespace 'ROOT\CCM\ClientSDK' -Query 'SELECT * FROM CCM_SoftwareUpdate WHERE EvaluationState = 6 or EvaluationState = 7')
					Write-Log -Message "The number of updates pending installation is [$($CMInstallPendingUpdates.Count)]." -Source ${CmdletName}
				} While (($CMInstallPendingUpdates.Count -ne 0) -and ((New-TimeSpan -Start $StartTime -End $(Get-Date)) -lt $WaitForPendingUpdatesTimeout))
			} Else {
				Write-Log -Message 'There are no missing updates.' -Source ${CmdletName}
			}
		} Catch {
			Write-Log -Message "Failed to trigger installation of missing software updates. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to trigger installation of missing software updates: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion SCCM Tools

Function Update-GroupPolicy {
	<#
	.SYNOPSIS

	Performs a gpupdate command to refresh Group Policies on the local machine.

	.DESCRIPTION

	Performs a gpupdate command to refresh Group Policies on the local machine.

	.PARAMETER ContinueOnError

	Continue if an error is encountered. Default is: $true.

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	None

	This function does not return any objects.

	.EXAMPLE

	Update-GroupPolicy

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Boolean]$ContinueOnError = $true
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		[String[]]$GPUpdateCmds = '/C echo N | gpupdate.exe /Target:Computer /Force', '/C echo N | gpupdate.exe /Target:User /Force'
		[Int32]$InstallCount = 0

		ForEach ($GPUpdateCmd in $GPUpdateCmds) {

			Try {
				If ($InstallCount -eq 0) {
					[String]$InstallMsg = 'Updating Group Policies for the Machine'
				} Else {
					[String]$InstallMsg = 'Updating Group Policies for the User'
				}

				Write-Log -Message "$($InstallMsg)..." -Source ${CmdletName}
				[PSObject]$ExecuteResult = Execute-Process -Path "$envWinDir\System32\cmd.exe" -Parameters $GPUpdateCmd -WindowStyle 'Hidden' -PassThru -ExitOnProcessFailure $false

				If ($ExecuteResult.ExitCode -ne 0) {
					If ($ExecuteResult.ExitCode -eq 60002) {
						$Message = "Execute-Process function failed with exit code [$($ExecuteResult.ExitCode)]."
						Write-Log -Message $Message -Source ${CmdletName} -Severity 3
					} Else {
						$Message = "gpupdate.exe failed with exit code [$($ExecuteResult.ExitCode)]."
						Write-Log -Message $Message -Source ${CmdletName} -Severity 3
					}
				}

				$InstallCount++

			} Catch {
				Write-Log -Message "$($InstallMsg) failed. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}

				If (-not $ContinueOnError) {
					Throw "$($InstallMsg) failed: $($_.Exception.Message)"

				}

				Continue
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}

#region Function Test-ServiceExists
Function Test-ServiceExists {
	<#
	.SYNOPSIS
	Check to see if a service exists.

	.DESCRIPTION
	Check to see if a service exists (using WMI method because Get-Service will generate ErrorRecord if service doesn't exist).

	.PARAMETER Name
	Specify the name of the service.

	Note: Service name can be found by executing "Get-Service | Format-Table -AutoSize -Wrap" or by using the properties screen of a service in services.msc.

	.PARAMETER ComputerName
	Specify the name of the computer. Default is: the local computer.

	.PARAMETER PassThru
	Return the WMI service object. To see all the properties use: Test-ServiceExists -Name 'spooler' -PassThru | Get-Member

	.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.

	.INPUTS
	None

	You cannot pipe objects to this function.

	.OUTPUTS
	None

	This function does not return any objects.

	.EXAMPLE
	Test-ServiceExists -Name 'wuauserv'

	.EXAMPLE
	Test-ServiceExists -Name 'testservice' -PassThru | Where-Object { $_ } | ForEach-Object { $_.Delete() }

	Check if a service exists and then delete it by using the -PassThru parameter.

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]$ComputerName = $env:ComputerName,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Switch]$PassThru,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Boolean]$ContinueOnError = $true
	)
	Begin {

		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

	}
	Process {

		Try {
			$ServiceObject = Get-CimInstance -ComputerName $ComputerName -Class 'Win32_Service' -Filter "Name='$Name'" -ErrorAction 'Stop'
			# If nothing is returned from Win32_Service, check Win32_BaseService
			If (-not $ServiceObject) {
				$ServiceObject = Get-CimInstance -ComputerName $ComputerName -Class 'Win32_BaseService' -Filter "Name='$Name'" -ErrorAction 'Stop'
			}

			If ($ServiceObject) {
				Write-Log -Message "Service [$Name] exists." -Source ${CmdletName}

				If ($PassThru) {
					Write-Output -InputObject ($ServiceObject)
				} Else {
					Write-Output -InputObject ($true)
				}

			} Else {
				Write-Log -Message "Service [$Name] does not exist." -Source ${CmdletName}

				If ($PassThru) {
					Write-Output -InputObject ($ServiceObject)
				} Else {
					Write-Output -InputObject ($false)
				}

			}
		} Catch {
			Write-Log -Message "Failed check to see if service [$Name] exists." -Severity 3 -Source ${CmdletName}

			If (-not $ContinueOnError) {
				Throw "Failed check to see if service [$Name] exists: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Stop-ServiceAndDependencies
Function Stop-ServiceAndDependencies {
	<#
	.SYNOPSIS
	Stop Windows service and its dependencies.

	.DESCRIPTION
	Stop Windows service and its dependencies.

	.PARAMETER Name
	Specify the name of the service.

	.PARAMETER ComputerName
	Specify the name of the computer. Default is: the local computer.

	.PARAMETER SkipServiceExistsTest
	Choose to skip the test to check whether or not the service exists if it was already done outside of this function.

	.PARAMETER SkipDependentServices
	Choose to skip checking for and stopping dependent services. Default is: $false.

	.PARAMETER PendingStatusWait
	The amount of time to wait for a service to get out of a pending state before continuing. Default is 60 seconds.

	.PARAMETER PassThru
	Return the System.ServiceProcess.ServiceController service object.

	.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.

	.INPUTS
	None

	You cannot pipe objects to this function.

	.OUTPUTS
	System.ServiceProcess.ServiceController.

	Returns the service object.

	.EXAMPLE
	Stop-ServiceAndDependencies -Name 'wuauserv'

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]$ComputerName = $env:ComputerName,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Switch]$SkipServiceExistsTest,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Switch]$SkipDependentServices,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Timespan]$PendingStatusWait = (New-TimeSpan -Seconds 60),
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Switch]$PassThru,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Boolean]$ContinueOnError = $true
	)
	Begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			## Check to see if the service exists
			If ((-not $SkipServiceExistsTest) -and (-not (Test-ServiceExists -ComputerName $ComputerName -Name $Name -ContinueOnError $false))) {
				Write-Log -Message "Service [$Name] does not exist." -Source ${CmdletName} -Severity 2
				Throw "Service [$Name] does not exist."
			}

			## Get the service object
			Write-Log -Message "Getting the service object for service [$Name]." -Source ${CmdletName}
			[ServiceProcess.ServiceController]$Service = Get-Service -ComputerName $ComputerName -Name $Name -ErrorAction 'Stop'

			## Wait up to 60 seconds if service is in a pending state
			[String[]]$PendingStatus = 'ContinuePending', 'PausePending', 'StartPending', 'StopPending'

			If ($PendingStatus -contains $Service.Status) {
				Switch ($Service.Status) {
					'ContinuePending' {
						$DesiredStatus = 'Running'
					}
					'PausePending' {
						$DesiredStatus = 'Paused'
					}
					'StartPending' {
						$DesiredStatus = 'Running'
					}
					'StopPending' {
						$DesiredStatus = 'Stopped'
					}
				}

				Write-Log -Message "Waiting for up to [$($PendingStatusWait.TotalSeconds)] seconds to allow service pending status [$($Service.Status)] to reach desired status [$DesiredStatus]." -Source ${CmdletName}

				$Service.WaitForStatus([ServiceProcess.ServiceControllerStatus]$DesiredStatus, $PendingStatusWait)
				$Service.Refresh()

			}

			## Discover if the service is currently running
			Write-Log -Message "Service [$($Service.ServiceName)] with display name [$($Service.DisplayName)] has a status of [$($Service.Status)]." -Source ${CmdletName}

			If ($Service.Status -ne 'Stopped') {

				#  Discover all dependent services that are running and stop them
				If (-not $SkipDependentServices) {
					Write-Log -Message "Discovering all dependent service(s) for service [$Name] which are not 'Stopped'." -Source ${CmdletName}
					[ServiceProcess.ServiceController[]]$DependentServices = Get-Service -ComputerName $ComputerName -Name $Service.ServiceName -DependentServices -ErrorAction 'Stop' | Where-Object { $_.Status -ne 'Stopped' }

					If ($DependentServices) {

						ForEach ($DependentService in $DependentServices) {
							Write-Log -Message "Stopping dependent service [$($DependentService.ServiceName)] with display name [$($DependentService.DisplayName)] and a status of [$($DependentService.Status)]." -Source ${CmdletName}
							Try {
								Stop-Service -InputObject (Get-Service -ComputerName $ComputerName -Name $DependentService.ServiceName -ErrorAction 'Stop') -Force -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'
							} Catch {
								Write-Log -Message "Failed to stop dependent service [$($DependentService.ServiceName)] with display name [$($DependentService.DisplayName)] and a status of [$($DependentService.Status)]. Continue..." -Severity 2 -Source ${CmdletName}
								Continue
							}
						}

					} Else {
						Write-Log -Message "Dependent service(s) were not discovered for service [$Name]." -Source ${CmdletName}
					}
				}

				#  Stop the parent service
				Write-Log -Message "Stopping parent service [$($Service.ServiceName)] with display name [$($Service.DisplayName)]." -Source ${CmdletName}
				[ServiceProcess.ServiceController]$Service = Stop-Service -InputObject (Get-Service -ComputerName $ComputerName -Name $Service.ServiceName -ErrorAction 'Stop') -Force -PassThru -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'

			}
		} Catch {

			Write-Log -Message "Failed to stop the service [$Name]. `r`n$(Resolve-Error)" -Source ${CmdletName} -Severity 3

			If (-not $ContinueOnError) {
				Throw "Failed to stop the service [$Name]: $($_.Exception.Message)"
			}

		} Finally {
			#  Return the service object if option selected
			If ($PassThru -and $Service) {
				Write-Output -InputObject ($Service)
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Start-ServiceAndDependencies
Function Start-ServiceAndDependencies {
	<#
	.SYNOPSIS

	Start Windows service and its dependencies.

	.DESCRIPTION

	Start Windows service and its dependencies.

	.PARAMETER Name

	Specify the name of the service.

	.PARAMETER ComputerName

	Specify the name of the computer. Default is: the local computer.

	.PARAMETER SkipServiceExistsTest

	Choose to skip the test to check whether or not the service exists if it was already done outside of this function.

	.PARAMETER SkipDependentServices

	Choose to skip checking for and starting dependent services. Default is: $false.

	.PARAMETER PendingStatusWait

	The amount of time to wait for a service to get out of a pending state before continuing. Default is 60 seconds.

	.PARAMETER PassThru

	Return the System.ServiceProcess.ServiceController service object.

	.PARAMETER ContinueOnError

	Continue if an error is encountered. Default is: $true.

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	System.ServiceProcess.ServiceController.

	Returns the service object.

	.EXAMPLE

	Start-ServiceAndDependencies -Name 'wuauserv'

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]$ComputerName = $env:ComputerName,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Switch]$SkipServiceExistsTest,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Switch]$SkipDependentServices,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Timespan]$PendingStatusWait = (New-TimeSpan -Seconds 60),
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Switch]$PassThru,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Boolean]$ContinueOnError = $true
	)
	Begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			## Check to see if the service exists
			If ((-not $SkipServiceExistsTest) -and (-not (Test-ServiceExists -ComputerName $ComputerName -Name $Name -ContinueOnError $false))) {
				Write-Log -Message "Service [$Name] does not exist." -Source ${CmdletName} -Severity 2
				Throw "Service [$Name] does not exist."
			}

			## Get the service object
			Write-Log -Message "Getting the service object for service [$Name]." -Source ${CmdletName}
			[ServiceProcess.ServiceController]$Service = Get-Service -ComputerName $ComputerName -Name $Name -ErrorAction 'Stop'
			## Wait up to 60 seconds if service is in a pending state
			[String[]]$PendingStatus = 'ContinuePending', 'PausePending', 'StartPending', 'StopPending'
			If ($PendingStatus -contains $Service.Status) {
				Switch ($Service.Status) {
					'ContinuePending' {
						$DesiredStatus = 'Running'
					}
					'PausePending' {
						$DesiredStatus = 'Paused'
					}
					'StartPending' {
						$DesiredStatus = 'Running'
					}
					'StopPending' {
						$DesiredStatus = 'Stopped'
					}
				}
				Write-Log -Message "Waiting for up to [$($PendingStatusWait.TotalSeconds)] seconds to allow service pending status [$($Service.Status)] to reach desired status [$DesiredStatus]." -Source ${CmdletName}
				$Service.WaitForStatus([ServiceProcess.ServiceControllerStatus]$DesiredStatus, $PendingStatusWait)
				$Service.Refresh()
			}
			## Discover if the service is currently stopped
			Write-Log -Message "Service [$($Service.ServiceName)] with display name [$($Service.DisplayName)] has a status of [$($Service.Status)]." -Source ${CmdletName}
			If ($Service.Status -ne 'Running') {
				#  Start the parent service
				Write-Log -Message "Starting parent service [$($Service.ServiceName)] with display name [$($Service.DisplayName)]." -Source ${CmdletName}
				[ServiceProcess.ServiceController]$Service = Start-Service -InputObject (Get-Service -ComputerName $ComputerName -Name $Service.ServiceName -ErrorAction 'Stop') -PassThru -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'

				#  Discover all dependent services that are stopped and start them
				If (-not $SkipDependentServices) {
					Write-Log -Message "Discover all dependent service(s) for service [$Name] which are not 'Running'." -Source ${CmdletName}
					[ServiceProcess.ServiceController[]]$DependentServices = Get-Service -ComputerName $ComputerName -Name $Service.ServiceName -DependentServices -ErrorAction 'Stop' | Where-Object { $_.Status -ne 'Running' }
					If ($DependentServices) {
						ForEach ($DependentService in $DependentServices) {
							Write-Log -Message "Starting dependent service [$($DependentService.ServiceName)] with display name [$($DependentService.DisplayName)] and a status of [$($DependentService.Status)]." -Source ${CmdletName}
							Try {
								Start-Service -InputObject (Get-Service -ComputerName $ComputerName -Name $DependentService.ServiceName -ErrorAction 'Stop') -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'
							} Catch {
								Write-Log -Message "Failed to start dependent service [$($DependentService.ServiceName)] with display name [$($DependentService.DisplayName)] and a status of [$($DependentService.Status)]. Continue..." -Severity 2 -Source ${CmdletName}
								Continue
							}
						}
					} Else {
						Write-Log -Message "Dependent service(s) were not discovered for service [$Name]." -Source ${CmdletName}
					}
				}
			}
		} Catch {
			Write-Log -Message "Failed to start the service [$Name]. `r`n$(Resolve-Error)" -Source ${CmdletName} -Severity 3
			If (-not $ContinueOnError) {
				Throw "Failed to start the service [$Name]: $($_.Exception.Message)"
			}
		} Finally {
			#  Return the service object if option selected
			If ($PassThru -and $Service) {
				Write-Output -InputObject ($Service)
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Get-ServiceStartMode
Function Get-ServiceStartMode {
	<#
	.SYNOPSIS

	Get the service startup mode.

	.DESCRIPTION

	Get the service startup mode.

	.PARAMETER Name

	Specify the name of the service.

	.PARAMETER ComputerName

	Specify the name of the computer. Default is: the local computer.

	.PARAMETER ContinueOnError

	Continue if an error is encountered. Default is: $true.

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	System.ServiceProcess.ServiceController.

	Returns the service object.

	.EXAMPLE

	Get-ServiceStartMode -Name 'wuauserv'

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdLetBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]$ComputerName = $env:ComputerName,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Boolean]$ContinueOnError = $true
	)
	Begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message "Getting the service [$Name] startup mode." -Source ${CmdletName}
			[String]$ServiceStartMode = (Get-WmiObject -ComputerName $ComputerName -Class 'Win32_Service' -Filter "Name='$Name'" -Property 'StartMode' -ErrorAction 'Stop').StartMode
			## If service start mode is set to 'Auto', change value to 'Automatic' to be consistent with 'Set-ServiceStartMode' function
			If ($ServiceStartMode -eq 'Auto') {
				$ServiceStartMode = 'Automatic'
			}

			## If on Windows Vista or higher, check to see if service is set to Automatic (Delayed Start)
			If (($ServiceStartMode -eq 'Automatic') -and (([Version]$envOSVersion).Major -gt 5)) {
				Try {
					[String]$ServiceRegistryPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$Name"
					[Int32]$DelayedAutoStart = Get-ItemProperty -LiteralPath $ServiceRegistryPath -ErrorAction 'Stop' | Select-Object -ExpandProperty 'DelayedAutoStart' -ErrorAction 'Stop'
					If ($DelayedAutoStart -eq 1) {
						$ServiceStartMode = 'Automatic (Delayed Start)'
					}
				} Catch {
				}
			}

			Write-Log -Message "Service [$Name] startup mode is set to [$ServiceStartMode]." -Source ${CmdletName}
			Write-Output -InputObject ($ServiceStartMode)
		} Catch {
			Write-Log -Message "Failed to get the service [$Name] startup mode. `r`n$(Resolve-Error)" -Source ${CmdletName} -Severity 3
			If (-not $ContinueOnError) {
				Throw "Failed to get the service [$Name] startup mode: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Set-ServiceStartMode
Function Set-ServiceStartMode {
	<#
	.SYNOPSIS

	Set the service startup mode.

	.DESCRIPTION

	Set the service startup mode.

	.PARAMETER Name

	Specify the name of the service.

	.PARAMETER ComputerName

	Specify the name of the computer. Default is: the local computer.

	.PARAMETER StartMode

	Specify startup mode for the service. Options: Automatic, Automatic (Delayed Start), Manual, Disabled, Boot, System.

	.PARAMETER ContinueOnError

	Continue if an error is encountered. Default is: $true.

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	None

	This function does not return any objects.

	.EXAMPLE

	Set-ServiceStartMode -Name 'wuauserv' -StartMode 'Automatic (Delayed Start)'

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdLetBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]$ComputerName = $env:ComputerName,
		[Parameter(Mandatory = $true)]
		[ValidateSet('Automatic', 'Automatic (Delayed Start)', 'Manual', 'Disabled', 'Boot', 'System')]
		[String]$StartMode,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Boolean]$ContinueOnError = $true
	)
	Begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			## If on lower than Windows Vista and 'Automatic (Delayed Start)' selected, then change to 'Automatic' because 'Delayed Start' is not supported.
			If (($StartMode -eq 'Automatic (Delayed Start)') -and (([Version]$envOSVersion).Major -lt 6)) {
				$StartMode = 'Automatic'
			}

			Write-Log -Message "Set service [$Name] startup mode to [$StartMode]." -Source ${CmdletName}

			## Set the name of the start up mode that will be passed to sc.exe
			[String]$ScExeStartMode = $StartMode
			Switch ($StartMode) {
				'Automatic' {
					$ScExeStartMode = 'Auto'; Break
				}
				'Automatic (Delayed Start)' {
					$ScExeStartMode = 'Delayed-Auto'; Break
				}
				'Manual' {
					$ScExeStartMode = 'Demand'; Break
				}
			}

			## Set the start up mode using sc.exe. Note: we found that the ChangeStartMode method in the Win32_Service WMI class set services to 'Automatic (Delayed Start)' even when you specified 'Automatic' on Win7, Win8, and Win10.
			$ChangeStartMode = & "$envWinDir\System32\sc.exe" config $Name start= $ScExeStartMode

			If ($global:LastExitCode -ne 0) {
				Throw "sc.exe failed with exit code [$($global:LastExitCode)] and message [$ChangeStartMode]."
			}

			Write-Log -Message "Successfully set service [$Name] startup mode to [$StartMode]." -Source ${CmdletName}
		} Catch {
			Write-Log -Message "Failed to set service [$Name] startup mode to [$StartMode]. `r`n$(Resolve-Error)" -Source ${CmdletName} -Severity 3
			If (-not $ContinueOnError) {
				Throw "Failed to set service [$Name] startup mode to [$StartMode]: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Execute-Process
Function Execute-Process {
	<#
	.SYNOPSIS
	Execute a process with optional arguments, working directory, window style.

	.DESCRIPTION
	Executes a process, e.g. a file included in the Files directory of the App Deploy Toolkit, or a file on the local machine.
	Provides various options for handling the return codes (see Parameters).

	.PARAMETER Path
	Path to the file to be executed. If the file is located directly in the "Files" directory of the App Deploy Toolkit, only the file name needs to be specified.
	Otherwise, the full path of the file must be specified. If the files is in a subdirectory of "Files", use the "$dirFiles" variable as shown in the example.

	.PARAMETER Parameters
	Arguments to be passed to the executable

	.PARAMETER SecureParameters
	Hides all parameters passed to the executable from the Toolkit log file

	.PARAMETER WindowStyle
	Style of the window of the process executed. Options: Normal, Hidden, Maximized, Minimized. Default: Normal.
	Note: Not all processes honor WindowStyle. WindowStyle is a recommendation passed to the process. They can choose to ignore it.
	Only works for native Windows GUI applications. If the WindowStyle is set to Hidden, UseShellExecute should be set to $true.

	.PARAMETER CreateNoWindow
	Specifies whether the process should be started with a new window to contain it. Only works for Console mode applications. UseShellExecute should be set to $false.
	Default is false.

	.PARAMETER WorkingDirectory
	The working directory used for executing the process. Defaults to the directory of the file being executed.
	Parameter UseShellExecute affects this parameter.

	.PARAMETER NoWait
	Immediately continue after executing the process.

	.PARAMETER PassThru
	If NoWait is not specified, returns an object with ExitCode, STDOut and STDErr output from the process. If NoWait is specified, returns an object with Id, Handle and ProcessName.

	.PARAMETER WaitForMsiExec
	Sometimes an EXE bootstrapper will launch an MSI install. In such cases, this variable will ensure that
	this function waits for the msiexec engine to become available before starting the install.

	.PARAMETER MsiExecWaitTime
	Specify the length of time in seconds to wait for the msiexec engine to become available. Default: 600 seconds (10 minutes).

	.PARAMETER IgnoreExitCodes
	List the exit codes to ignore or * to ignore all exit codes.

	.PARAMETER PriorityClass
	Specifies priority class for the process. Options: Idle, Normal, High, AboveNormal, BelowNormal, RealTime. Default: Normal

	.PARAMETER ExitOnProcessFailure
	Specifies whether the function should call Exit-Script when the process returns an exit code that is considered an error/failure. Default: $true

	.PARAMETER UseShellExecute
	Specifies whether to use the operating system shell to start the process.
	$true if the shell should be used when starting the process;
	$false if the process should be created directly from the executable file.

	The word "Shell" in this context refers to a graphical shell (similar to the Windows shell) rather than
	command shells (for example, bash or sh) and lets users launch graphical applications or open documents.
	It lets you open a file or a url and the Shell will figure out the program to open it with.
	The WorkingDirectory property behaves differently depending on the value of the UseShellExecute property.
	When UseShellExecute is true, the WorkingDirectory property specifies the location of the executable.
	When UseShellExecute is false, the WorkingDirectory property is not used to find the executable.
	Instead, it is used only by the process that is started and has meaning only within the context of the new process.
	If you set UseShellExecute to $true, there will be no available output from the process.

	Default: $false

	.PARAMETER ContinueOnError
	Continue if an error occured while trying to start the process. Default: $false.

	.EXAMPLE
	Execute-Process -Path 'uninstall_flash_player_64bit.exe' -Parameters '/uninstall' -WindowStyle 'Hidden'

	If the file is in the "Files" directory of the App Deploy Toolkit, only the file name needs to be specified.

	.INPUTS
	None

	You cannot pipe objects to this function.

	.OUTPUTS
	None

	This function does not generate any output.

	.EXAMPLE
	Execute-Process -Path "$dirFiles\Bin\setup.exe" -Parameters '/S' -WindowStyle 'Hidden'

	.EXAMPLE
	Execute-Process -Path 'setup.exe' -Parameters '/S' -IgnoreExitCodes '1,2'

	.EXAMPLE
	Execute-Process -Path 'setup.exe' -Parameters "-s -f2`"$configToolkitLogDir\$installName.log`""

	Launch InstallShield "setup.exe" from the ".\Files" sub-directory and force log files to the logging folder.

	.EXAMPLE
	Execute-Process -Path 'setup.exe' -Parameters "/s /v`"ALLUSERS=1 /qn /L* \`"$configToolkitLogDir\$installName.log`"`""

	Launch InstallShield "setup.exe" with embedded MSI and force log files to the logging folder.

	.EXAMPLE
	Use SCCM to create a single Package and Deployment Type that can run "whether or not a user is logged on" and also
	displays interaction for logged-on users including RDP session users.

	If no user is logged on, in Deploy-Application.ps1:
	Execute-Process -Path "Deploy-Application.exe" -Parameters $DeploymentType

	If a user is logged on, in Deploy-Application.ps1:
	[String]$PsExecParameters = "-accepteula -s -w `"$dirSupportFiles`" `"$dirSupportFiles\ServiceUI_x64.exe`" -process:explorer.exe ..\Deploy-Application.exe $DeploymentType"
	[PsObject]$ExecuteProcessResult = Execute-Process -Path "$dirSupportFiles\PsExec64.exe" -Parameters $PsExecParameters -PassThru

	Launch PsExec with parameters for ServiceUI and Deploy-Application.exe. Will work with spaces in $scriptParentPath.

	If ServiceUI is run directly from SCCM's command line, then execution does not work for RDP session users.
	Using PsExec in this context also ensures greater chance of success for unknown reasons.

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[Alias('FilePath')]
		[ValidateNotNullorEmpty()]
		[String]$Path,
		[Parameter(Mandatory = $false)]
		[Alias('Arguments')]
		[ValidateNotNullorEmpty()]
		[String[]]$Parameters,
		[Parameter(Mandatory = $false)]
		[Switch]$SecureParameters = $false,
		[Parameter(Mandatory = $false)]
		[ValidateSet('Normal', 'Hidden', 'Maximized', 'Minimized')]
		[Diagnostics.ProcessWindowStyle]$WindowStyle = 'Normal',
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Switch]$CreateNoWindow = $false,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[String]$WorkingDirectory,
		[Parameter(Mandatory = $false)]
		[Switch]$NoWait = $false,
		[Parameter(Mandatory = $false)]
		[Switch]$PassThru = $false,
		[Parameter(Mandatory = $false)]
		[Switch]$WaitForMsiExec = $false,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Int32]$MsiExecWaitTime = $configMSIMutexWaitTime,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[String]$IgnoreExitCodes,
		[Parameter(Mandatory = $false)]
		[ValidateSet('Idle', 'Normal', 'High', 'AboveNormal', 'BelowNormal', 'RealTime')]
		[Diagnostics.ProcessPriorityClass]$PriorityClass = 'Normal',
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Boolean]$ExitOnProcessFailure = $true,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Boolean]$UseShellExecute = $false,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Boolean]$ContinueOnError = $false
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			$private:returnCode = $null
			$stdOut = $stdErr = $null

			## Validate and find the fully qualified path for the $Path variable.
			If (([IO.Path]::IsPathRooted($Path)) -and ([IO.Path]::HasExtension($Path))) {
				Write-Log -Message "[$Path] is a valid fully qualified path, continue." -Source ${CmdletName}

				If (-not (Test-Path -LiteralPath $Path -PathType 'Leaf' -ErrorAction 'Stop')) {
					Write-Log -Message "File [$Path] not found." -Severity 3 -Source ${CmdletName}

					If (-not $ContinueOnError) {
						Throw "File [$Path] not found."
					}
					Return
				}
			} Else {
				#  The first directory to search will be the 'Files' subdirectory of the script directory
				[String]$PathFolders = $dirFiles
				#  Add the current location of the console (Windows always searches this location first)
				[String]$PathFolders = $PathFolders + ';' + (Get-Location -PSProvider 'FileSystem').Path
				#  Add the new path locations to the PATH environment variable
				$env:PATH = $PathFolders + ';' + $env:PATH

				#  Get the fully qualified path for the file. Get-Command searches PATH environment variable to find this value.
				[String]$FullyQualifiedPath = Get-Command -Name $Path -CommandType 'Application' -TotalCount 1 -Syntax -ErrorAction 'Stop'

				#  Revert the PATH environment variable to it's original value
				$env:PATH = $env:PATH -replace [RegEx]::Escape($PathFolders + ';'), ''

				If ($FullyQualifiedPath) {
					Write-Log -Message "[$Path] successfully resolved to fully qualified path [$FullyQualifiedPath]." -Source ${CmdletName}

					$Path = $FullyQualifiedPath
				} Else {
					Write-Log -Message "[$Path] contains an invalid path or file name." -Severity 3 -Source ${CmdletName}

					If (-not $ContinueOnError) {
						Throw "[$Path] contains an invalid path or file name."
					}
					Return
				}
			}

			## Set the Working directory (if not specified)
			If (-not $WorkingDirectory) {
				$WorkingDirectory = Split-Path -Path $Path -Parent -ErrorAction 'Stop'
			}

			## If the WindowStyle parameter is set to 'Hidden', set the UseShellExecute parameter to '$true'.
			If ($WindowStyle -eq 'Hidden') {
				$UseShellExecute = $true
			}

			## If MSI install, check to see if the MSI installer service is available or if another MSI install is already underway.
			## Please note that a race condition is possible after this check where another process waiting for the MSI installer
			##  to become available grabs the MSI Installer mutex before we do. Not too concerned about this possible race condition.
			If (($Path -match 'msiexec') -or ($WaitForMsiExec)) {
				[Timespan]$MsiExecWaitTimeSpan = New-TimeSpan -Seconds $MsiExecWaitTime
				[Boolean]$MsiExecAvailable = Test-IsMutexAvailable -MutexName 'Global\_MSIExecute' -MutexWaitTimeInMilliseconds $MsiExecWaitTimeSpan.TotalMilliseconds
				Start-Sleep -Seconds 1
				If (-not $MsiExecAvailable) {
					#  Default MSI exit code for install already in progress
					[Int32]$returnCode = 1618
					Write-Log -Message 'Another MSI installation is already in progress and needs to be completed before proceeding with this installation.' -Severity 3 -Source ${CmdletName}
					If (-not $ContinueOnError) {
						Throw 'Another MSI installation is already in progress and needs to be completed before proceeding with this installation.'
					}
					Return
				}
			}

			Try {
				## Disable Zone checking to prevent warnings when running executables
				$env:SEE_MASK_NOZONECHECKS = 1

				## Using this variable allows capture of exceptions from .NET methods. Private scope only changes value for current function.
				$private:previousErrorActionPreference = $ErrorActionPreference
				$ErrorActionPreference = 'Stop'

				## Define process
				$processStartInfo = New-Object -TypeName 'System.Diagnostics.ProcessStartInfo' -ErrorAction 'Stop'
				$processStartInfo.FileName = $Path
				$processStartInfo.WorkingDirectory = $WorkingDirectory
				$processStartInfo.UseShellExecute = $UseShellExecute
				$processStartInfo.ErrorDialog = $false
				$processStartInfo.RedirectStandardOutput = $true
				$processStartInfo.RedirectStandardError = $true
				$processStartInfo.CreateNoWindow = $CreateNoWindow
				If ($Parameters) {
					$processStartInfo.Arguments = $Parameters
				}
				$processStartInfo.WindowStyle = $WindowStyle
				If ($processStartInfo.UseShellExecute -eq $true) {
					Write-Log -Message 'UseShellExecute is set to true, standard output and error will not be available.' -Source ${CmdletName}
					$processStartInfo.RedirectStandardOutput = $false
					$processStartInfo.RedirectStandardError = $false
				}
				$process = New-Object -TypeName 'System.Diagnostics.Process' -ErrorAction 'Stop'
				$process.StartInfo = $processStartInfo

				If ($processStartInfo.UseShellExecute -eq $false) {
					## Add event handler to capture process's standard output redirection
					[ScriptBlock]$processEventHandler = { If (-not [String]::IsNullOrEmpty($EventArgs.Data)) {
							$Event.MessageData.AppendLine($EventArgs.Data)
						} }
					$stdOutBuilder = New-Object -TypeName 'System.Text.StringBuilder' -ArgumentList ('')
					$stdOutEvent = Register-ObjectEvent -InputObject $process -Action $processEventHandler -EventName 'OutputDataReceived' -MessageData $stdOutBuilder -ErrorAction 'Stop'
					$stdErrBuilder = New-Object -TypeName 'System.Text.StringBuilder' -ArgumentList ('')
					$stdErrEvent = Register-ObjectEvent -InputObject $process -Action $processEventHandler -EventName 'ErrorDataReceived' -MessageData $stdErrBuilder -ErrorAction 'Stop'
				}

				## Start Process
				Write-Log -Message "Working Directory is [$WorkingDirectory]." -Source ${CmdletName}
				If ($Parameters) {
					If ($Parameters -match '-Command \&') {
						Write-Log -Message "Executing [$Path [PowerShell ScriptBlock]]..." -Source ${CmdletName}
					} Else {
						If ($SecureParameters) {
							Write-Log -Message "Executing [$Path (Parameters Hidden)]..." -Source ${CmdletName}
						} Else {
							Write-Log -Message "Executing [$Path $Parameters]..." -Source ${CmdletName}
						}
					}
				} Else {
					Write-Log -Message "Executing [$Path]..." -Source ${CmdletName}
				}

				$null = $process.Start()
				## Set priority
				If ($PriorityClass -ne 'Normal') {
					Try {
						If ($process.HasExited -eq $false) {
							Write-Log -Message "Changing the priority class for the process to [$PriorityClass]" -Source ${CmdletName}
							$process.PriorityClass = $PriorityClass
						} Else {
							Write-Log -Message "Cannot change the priority class for the process to [$PriorityClass], because the process has exited already." -Severity 2 -Source ${CmdletName}
						}

					} Catch {
						Write-Log -Message 'Failed to change the priority class for the process.' -Severity 2 -Source ${CmdletName}
					}
				}
				## NoWait specified, return process details. If it isn't specified, start reading standard Output and Error streams
				If ($NoWait) {
					Write-Log -Message 'NoWait parameter specified. Continuing without waiting for exit code...' -Source ${CmdletName}

					If ($PassThru) {
						If ($process.HasExited -eq $false) {
							Write-Log -Message 'PassThru parameter specified, returning process details object.' -Source ${CmdletName}
							[PSObject]$ProcessDetails = New-Object -TypeName 'PSObject' -Property @{ Id = If ($process.Id) {
									$process.Id
								} Else {
									$null
								} ; Handle                                                                 = If ($process.Handle) {
									$process.Handle
								} Else {
									[IntPtr]::Zero
								}; ProcessName                                                             = If ($process.ProcessName) {
									$process.ProcessName
								} Else {
									''
								}
							}
							Write-Output -InputObject ($ProcessDetails)
						} Else {
							Write-Log -Message 'PassThru parameter specified, however the process has already exited.' -Source ${CmdletName}
						}
					}
				} Else {
					If ($processStartInfo.UseShellExecute -eq $false) {
						$process.BeginOutputReadLine()
						$process.BeginErrorReadLine()
					}
					## Instructs the Process component to wait indefinitely for the associated process to exit.
					$process.WaitForExit()

					## HasExited indicates that the associated process has terminated, either normally or abnormally. Wait until HasExited returns $true.
					While (-not $process.HasExited) {
						$process.Refresh(); Start-Sleep -Seconds 1
					}

					## Get the exit code for the process
					Try {
						[Int32]$returnCode = $process.ExitCode
					} Catch [System.Management.Automation.PSInvalidCastException] {
						#  Catch exit codes that are out of int32 range
						[Int32]$returnCode = 60013
					}

					If ($processStartInfo.UseShellExecute -eq $false) {
						## Unregister standard output and error event to retrieve process output
						If ($stdOutEvent) {
							Unregister-Event -SourceIdentifier $stdOutEvent.Name -ErrorAction 'Stop'; $stdOutEvent = $null
						}
						If ($stdErrEvent) {
							Unregister-Event -SourceIdentifier $stdErrEvent.Name -ErrorAction 'Stop'; $stdErrEvent = $null
						}
						$stdOut = $stdOutBuilder.ToString() -replace $null, ''
						$stdErr = $stdErrBuilder.ToString() -replace $null, ''

						If ($stdErr.Length -gt 0) {
							Write-Log -Message "Standard error output from the process: $stdErr" -Severity 3 -Source ${CmdletName}
						}
					}
				}
			} Finally {
				If ($processStartInfo.UseShellExecute -eq $false) {
					## Make sure the standard output and error event is unregistered
					If ($stdOutEvent) {
						Unregister-Event -SourceIdentifier $stdOutEvent.Name -ErrorAction 'SilentlyContinue'; $stdOutEvent = $null
					}
					If ($stdErrEvent) {
						Unregister-Event -SourceIdentifier $stdErrEvent.Name -ErrorAction 'SilentlyContinue'; $stdErrEvent = $null
					}
				}
				## Free resources associated with the process, this does not cause process to exit
				If ($process) {
					$process.Dispose()
				}

				## Re-enable Zone checking
				Remove-Item -LiteralPath 'env:SEE_MASK_NOZONECHECKS' -ErrorAction 'SilentlyContinue'

				If ($private:previousErrorActionPreference) {
					$ErrorActionPreference = $private:previousErrorActionPreference
				}
			}

			If (-not $NoWait) {
				## Check to see whether we should ignore exit codes
				$ignoreExitCodeMatch = $false
				If ($ignoreExitCodes) {
					## Check whether * was specified, which would tell us to ignore all exit codes
					If ($ignoreExitCodes.Trim() -eq '*') {
						$ignoreExitCodeMatch = $true
					} Else {
						## Split the processes on a comma
						[Int32[]]$ignoreExitCodesArray = $ignoreExitCodes -split ','
						ForEach ($ignoreCode in $ignoreExitCodesArray) {
							If ($returnCode -eq $ignoreCode) {
								$ignoreExitCodeMatch = $true
							}
						}
					}
				}

				## If the passthru switch is specified, return the exit code and any output from process
				If ($PassThru) {
					Write-Log -Message 'PassThru parameter specified, returning execution results object.' -Source ${CmdletName}
					[PSObject]$ExecutionResults = New-Object -TypeName 'PSObject' -Property @{ ExitCode = $returnCode; StdOut = If ($stdOut) {
							$stdOut
						} Else {
							''
						}; StdErr = If ($stdErr) {
							$stdErr
						} Else {
							''
						}
					}
					Write-Output -InputObject ($ExecutionResults)
				}

				If ($ignoreExitCodeMatch) {
					Write-Log -Message "Execution completed and the exit code [$returncode] is being ignored." -Source ${CmdletName}
				} ElseIf (($returnCode -eq 3010) -or ($returnCode -eq 1641)) {
					Write-Log -Message "Execution completed successfully with exit code [$returnCode]. A reboot is required." -Severity 2 -Source ${CmdletName}
					Set-Variable -Name 'msiRebootDetected' -Value $true -Scope 'Script'
				} ElseIf (($returnCode -eq 1605) -and ($Path -match 'msiexec')) {
					Write-Log -Message "Execution failed with exit code [$returnCode] because the product is not currently installed." -Severity 3 -Source ${CmdletName}
				} ElseIf (($returnCode -eq -2145124329) -and ($Path -match 'wusa')) {
					Write-Log -Message "Execution failed with exit code [$returnCode] because the Windows Update is not applicable to this system." -Severity 3 -Source ${CmdletName}
				} ElseIf (($returnCode -eq 17025) -and ($Path -match 'fullfile')) {
					Write-Log -Message "Execution failed with exit code [$returnCode] because the Office Update is not applicable to this system." -Severity 3 -Source ${CmdletName}
				} ElseIf ($returnCode -eq 0) {
					Write-Log -Message "Execution completed successfully with exit code [$returnCode]." -Source ${CmdletName}
				} Else {
					[String]$MsiExitCodeMessage = ''
					If ($Path -match 'msiexec') {
						[String]$MsiExitCodeMessage = Get-MsiExitCodeMessage -MsiExitCode $returnCode
					}

					If ($MsiExitCodeMessage) {
						Write-Log -Message "Execution failed with exit code [$returnCode]: $MsiExitCodeMessage" -Severity 3 -Source ${CmdletName}
					} Else {
						Write-Log -Message "Execution failed with exit code [$returnCode]." -Severity 3 -Source ${CmdletName}
					}

					If ($ExitOnProcessFailure) {
						Exit-Script -ExitCode $returnCode
					}
				}
			}
		} Catch {
			If ([String]::IsNullOrEmpty([String]$returnCode)) {
				[Int32]$returnCode = 60002
				Write-Log -Message "Function failed, setting exit code to [$returnCode]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Function failed, setting exit code to [$returnCode]. $($_.Exception.Message)"
				}
			} Else {
				Write-Log -Message "Execution completed with exit code [$returnCode]. Function failed. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			}

			If ($PassThru) {
				[PSObject]$ExecutionResults = New-Object -TypeName 'PSObject' -Property @{ ExitCode = $returnCode; StdOut = If ($stdOut) {
						$stdOut
					} Else {
						''
					}; StdErr = If ($stdErr) {
						$stdErr
					} Else {
						''
					}
				}
				Write-Output -InputObject ($ExecutionResults)
			}

			If ($ExitOnProcessFailure) {
				Exit-Script -ExitCode $returnCode
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion
#region Function Get-RunningProcesses
Function Get-RunningProcesses {
	<#
	.SYNOPSIS

	Gets the processes that are running from a custom list of process objects and also adds a property called ProcessDescription.

	.DESCRIPTION

	Gets the processes that are running from a custom list of process objects and also adds a property called ProcessDescription.

	.PARAMETER ProcessObjects

	Custom object containing the process objects to search for. If not supplied, the function just returns $null

	.PARAMETER DisableLogging

	Disables function logging

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	Syste.Boolean.

	Rettuns $true if the process is running, otherwise $false.

	.EXAMPLE

	Get-RunningProcesses -ProcessObjects $ProcessObjects

	.NOTES

	This is an internal script function and should typically not be called directly.

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $false, Position = 0)]
		[PSObject[]]$ProcessObjects,
		[Parameter(Mandatory = $false, Position = 1)]
		[Switch]$DisableLogging
	)

	begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}

	process {

		## Confirm input isn't null before proceeding.
		if (!$processObjects -or !$processObjects[0].ProcessName) {
			return
		}

		if (!$DisableLogging) {
			Write-Log -Message "Checking for running applications: [$($processObjects.ProcessName -join ',')]" -Source ${CmdletName}
		}

		## Get all running processes and append properties.
		[Diagnostics.Process[]]$runningProcesses = foreach ($process in (Get-Process -Name $processObjects.ProcessName -ErrorAction SilentlyContinue)) {
			Add-Member -InputObject $process -MemberType NoteProperty -Name ProcessDescription -Force -PassThru -Value $(
				if (![System.String]::IsNullOrWhiteSpace(($objDescription = ($processObjects | Where-Object { $_.ProcessName -eq $process.ProcessName }).ProcessDescription))) {
					# The description of the process provided as a Parameter to the function, e.g. -ProcessName "winword=Microsoft Office Word".
					$objDescription
				} elseif ($process.Description) {
					# If the process already has a description field specified, then use it
					$process.Description
				} else {
					# Fall back on the process name if no description is provided by the process or as a parameter to the function
					$process.ProcessName
				}
			)
		}

		## Return output if there's any.
		if (!$runningProcesses) {
			if (!$DisableLogging) {
				Write-Log -Message 'Specified applications are not running.' -Source ${CmdletName}
			}
			return
		}

		if (!$DisableLogging) {
			Write-Log -Message "The following processes are running: [$(($runningProcesses.ProcessName | Select-Object -Unique) -join ',')]." -Source ${CmdletName}
		}

		return ($runningProcesses | Sort-Object)

	}

	end {
		## Write out the footer
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Convert-RegistryPath
Function Convert-RegistryPath {
	<#
	.SYNOPSIS

	Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets.

	.DESCRIPTION

	Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets.

	Converts registry key hives to their full paths. Example: HKLM is converted to "Registry::HKEY_LOCAL_MACHINE".

	.PARAMETER Key

	Path to the registry key to convert (can be a registry hive or fully qualified path)

	.PARAMETER Wow6432Node

	Specifies that the 32-bit registry view (Wow6432Node) should be used on a 64-bit system.

	.PARAMETER SID

	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.

	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.

	.PARAMETER DisableFunctionLogging

	Disables logging of this function. Default: $true

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	System.String

	Returns the converted registry key path.

	.EXAMPLE

	Convert-RegistryPath -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'

	.EXAMPLE

	Convert-RegistryPath -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[String]$Key,
		[Parameter(Mandatory = $false)]
		[Switch]$Wow6432Node = $false,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[String]$SID,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Boolean]$DisableFunctionLogging = $true
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		## Convert the registry key hive to the full path, only match if at the beginning of the line
		If ($Key -match '^HKLM') {
			$Key = $Key -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKLM:', 'HKEY_LOCAL_MACHINE\' -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
		} ElseIf ($Key -match '^HKCR') {
			$Key = $Key -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\' -replace '^HKCR:', 'HKEY_CLASSES_ROOT\' -replace '^HKCR\\', 'HKEY_CLASSES_ROOT\'
		} ElseIf ($Key -match '^HKCU') {
			$Key = $Key -replace '^HKCU:\\', 'HKEY_CURRENT_USER\' -replace '^HKCU:', 'HKEY_CURRENT_USER\' -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
		} ElseIf ($Key -match '^HKU') {
			$Key = $Key -replace '^HKU:\\', 'HKEY_USERS\' -replace '^HKU:', 'HKEY_USERS\' -replace '^HKU\\', 'HKEY_USERS\'
		} ElseIf ($Key -match '^HKCC') {
			$Key = $Key -replace '^HKCC:\\', 'HKEY_CURRENT_CONFIG\' -replace '^HKCC:', 'HKEY_CURRENT_CONFIG\' -replace '^HKCC\\', 'HKEY_CURRENT_CONFIG\'
		} ElseIf ($Key -match '^HKPD') {
			$Key = $Key -replace '^HKPD:\\', 'HKEY_PERFORMANCE_DATA\' -replace '^HKPD:', 'HKEY_PERFORMANCE_DATA\' -replace '^HKPD\\', 'HKEY_PERFORMANCE_DATA\'
		}

		If ($Wow6432Node -and $Is64BitProcess) {
			If ($Key -match '^(HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\|HKEY_CURRENT_USER\\SOFTWARE\\Classes\\|HKEY_CLASSES_ROOT\\)(AppID\\|CLSID\\|DirectShow\\|Interface\\|Media Type\\|MediaFoundation\\|PROTOCOLS\\|TypeLib\\)') {
				$Key = $Key -replace '^(HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\|HKEY_CURRENT_USER\\SOFTWARE\\Classes\\|HKEY_CLASSES_ROOT\\)(AppID\\|CLSID\\|DirectShow\\|Interface\\|Media Type\\|MediaFoundation\\|PROTOCOLS\\|TypeLib\\)', '$1Wow6432Node\$2'
			} ElseIf ($Key -match '^HKEY_LOCAL_MACHINE\\SOFTWARE\\') {
				$Key = $Key -replace '^HKEY_LOCAL_MACHINE\\SOFTWARE\\', 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\'
			} ElseIf ($Key -match '^HKEY_LOCAL_MACHINE\\SOFTWARE$') {
				$Key = $Key -replace '^HKEY_LOCAL_MACHINE\\SOFTWARE$', 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node'
			} ElseIf ($Key -match '^HKEY_CURRENT_USER\\Software\\Microsoft\\Active Setup\\Installed Components\\') {
				$Key = $Key -replace '^HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components\\', 'HKEY_CURRENT_USER\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\'
			}
		}

		## Append the PowerShell provider to the registry key path
		If ($key -notmatch '^Registry::') {
			[String]$key = "Registry::$key"
		}

		If ($PSBoundParameters.ContainsKey('SID')) {
			## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
			If ($key -match '^Registry::HKEY_CURRENT_USER\\') {
				$key = $key -replace '^Registry::HKEY_CURRENT_USER\\', "Registry::HKEY_USERS\$SID\"
			} ElseIf (-not $DisableFunctionLogging) {
				Write-Log -Message 'SID parameter specified but the registry hive of the key is not HKEY_CURRENT_USER.' -Source ${CmdletName} -Severity 2
			}
		}

		If ($Key -match '^Registry::HKEY_LOCAL_MACHINE|^Registry::HKEY_CLASSES_ROOT|^Registry::HKEY_CURRENT_USER|^Registry::HKEY_USERS|^Registry::HKEY_CURRENT_CONFIG|^Registry::HKEY_PERFORMANCE_DATA') {
			## Check for expected key string format
			If (-not $DisableFunctionLogging) {
				Write-Log -Message "Return fully qualified registry key path [$key]." -Source ${CmdletName}
			}
			Write-Output -InputObject ($key)
		} Else {
			#  If key string is not properly formatted, throw an error
			Throw "Unable to detect target registry hive in string [$key]."
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Test-RegistryValue
Function Test-RegistryValue {
	<#
	.SYNOPSIS

	Test if a registry value exists.

	.DESCRIPTION

	Checks a registry key path to see if it has a value with a given name. Can correctly handle cases where a value simply has an empty or null value.

	.PARAMETER Key

	Path of the registry key.

	.PARAMETER Value

	Specify the registry key value to check the existence of.

	.PARAMETER SID

	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.

	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.

	.PARAMETER Wow6432Node

	Specify this switch to check the 32-bit registry (Wow6432Node) on 64-bit systems.

	.INPUTS

	System.String

	Accepts a string value for the registry key path.

	.OUTPUTS

	System.String

	Returns $true if the registry value exists, $false if it does not.

	.EXAMPLE

	Test-RegistryValue -Key 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations'

	.NOTES

	To test if registry key exists, use Test-Path function like so:

	Test-Path -Path $Key -PathType 'Container'

	.LINK

	https://psappdeploytoolkit.com
	#>
	Param (
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]$Key,
		[Parameter(Mandatory = $true, Position = 1)]
		[ValidateNotNullOrEmpty()]$Value,
		[Parameter(Mandatory = $false, Position = 2)]
		[ValidateNotNullorEmpty()]
		[String]$SID,
		[Parameter(Mandatory = $false)]
		[Switch]$Wow6432Node = $false
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
		Try {
			If ($PSBoundParameters.ContainsKey('SID')) {
				[String]$Key = Convert-RegistryPath -Key $Key -Wow6432Node:$Wow6432Node -SID $SID
			} Else {
				[String]$Key = Convert-RegistryPath -Key $Key -Wow6432Node:$Wow6432Node
			}
		} Catch {
			Throw
		}
		[Boolean]$IsRegistryValueExists = $false
		Try {
			If (Test-Path -LiteralPath $Key -ErrorAction 'Stop') {
				[String[]]$PathProperties = Get-Item -LiteralPath $Key -ErrorAction 'Stop' | Select-Object -ExpandProperty 'Property' -ErrorAction 'Stop'
				If ($PathProperties -contains $Value) {
					$IsRegistryValueExists = $true
				}
			}
		} Catch {
		}

		If ($IsRegistryValueExists) {
			Write-Log -Message "Registry key value [$Key] [$Value] does exist." -Source ${CmdletName}
		} Else {
			Write-Log -Message "Registry key value [$Key] [$Value] does not exist." -Source ${CmdletName}
		}
		Write-Output -InputObject ($IsRegistryValueExists)
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Get-RegistryKey
Function Get-RegistryKey {
	<#
	.SYNOPSIS

	Retrieves value names and value data for a specified registry key or optionally, a specific value.

	.DESCRIPTION

	Retrieves value names and value data for a specified registry key or optionally, a specific value.

	If the registry key does not exist or contain any values, the function will return $null by default. To test for existence of a registry key path, use built-in Test-Path cmdlet.

	.PARAMETER Key

	Path of the registry key.

	.PARAMETER Value

	Value to retrieve (optional).

	.PARAMETER Wow6432Node

	Specify this switch to read the 32-bit registry (Wow6432Node) on 64-bit systems.

	.PARAMETER SID

	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.

	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.

	.PARAMETER ReturnEmptyKeyIfExists

	Return the registry key if it exists but it has no property/value pairs underneath it. Default is: $false.

	.PARAMETER DoNotExpandEnvironmentNames

	Return unexpanded REG_EXPAND_SZ values. Default is: $false.

	.PARAMETER ContinueOnError

	Continue if an error is encountered. Default is: $true.

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	System.String

	Returns the value of the registry key or value.

	.EXAMPLE

	Get-RegistryKey -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'

	.EXAMPLE

	Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\iexplore.exe'

	.EXAMPLE

	Get-RegistryKey -Key 'HKLM:Software\Wow6432Node\Microsoft\Microsoft SQL Server Compact Edition\v3.5' -Value 'Version'

	.EXAMPLE

	Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Value 'Path' -DoNotExpandEnvironmentNames

	Returns %ProgramFiles%\Java instead of C:\Program Files\Java

	.EXAMPLE

	Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Example' -Value '(Default)'

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[String]$Key,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]$Value,
		[Parameter(Mandatory = $false)]
		[Switch]$Wow6432Node = $false,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[String]$SID,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Switch]$ReturnEmptyKeyIfExists = $false,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[Switch]$DoNotExpandEnvironmentNames = $false,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Boolean]$ContinueOnError = $true
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
			If ($PSBoundParameters.ContainsKey('SID')) {
				[String]$key = Convert-RegistryPath -Key $key -Wow6432Node:$Wow6432Node -SID $SID
			} Else {
				[String]$key = Convert-RegistryPath -Key $key -Wow6432Node:$Wow6432Node
			}

			## Check if the registry key exists
			If (-not (Test-Path -LiteralPath $key -ErrorAction 'Stop')) {
				Write-Log -Message "Registry key [$key] does not exist. Return `$null." -Severity 2 -Source ${CmdletName}
				$regKeyValue = $null
			} Else {
				If ($PSBoundParameters.ContainsKey('Value')) {
					Write-Log -Message "Getting registry key [$key] value [$value]." -Source ${CmdletName}
				} Else {
					Write-Log -Message "Getting registry key [$key] and all property values." -Source ${CmdletName}
				}

				## Get all property values for registry key
				$regKeyValue = Get-ItemProperty -LiteralPath $key -ErrorAction 'Stop'
				[Int32]$regKeyValuePropertyCount = $regKeyValue | Measure-Object | Select-Object -ExpandProperty 'Count'

				## Select requested property
				If ($PSBoundParameters.ContainsKey('Value')) {
					#  Check if registry value exists
					[Boolean]$IsRegistryValueExists = $false
					If ($regKeyValuePropertyCount -gt 0) {
						Try {
							[string[]]$PathProperties = Get-Item -LiteralPath $Key -ErrorAction 'Stop' | Select-Object -ExpandProperty 'Property' -ErrorAction 'Stop'
							If ($PathProperties -contains $Value) {
								$IsRegistryValueExists = $true
							}
						} Catch {
						}
					}

					#  Get the Value (do not make a strongly typed variable because it depends entirely on what kind of value is being read)
					If ($IsRegistryValueExists) {
						If ($DoNotExpandEnvironmentNames) {
							#Only useful on 'ExpandString' values
							If ($Value -like '(Default)') {
								$regKeyValue = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').GetValue($null, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
							} Else {
								$regKeyValue = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').GetValue($Value, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
							}
						} ElseIf ($Value -like '(Default)') {
							$regKeyValue = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').GetValue($null)
						} Else {
							$regKeyValue = $regKeyValue | Select-Object -ExpandProperty $Value -ErrorAction 'SilentlyContinue'
						}
					} Else {
						Write-Log -Message "Registry key value [$Key] [$Value] does not exist. Return `$null." -Source ${CmdletName}
						$regKeyValue = $null
					}
				}
				## Select all properties or return empty key object
				Else {
					If ($regKeyValuePropertyCount -eq 0) {
						If ($ReturnEmptyKeyIfExists) {
							Write-Log -Message "No property values found for registry key. Return empty registry key object [$key]." -Source ${CmdletName}
							$regKeyValue = Get-Item -LiteralPath $key -Force -ErrorAction 'Stop'
						} Else {
							Write-Log -Message "No property values found for registry key. Return `$null." -Source ${CmdletName}
							$regKeyValue = $null
						}
					}
				}
			}
			Write-Output -InputObject ($regKeyValue)
		} Catch {
			If (-not $Value) {
				Write-Log -Message "Failed to read registry key [$key]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to read registry key [$key]: $($_.Exception.Message)"
				}
			} Else {
				Write-Log -Message "Failed to read registry key [$key] value [$value]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to read registry key [$key] value [$value]: $($_.Exception.Message)"
				}
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Set-RegistryKey
Function Set-RegistryKey {
	<#
	.SYNOPSIS

	Creates a registry key name, value, and value data; it sets the same if it already exists.

	.DESCRIPTION

	Creates a registry key name, value, and value data; it sets the same if it already exists.

	.PARAMETER Key

	The registry key path.

	.PARAMETER Name

	The value name.

	.PARAMETER Value

	The value data.

	.PARAMETER Type

	The type of registry value to create or set. Options: 'Binary','DWord','ExpandString','MultiString','None','QWord','String','Unknown'. Default: String.

	DWord should be specified as a decimal.

	.PARAMETER Wow6432Node

	Specify this switch to write to the 32-bit registry (Wow6432Node) on 64-bit systems.

	.PARAMETER SID

	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.

	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.

	.PARAMETER ContinueOnError

	Continue if an error is encountered. Default is: $true.

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	None

	This function does not generate any output.

	.EXAMPLE

	Set-RegistryKey -Key $blockedAppPath -Name 'Debugger' -Value $blockedAppDebuggerValue

	.EXAMPLE

	Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE' -Name 'Application' -Type 'DWord' -Value '1'

	.EXAMPLE

	Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'Debugger' -Value $blockedAppDebuggerValue -Type String

	.EXAMPLE

	Set-RegistryKey -Key 'HKCU\Software\Microsoft\Example' -Name 'Data' -Value (0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x02,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x02,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x01,0x01,0x01,0x02,0x02,0x02) -Type 'Binary'

	.EXAMPLE

	Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Example' -Name '(Default)' -Value "Text"

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[String]$Key,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory = $false)]
		$Value,
		[Parameter(Mandatory = $false)]
		[ValidateSet('Binary', 'DWord', 'ExpandString', 'MultiString', 'None', 'QWord', 'String', 'Unknown')]
		[Microsoft.Win32.RegistryValueKind]$Type = 'String',
		[Parameter(Mandatory = $false)]
		[Switch]$Wow6432Node = $false,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[String]$SID,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Boolean]$ContinueOnError = $true
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			[String]$RegistryValueWriteAction = 'set'

			## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
			If ($PSBoundParameters.ContainsKey('SID')) {
				[String]$key = Convert-RegistryPath -Key $key -Wow6432Node:$Wow6432Node -SID $SID
			} Else {
				[String]$key = Convert-RegistryPath -Key $key -Wow6432Node:$Wow6432Node
			}

			## Create registry key if it doesn't exist
			If (-not (Test-Path -LiteralPath $key -ErrorAction 'Stop')) {
				Try {
					Write-Log -Message "Creating registry key [$key]." -Source ${CmdletName}
					# No forward slash found in Key. Use New-Item cmdlet to create registry key
					If ((($Key -split '/').Count - 1) -eq 0) {
						$null = New-Item -Path $key -ItemType 'Registry' -Force -ErrorAction 'Stop'
					}
					# Forward slash was found in Key. Use REG.exe ADD to create registry key
					Else {
						If ($Is64BitProcess -and -not $Wow6432Node) {
							$RegMode = '/reg:64'
						} Else {
							$RegMode = '/reg:32'
						}
						[String]$CreateRegkeyResult = & "$envWinDir\System32\reg.exe" Add "$($Key.Substring($Key.IndexOf('::') + 2))" /f $RegMode
						If ($global:LastExitCode -ne 0) {
							Throw "Failed to create registry key [$Key]"
						}
					}
				} Catch {
					Throw
				}
			}

			If ($Name) {
				## Set registry value if it doesn't exist
				If (-not (Get-ItemProperty -LiteralPath $key -Name $Name -ErrorAction 'SilentlyContinue')) {
					Write-Log -Message "Setting registry key value: [$key] [$name = $value]." -Source ${CmdletName}
					$null = New-ItemProperty -LiteralPath $key -Name $name -Value $value -PropertyType $Type -ErrorAction 'Stop'
				}
				## Update registry value if it does exist
				Else {
					[String]$RegistryValueWriteAction = 'update'
					If ($Name -eq '(Default)') {
						## Set Default registry key value with the following workaround, because Set-ItemProperty contains a bug and cannot set Default registry key value
						$null = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').OpenSubKey('', 'ReadWriteSubTree').SetValue($null, $value)
					} Else {
						Write-Log -Message "Updating registry key value: [$key] [$name = $value]." -Source ${CmdletName}
						$null = Set-ItemProperty -LiteralPath $key -Name $name -Value $value -ErrorAction 'Stop'
					}
				}
			}
		} Catch {
			If ($Name) {
				Write-Log -Message "Failed to $RegistryValueWriteAction value [$value] for registry key [$key] [$name]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to $RegistryValueWriteAction value [$value] for registry key [$key] [$name]: $($_.Exception.Message)"
				}
			} Else {
				Write-Log -Message "Failed to set registry key [$key]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to set registry key [$key]: $($_.Exception.Message)"
				}
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Remove-RegistryKey
Function Remove-RegistryKey {
	<#
	.SYNOPSIS

	Deletes the specified registry key or value.

	.DESCRIPTION

	Deletes the specified registry key or value.

	.PARAMETER Key

	Path of the registry key to delete.

	.PARAMETER Name

	Name of the registry value to delete.

	.PARAMETER Recurse

	Delete registry key recursively.

	.PARAMETER SID

	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.

	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.

	.PARAMETER ContinueOnError

	Continue if an error is encountered. Default is: $true.

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	None

	This function does not generate any output.

	.EXAMPLE

	Remove-RegistryKey -Key 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'

	.EXAMPLE

	Remove-RegistryKey -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'RunAppInstall'

	.EXAMPLE

	Remove-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Example' -Name '(Default)'

	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[String]$Key,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]$Name,
		[Parameter(Mandatory = $false)]
		[Switch]$Recurse,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[String]$SID,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[Boolean]$ContinueOnError = $true
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
			If ($PSBoundParameters.ContainsKey('SID')) {
				[String]$Key = Convert-RegistryPath -Key $Key -SID $SID
			} Else {
				[String]$Key = Convert-RegistryPath -Key $Key
			}

			If (-not $Name) {
				If (Test-Path -LiteralPath $Key -ErrorAction 'Stop') {
					If ($Recurse) {
						Write-Log -Message "Deleting registry key recursively [$Key]." -Source ${CmdletName}
						$null = Remove-Item -LiteralPath $Key -Force -Recurse -ErrorAction 'Stop'
					} Else {
						If ($null -eq (Get-ChildItem -LiteralPath $Key -ErrorAction 'Stop')) {
							## Check if there are subkeys of $Key, if so, executing Remove-Item will hang. Avoiding this with Get-ChildItem.
							Write-Log -Message "Deleting registry key [$Key]." -Source ${CmdletName}
							$null = Remove-Item -LiteralPath $Key -Force -ErrorAction 'Stop'
						} Else {
							Throw "Unable to delete child key(s) of [$Key] without [-Recurse] switch."
						}
					}
				} Else {
					Write-Log -Message "Unable to delete registry key [$Key] because it does not exist." -Severity 2 -Source ${CmdletName}
				}
			} Else {
				If (Test-Path -LiteralPath $Key -ErrorAction 'Stop') {
					Write-Log -Message "Deleting registry value [$Key] [$Name]." -Source ${CmdletName}

					If ($Name -eq '(Default)') {
						## Remove (Default) registry key value with the following workaround because Remove-ItemProperty cannot remove the (Default) registry key value
						$null = (Get-Item -LiteralPath $Key -ErrorAction 'Stop').OpenSubKey('', 'ReadWriteSubTree').DeleteValue('')
					} Else {
						$null = Remove-ItemProperty -LiteralPath $Key -Name $Name -Force -ErrorAction 'Stop'
					}
				} Else {
					Write-Log -Message "Unable to delete registry value [$Key] [$Name] because registry key does not exist." -Severity 2 -Source ${CmdletName}
				}
			}
		} Catch [System.Management.Automation.PSArgumentException] {
			Write-Log -Message "Unable to delete registry value [$Key] [$Name] because it does not exist." -Severity 2 -Source ${CmdletName}
		} Catch {
			If (-not $Name) {
				Write-Log -Message "Failed to delete registry key [$Key]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to delete registry key [$Key]: $($_.Exception.Message)"
				}
			} Else {
				Write-Log -Message "Failed to delete registry value [$Key] [$Name]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to delete registry value [$Key] [$Name]: $($_.Exception.Message)"
				}
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Invoke-HKCURegistrySettingsForAllUsers
Function Invoke-HKCURegistrySettingsForAllUsers {
	<#
	.SYNOPSIS

	Set current user registry settings for all current users and any new users in the future.

	.DESCRIPTION

	Set HKCU registry settings for all current and future users by loading their NTUSER.dat registry hive file, and making the modifications.

	This function will modify HKCU settings for all users even when executed under the SYSTEM account.

	To ensure new users in the future get the registry edits, the Default User registry hive used to provision the registry for new users is modified.

	This function can be used as an alternative to using ActiveSetup for registry settings.

	The advantage of using this function over ActiveSetup is that a user does not have to log off and log back on before the changes take effect.

	.PARAMETER RegistrySettings

	Script block which contains HKCU registry settings which should be modified for all users on the system. Must specify the -SID parameter for all HKCU settings.

	.PARAMETER UserProfiles

	Specify the user profiles to modify HKCU registry settings for. Default is all user profiles except for system profiles.

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	None

	This function does not generate any output.

	.EXAMPLE
	```powershell
	[ScriptBlock]$HKCURegistrySettings = {
		Set-RegistryKey -Key 'HKCU\Software\Microsoft\Office\14.0\Common' -Name 'qmenable' -Value 0 -Type DWord -SID $UserProfile.SID
		Set-RegistryKey -Key 'HKCU\Software\Microsoft\Office\14.0\Common' -Name 'updatereliabilitydata' -Value 1 -Type DWord -SID $UserProfile.SID
	}

	Invoke-HKCURegistrySettingsForAllUsers -RegistrySettings $HKCURegistrySettings
	```
	.NOTES

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[ScriptBlock]$RegistrySettings,
		[Parameter(Mandatory = $false)]
		[ValidateNotNullorEmpty()]
		[PSObject[]]$UserProfiles = (Get-UserProfiles)
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		ForEach ($UserProfile in $UserProfiles) {
			Try {
				#  Set the path to the user's registry hive when it is loaded
				[String]$UserRegistryPath = "Registry::HKEY_USERS\$($UserProfile.SID)"

				#  Set the path to the user's registry hive file
				[String]$UserRegistryHiveFile = Join-Path -Path $UserProfile.ProfilePath -ChildPath 'NTUSER.DAT'

				#  Load the User profile registry hive if it is not already loaded because the User is logged in
				[Boolean]$ManuallyLoadedRegHive = $false
				If (-not (Test-Path -LiteralPath $UserRegistryPath)) {
					#  Load the User registry hive if the registry hive file exists
					If (Test-Path -LiteralPath $UserRegistryHiveFile -PathType 'Leaf') {
						Write-Log -Message "Loading the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]." -Source ${CmdletName}
						[String]$HiveLoadResult = & "$envWinDir\System32\reg.exe" load "`"HKEY_USERS\$($UserProfile.SID)`"" "`"$UserRegistryHiveFile`""

						If ($global:LastExitCode -ne 0) {
							Throw "Failed to load the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. Failure message [$HiveLoadResult]. Continue..."
						}

						[Boolean]$ManuallyLoadedRegHive = $true
					} Else {
						Throw "Failed to find the registry hive file [$UserRegistryHiveFile] for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. Continue..."
					}
				} Else {
					Write-Log -Message "The user [$($UserProfile.NTAccount)] registry hive is already loaded in path [HKEY_USERS\$($UserProfile.SID)]." -Source ${CmdletName}
				}

				## Execute ScriptBlock which contains code to manipulate HKCU registry.
				#  Make sure read/write calls to the HKCU registry hive specify the -SID parameter or settings will not be changed for all users.
				#  Example: Set-RegistryKey -Key 'HKCU\Software\Microsoft\Office\14.0\Common' -Name 'qmenable' -Value 0 -Type DWord -SID $UserProfile.SID
				Write-Log -Message 'Executing ScriptBlock to modify HKCU registry settings for all users.' -Source ${CmdletName}
				& $RegistrySettings
			} Catch {
				Write-Log -Message "Failed to modify the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)] `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			} Finally {
				If ($ManuallyLoadedRegHive) {
					Try {
						Write-Log -Message "Unload the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]." -Source ${CmdletName}
						[String]$HiveLoadResult = & "$envWinDir\System32\reg.exe" unload "`"HKEY_USERS\$($UserProfile.SID)`""

						If ($global:LastExitCode -ne 0) {
							Write-Log -Message "REG.exe failed to unload the registry hive and exited with exit code [$($global:LastExitCode)]. Performing manual garbage collection to ensure successful unloading of registry hive." -Severity 2 -Source ${CmdletName}
							[GC]::Collect()
							[GC]::WaitForPendingFinalizers()
							Start-Sleep -Seconds 5

							Write-Log -Message "Unload the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]." -Source ${CmdletName}
							[String]$HiveLoadResult = & "$envWinDir\System32\reg.exe" unload "`"HKEY_USERS\$($UserProfile.SID)`""
							If ($global:LastExitCode -ne 0) {
								Throw "REG.exe failed with exit code [$($global:LastExitCode)] and result [$HiveLoadResult]."
							}
						}
					} Catch {
						Write-Log -Message "Failed to unload the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
					}
				}
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-LoggedOnUser
Function Get-LoggedOnUser {
	<#
	.SYNOPSIS

	Get session details for all local and RDP logged on users.

	.DESCRIPTION

	Get session details for all local and RDP logged on users using Win32 APIs. Get the following session details:
		NTAccount, SID, UserName, DomainName, SessionId, SessionName, ConnectState, IsCurrentSession, IsConsoleSession, IsUserSession, IsActiveUserSession
		IsRdpSession, IsLocalAdmin, LogonTime, IdleTime, DisconnectTime, ClientName, ClientProtocolType, ClientDirectory, ClientBuildNumber

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	None

	This function does not return any objects.

	.EXAMPLE

	Get-LoggedOnUser

	.NOTES

	Description of ConnectState property:

	Value        Description
	-----        -----------
	Active       A user is logged on to the session.
	ConnectQuery The session is in the process of connecting to a client.
	Connected    A client is connected to the session.
	Disconnected The session is active, but the client has disconnected from it.
	Down         The session is down due to an error.
	Idle         The session is waiting for a client to connect.
	Initializing The session is initializing.
	Listening    The session is listening for connections.
	Reset        The session is being reset.
	Shadowing    This session is shadowing another session.

	Description of IsActiveUserSession property:

	- If a console user exists, then that will be the active user session.
	- If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user that has ConnectState either 'Active' or 'Connected' is the active user.

	Description of IsRdpSession property:
	- Gets a value indicating whether the user is associated with an RDP client session.

	Description of IsLocalAdmin property:
	- Checks whether the user is a member of the Administrators group

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message 'Getting session information for all logged on users.' -Source ${CmdletName}
			Write-Output -InputObject ([PSADT.QueryUser]::GetUserSessionInfo("$env:ComputerName"))
		} Catch {
			Write-Log -Message "Failed to get session information for all logged on users. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


#region Function Get-PendingReboot
Function Get-PendingReboot {
	<#
	.SYNOPSIS

	Get the pending reboot status on a local computer.

	.DESCRIPTION

	Check WMI and the registry to determine if the system has a pending reboot operation from any of the following:
	a) Component Based Servicing (Vista, Windows 2008)
	b) Windows Update / Auto Update (XP, Windows 2003 / 2008)
	c) SCCM 2012 Clients (DetermineIfRebootPending WMI method)
	d) App-V Pending Tasks (global based Appv 5.0 SP2)
	e) Pending File Rename Operations (XP, Windows 2003 / 2008)

	.INPUTS

	None

	You cannot pipe objects to this function.

	.OUTPUTS

	PSObject

	Returns a custom object with the following properties
	- ComputerName
	- LastBootUpTime
	- IsSystemRebootPending
	- IsCBServicingRebootPending
	- IsWindowsUpdateRebootPending
	- IsSCCMClientRebootPending
	- IsFileRenameRebootPending
	- PendingFileRenameOperations
	- ErrorMsg

	.EXAMPLE

	Get-PendingReboot

	Returns custom object with following properties:
	- ComputerName
	- LastBootUpTime
	- IsSystemRebootPending
	- IsCBServicingRebootPending
	- IsWindowsUpdateRebootPending
	- IsSCCMClientRebootPending
	- IsFileRenameRebootPending
	- PendingFileRenameOperations
	- ErrorMsg

	.EXAMPLE

	(Get-PendingReboot).IsSystemRebootPending

	Returns boolean value determining whether or not there is a pending reboot operation.

	.NOTES

	ErrorMsg only contains something if an error occurred

	.LINK

	https://psappdeploytoolkit.com
	#>
	[CmdletBinding()]
	Param (
	)

	Begin {
		## Get the name of this function and write header
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

		## Initialize variables
		[String]$private:ComputerName = $envComputerNameFQDN
		$PendRebootErrorMsg = $null
	}
	Process {
		Write-Log -Message "Getting the pending reboot status on the local computer [$ComputerName]." -Source ${CmdletName}

		## Get the date/time that the system last booted up
		Try {
			[Nullable[DateTime]]$LastBootUpTime = (Get-Date -ErrorAction 'Stop') - ([Timespan]::FromMilliseconds([Math]::Abs([Environment]::TickCount)))
		} Catch {
			[Nullable[DateTime]]$LastBootUpTime = $null
			[String[]]$PendRebootErrorMsg += "Failed to get LastBootUpTime: $($_.Exception.Message)"
			Write-Log -Message "Failed to get LastBootUpTime. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}

		## Determine if a Windows Vista/Server 2008 and above machine has a pending reboot from a Component Based Servicing (CBS) operation
		Try {
			If (([Version]$envOSVersion).Major -ge 5) {
				If (Test-Path -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction 'Stop') {
					[Nullable[Boolean]]$IsCBServicingRebootPending = $true
				} Else {
					[Nullable[Boolean]]$IsCBServicingRebootPending = $false
				}
			}
		} Catch {
			[Nullable[Boolean]]$IsCBServicingRebootPending = $null
			[String[]]$PendRebootErrorMsg += "Failed to get IsCBServicingRebootPending: $($_.Exception.Message)"
			Write-Log -Message "Failed to get IsCBServicingRebootPending. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}

		## Determine if there is a pending reboot from a Windows Update
		Try {
			If (Test-Path -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction 'Stop') {
				[Nullable[Boolean]]$IsWindowsUpdateRebootPending = $true
			} Else {
				[Nullable[Boolean]]$IsWindowsUpdateRebootPending = $false
			}
		} Catch {
			[Nullable[Boolean]]$IsWindowsUpdateRebootPending = $null
			[String[]]$PendRebootErrorMsg += "Failed to get IsWindowsUpdateRebootPending: $($_.Exception.Message)"
			Write-Log -Message "Failed to get IsWindowsUpdateRebootPending. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}

		## Determine if there is a pending reboot from a pending file rename operation
		[Boolean]$IsFileRenameRebootPending = $false
		$PendingFileRenameOperations = $null
		If (Test-RegistryValue -Key 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations') {
			#  If PendingFileRenameOperations value exists, set $IsFileRenameRebootPending variable to $true
			[Boolean]$IsFileRenameRebootPending = $true
			#  Get the value of PendingFileRenameOperations
			Try {
				[String[]]$PendingFileRenameOperations = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction 'Stop' | Select-Object -ExpandProperty 'PendingFileRenameOperations' -ErrorAction 'Stop'
			} Catch {
				[String[]]$PendRebootErrorMsg += "Failed to get PendingFileRenameOperations: $($_.Exception.Message)"
				Write-Log -Message "Failed to get PendingFileRenameOperations. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			}
		}

		## Determine SCCM 2012 Client reboot pending status
		Try {
			[Boolean]$IsSccmClientNamespaceExists = $false
			[PSObject]$SCCMClientRebootStatus = Invoke-WmiMethod -ComputerName $ComputerName -Namespace 'ROOT\CCM\ClientSDK' -Class 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending' -ErrorAction 'Stop'
			[Boolean]$IsSccmClientNamespaceExists = $true
			If ($SCCMClientRebootStatus.ReturnValue -ne 0) {
				Throw "'DetermineIfRebootPending' method of 'ROOT\CCM\ClientSDK\CCM_ClientUtilities' class returned error code [$($SCCMClientRebootStatus.ReturnValue)]"
			} Else {
				Write-Log -Message 'Successfully queried SCCM client for reboot status.' -Source ${CmdletName}
				[Nullable[Boolean]]$IsSCCMClientRebootPending = $false
				If ($SCCMClientRebootStatus.IsHardRebootPending -or $SCCMClientRebootStatus.RebootPending) {
					[Nullable[Boolean]]$IsSCCMClientRebootPending = $true
					Write-Log -Message 'Pending SCCM reboot detected.' -Source ${CmdletName}
				} Else {
					Write-Log -Message 'Pending SCCM reboot not detected.' -Source ${CmdletName}
				}
			}
		} Catch [System.Management.ManagementException] {
			[Nullable[Boolean]]$IsSCCMClientRebootPending = $null
			[Boolean]$IsSccmClientNamespaceExists = $false
			Write-Log -Message 'Failed to get IsSCCMClientRebootPending. Failed to detect the SCCM client WMI class.' -Severity 3 -Source ${CmdletName}
		} Catch {
			[Nullable[Boolean]]$IsSCCMClientRebootPending = $null
			[String[]]$PendRebootErrorMsg += "Failed to get IsSCCMClientRebootPending: $($_.Exception.Message)"
			Write-Log -Message "Failed to get IsSCCMClientRebootPending. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}

		## Determine if there is a pending reboot from an App-V global Pending Task. (User profile based tasks will complete on logoff/logon)
		Try {
			If (Test-Path -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Software\Microsoft\AppV\Client\PendingTasks' -ErrorAction 'Stop') {
				[Nullable[Boolean]]$IsAppVRebootPending = $true
			} Else {
				[Nullable[Boolean]]$IsAppVRebootPending = $false
			}
		} Catch {
			[Nullable[Boolean]]$IsAppVRebootPending = $null
			[String[]]$PendRebootErrorMsg += "Failed to get IsAppVRebootPending: $($_.Exception.Message)"
			Write-Log -Message "Failed to get IsAppVRebootPending. `r`n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}

		## Determine if there is a pending reboot for the system
		[Boolean]$IsSystemRebootPending = $false
		If ($IsCBServicingRebootPending -or $IsWindowsUpdateRebootPending -or $IsSCCMClientRebootPending -or $IsFileRenameRebootPending) {
			[Boolean]$IsSystemRebootPending = $true
		}

		## Create a custom object containing pending reboot information for the system
		[PSObject]$PendingRebootInfo = New-Object -TypeName 'PSObject' -Property @{
			ComputerName                 = $ComputerName
			LastBootUpTime               = $LastBootUpTime
			IsSystemRebootPending        = $IsSystemRebootPending
			IsCBServicingRebootPending   = $IsCBServicingRebootPending
			IsWindowsUpdateRebootPending = $IsWindowsUpdateRebootPending
			IsSCCMClientRebootPending    = $IsSCCMClientRebootPending
			IsAppVRebootPending          = $IsAppVRebootPending
			IsFileRenameRebootPending    = $IsFileRenameRebootPending
			PendingFileRenameOperations  = $PendingFileRenameOperations
			ErrorMsg                     = $PendRebootErrorMsg
		}
		Write-Log -Message "Pending reboot status on the local computer [$ComputerName]: `r`n$($PendingRebootInfo | Format-List | Out-String)" -Source ${CmdletName}
	}
	End {
		Write-Output -InputObject ($PendingRebootInfo | Select-Object -Property 'ComputerName', 'LastBootUpTime', 'IsSystemRebootPending', 'IsCBServicingRebootPending', 'IsWindowsUpdateRebootPending', 'IsSCCMClientRebootPending', 'IsAppVRebootPending', 'IsFileRenameRebootPending', 'PendingFileRenameOperations', 'ErrorMsg')

		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion


function Test-ExistingPath {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $Path
	)

	if (-not (Test-Path -Path $Path)) {
		New-Item -Path $Path -ItemType Directory -Force | Out-Null
	}

}

function Get-RegistryValue {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		$Path,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		$Name
	)

	Return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
}

function Set-RegistryValue {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		$Path,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		$Name,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		$Value,
		[ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'Qword')]
		$PropertyType = 'String'
	)

	#Make sure the key exists
	If (!(Test-Path $Path)) {
		New-Item $Path -Force | Out-Null
	}

	New-ItemProperty -Force -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType | Out-Null
}

function Install-CCMClient {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $CMMP = 'atklsccm.kostweingroup.intern',
		[Parameter()]
		[String] $CMSiteCode = 'KOW'
	)

	begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}

	process {

		try {
			#Get ccm cache path for later cleanup...
			try {
				$ccmcache = ([wmi]"ROOT\ccm\SoftMgmtAgent:CacheConfig.ConfigKey='Cache'").Location
			} catch {
				#Write-Log -Message "Error"
				continue
			}

			#download ccmsetup.exe from MP
			#$webclient = New-Object System.Net.WebClient
			$webclient = [System.Net.WebClient]::new()
			$url = "http://$($CMMP)/CCM_Client/ccmsetup.exe"
			$file = 'c:\windows\temp\ccmsetup.exe'
			$webclient.DownloadFile($url, $file)

			#stop the old sms agent service
			#Stop-Service 'ccmexec' -ErrorAction SilentlyContinue
			Stop-ServiceAndDependencies -Name 'CcmExec' -SkipServiceExistsTest -ErrorAction SilentlyContinue

			#Cleanup cache
			if ($null -ne $ccmcache) {
				try {
					Get-ChildItem $ccmcache '*' -Directory | ForEach-Object { [io.directory]::delete($_.fullname, $true) } -ErrorAction SilentlyContinue
				} catch {
					Write-Log -Message 'Error deleting CCMCache'
				}
			}

			#Cleanup Execution History
			Remove-RegistryKey -Key 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS\Mobile Client' -Recurse
			Remove-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client' -Recurse

			#Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS\Mobile Client\*' -Recurse -ErrorAction SilentlyContinue
			#Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\*' -Recurse -ErrorAction SilentlyContinue

			#kill existing instances of ccmsetup.exe
			$ccm = (Get-Process 'ccmsetup' -ErrorAction SilentlyContinue)
			if ($null -ne $ccm) {
				$ccm.kill()
			}

			#run ccmsetup
			Start-Process -FilePath $File -PassThru -Wait -ArgumentList "/mp:$($CMMP) /source:http://$($CMMP)/CCM_Client CCMHTTPPORT=80 RESETKEYINFORMATION=TRUE SMSSITECODE=$($CMSiteCode) SMSSLP=$($CMMP) FSP=$($CMMP)"
			#Start-Sleep(5)
			#'ccmsetup started...'
		} catch {
			$Message = "Error executing CMSetup `n`t$(Resolve-Error)"
			Write-Log -Message $Message -Source ${CmdletName} -Severity 3

		}

	}

	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}

}

function Invoke-ForcedClientUninstall {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $ParameterName
	)

	[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

	Try {
		Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
	} Catch {
		Exit 0
	}

	# Stop Services
	Stop-Service -Name ccmsetup -Force -ErrorAction SilentlyContinue
	Stop-Service -Name CcmExec -Force -ErrorAction SilentlyContinue
	Stop-Service -Name smstsmgr -Force -ErrorAction SilentlyContinue
	Stop-Service -Name CmRcService -Force -ErrorAction SilentlyContinue

	# Remove WMI Namespaces
	Get-CimInstance -Query "SELECT * FROM __Namespace WHERE Name='ccm'" -Namespace root | Remove-CimInstance
	Get-CimInstance -Query "SELECT * FROM __Namespace WHERE Name='sms'" -Namespace root\cimv2 | Remove-CimInstance

	# Remove Services from Registry
	$MyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services'
	Remove-Item -Path $MyPath\CCMSetup -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $MyPath\CcmExec -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $MyPath\smstsmgr -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $MyPath\CmRcService -Force -Recurse -ErrorAction SilentlyContinue

	# Remove SCCM Client from Registry
	$MyPath = 'HKLM:\SOFTWARE\Microsoft'
	Remove-Item -Path $MyPath\CCM -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $MyPath\CCMSetup -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $MyPath\SMS -Force -Recurse -ErrorAction SilentlyContinue

	# Remove Scheduled Tasks
	$Scheduled = Get-ScheduledTask -TaskName '*Configuration Manager*'

	foreach ($Task in $Scheduled) {
		Stop-ScheduledTask -InputObject $Task
		Unregister-ScheduledTask -InputObject $Task -Confirm $false
	}

	# Remove Folders and Files
	$MyPath = $env:WinDir
	#Remove-Item -Path $MyPath\CCM -Force -Recurse -ErrorAction SilentlyContinue
	#Remove-Item -Path $MyPath\ccmsetup -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $MyPath\ccmcache -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $MyPath\SMSCFG.ini -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $MyPath\SMS*.mif -Force -ErrorAction SilentlyContinue

	try {
		Remove-Item -Path $MyPath\CCM -Force -Recurse -ErrorAction SilentlyContinue
	} catch {
		Stop-ProcessLockingFile -FilePath $MyPath\CCM
		Remove-Item -Path $MyPath\CCM -Force -Recurse
	}

	try {
		Remove-Item -Path $MyPath\ccmsetup -Force -Recurse -ErrorAction SilentlyContinue
	} catch {
		Stop-ProcessLockingFile -FilePath $MyPath\ccmsetup
		Remove-Item -Path $MyPath\ccmsetup -Force -Recurse
	}

}

function Get-ProcessLockingFile {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $FilePath
	)

	Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class ProcessUtils {

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK {
        public IntPtr Information;
        public IntPtr Status;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_PROCESS_IDS_USING_FILE_INFORMATION {
        public ulong NumberOfProcessIdsInList;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public ulong[] ProcessIdList;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationFile(SafeFileHandle FileHandle, ref IO_STATUS_BLOCK IoStatusBlock,
        IntPtr FileInformation, uint Length, int FileInformationClass);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string lpFileName, FileAccess dwDesiredAccess,
        FileShare dwShareMode, IntPtr lpSecurityAttributes, FileMode dwCreationDisposition,
        FileAttributes dwFlagsAndAttributes, IntPtr hTemplateFile);

    public static ulong[] GetProcessesUsingFile(string filePath) {
        var processIds = new ulong[0];
        var ioStatusBlock = new IO_STATUS_BLOCK();
        var fileInfo = new FILE_PROCESS_IDS_USING_FILE_INFORMATION();

        using (var fileHandle = CreateFile(filePath, FileAccess.Read, FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero)) {
            if (!fileHandle.IsInvalid) {
                var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
                var fileInfoSize = Marshal.SizeOf(fileInfo);

                try {
                    int result = NtQueryInformationFile(fileHandle, ref ioStatusBlock, fileInfoPtr, (uint)fileInfoSize, 47);
                    if (result == 0) {
                        fileInfo = Marshal.PtrToStructure<FILE_PROCESS_IDS_USING_FILE_INFORMATION>(fileInfoPtr);
                        if (fileInfo.NumberOfProcessIdsInList > 0) {
                            processIds = new ulong[fileInfo.NumberOfProcessIdsInList];
                            Array.Copy(fileInfo.ProcessIdList, processIds, (int)fileInfo.NumberOfProcessIdsInList);
                        }
                    }
                }
                finally {
                    Marshal.FreeHGlobal(fileInfoPtr);
                }
            }
        }
        return processIds;
    }
}
'@

	# Get processes using a file:
	#$file = 'c:\temp\test.txt'
	[ProcessUtils]::GetProcessesUsingFile($FilePath)

}

function Stop-ProcessLockingFile {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $FilePath
	)

	$ProcID = Get-ProcessLockingFile -FilePath $FilePath
	if ($ProcID) {
		Stop-Process -Id $ProcID -Force
	}

}

#TODO: integrieren

Function Start-RepairServices {
	[CmdletBinding()]
	Param(
		[parameter(Mandatory = $true)]
		$ServiceName  # Must be string or array of strings
	)

	begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	process {

		ForEach ($Service in $ServiceName) {
			Write-Debug "Verifying $Service"

			Try {
				$OBJ_service = Get-Service -Name $Service
				$Test = $True

				# Check nested required services
				ForEach ($OBJ_SubService in $OBJ_service.RequiredServices) {
					Start-RepairServices $OBJ_SubService.Name
				}

				# Start service if it isn't already
				if ($obj_service.Status -ne 'Running') {
					Write-Debug 'Starting service.'
					Set-Service -Name $obj_service.Name -StartupType Automatic -Status Running
					Start-Service -Name $obj_service.Name
				}
			} Catch {
				Write-Debug 'Error fixing service'
			}
		}

	}
	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}

}

Function Start-RegisterWindowsComponents {
	[CmdletBinding()]
	Param (
		[parameter(Mandatory = $true)]
		$Components  # Must be string or array of strings
	)

	begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	process {

		ForEach ($Component in $Components) {
			Write-Debug "Verifying $Component"

			Try {
				Write-Debug "regsvr32.exe /s C:\Windows\system32\$Component"
				regsvr32.exe /s "C:\Windows\system32\$Component"
			} Catch {
				Write-Debug 'Error fixing service'
			}
		}

	}
	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}

}

Function Reset-DCOMPermissions {

	begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	process {

		$converter = New-Object system.management.ManagementClass Win32_SecurityDescriptorHelper

		$Reg = [WMIClass]'root\default:StdRegProv'
		$newDCOMSDDL = 'O:BAG:BAD:(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)(A;;CCDCLCSWRP;;;IU)'
		$DCOMbinarySD = $converter.SDDLToBinarySD($newDCOMSDDL)
		$Reg.SetBinaryValue(2147483650, 'SOFTWARE\Microsoft\Ole', 'DefaultLaunchPermission', $DCOMbinarySD.binarySD)

		$Reg = [WMIClass]'root\default:StdRegProv'
		$newDCOMSDDL = 'O:BAG:BAD:(A;;CCDCLC;;;WD)(A;;CCDCLC;;;LU)(A;;CCDCLC;;;S-1-5-32-562)(A;;CCDCLC;;;AN)'
		$DCOMbinarySD = $converter.SDDLToBinarySD($newDCOMSDDL)
		$Reg.SetBinaryValue(2147483650, 'SOFTWARE\Microsoft\Ole', 'MachineAccessRestriction', $DCOMbinarySD.binarySD)

		$Reg = [WMIClass]'root\default:StdRegProv'
		$newDCOMSDDL = 'O:BAG:BAD:(A;;CCDCSW;;;WD)(A;;CCDCLCSWRP;;;BA)(A;;CCDCLCSWRP;;;LU)(A;;CCDCLCSWRP;;;S-1-5-32-562)'
		$DCOMbinarySD = $converter.SDDLToBinarySD($newDCOMSDDL)
		$Reg.SetBinaryValue(2147483650, 'SOFTWARE\Microsoft\Ole', 'MachineLaunchRestriction', $DCOMbinarySD.binarySD)

	}
	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}

}

Function Repair-WMI {

	begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	process {

		winmgmt /verifyrepository
		winmgmt /salvagerepository

	}
	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}

}

Function Repair-SCCM {

	begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	process {

		Write-Debug 'Repairing CCM Client'
		Try {
			$getProcess = Get-Process -Name ccmrepair*
			If ($getProcess) {
				Write-Debug '[WARNING] SCCM Repair is already running. Script will end.'
				Exit 1
			} Else {
				Write-Debug "[INFO] Connect to the WMI Namespace on $strComputer."
				$SMSCli = [wmiclass] '\root\ccm:sms_client'
				Write-Debug "[INFO] Trigger the SCCM Repair on $strComputer."
				# The actual repair is put in a variable, to trap unwanted output.
				$repair = $SMSCli.RepairClient()
				Write-Debug '[INFO] Successfully connected to the WMI Namespace and triggered the SCCM Repair'
			}
		} Catch {
			# The soft repair trigger failed, so lets fall back to some more hands on methods.

			Stop-Service -Name 'CcmExec'

			$CCMPath = (Get-ItemProperty('HKLM:\SOFTWARE\Microsoft\SMS\Client\Configuration\Client Properties')).$('Local SMS Path')
			$files = Get-ChildItem "$($CCMPath)ServiceData\Messaging\EndpointQueues" -Include *.msg, *.que -Recurse

			foreach ($file in $files) {
				Try {
					Write-Debug "Removing $file.FullName"
					Remove-Item $file.FullName -Force
				} Catch {
					Write-Debug "Failed to remove $file.FullName"
				}
			}

			$ccmrepair = "$($CCMPath)ccmrepair.exe"
			$CCMRepairFailed = $False

			# See if CCMRepair exists
			If (Test-Path $ccmrepair) {
				Start-Process $ccmrepair
				Start-Sleep -Seconds 5
				$count = 0

				While (Get-Process -Name ccmrepair*) {
					if ($count -gt 60) {
						Write-Debug "We've looped more than 60 times which means this has ran for more than 10 minutes."
						Write-Debug "Break out so we don't run forever."
						$CCMRepairFailed = $True
						break
					}
					$count++
					Start-Sleep -Seconds 10
				}
			} else {
				Write-Debug "CCMRepair doesn't exist"
				$CCMRepairFailed = $True
			}

			if ($CCMRepairFailed) {
				# CCMRepair failed or doesn't exist, try and fall back to CCMSetup

				$ccmsetup = "$env:SystemRoot\ccmsetup\ccmsetup.exe"
				$ccmsetupargs = "/remediate:client  /log:""$($CCMPath)logs\repair-msi-scripted.log"""
				$CCMSetupFailed = $False

				# See if CCMSetup exists
				If (Test-Path $ccmsetup) {
					Start-Process $ccmsetup -ArgumentList $ccmsetupargs
					Start-Sleep -Seconds 5
					$count = 0

					While (Get-Process -Name ccmsetup*) {
						if ($count -gt 60) {
							Write-Debug "We've looped more than 60 times which means this has ran for more than 10 minutes."
							Write-Debug "Break out so we don't run forever."
							$CCMSetupFailed = $True
							break
						}
						$count++
						Start-Sleep -Seconds 10
					}
				} else {
					Write-Debug "CCMSetup doesn't exist"
					$CCMSetupFailed = $True
				}
			}

			# Probably should do something if running CCMsetup failed but that's for a future improvement.
			# For now we just give up.
		}

	}
	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}


}

function Get-CMLastTriggerTime {
<#
	.SYNOPSIS
	Retrieves the last trigger time for various Configuration Manager schedules.

	.DESCRIPTION
	The `Get-CMLastTriggerTime` function queries the Configuration Manager to get the last trigger time for a set of predefined schedules.
	These schedules include tasks such as Hardware Inventory, Software Inventory, Heartbeat Discovery, and many others.

	.PARAMETER ScheduleIds
	A hashtable containing predefined Schedule IDs for different Configuration Manager tasks.

	.OUTPUTS
	[PSCustomObject]
	Returns a PowerShell custom object containing the last trigger times for each schedule.

	.EXAMPLE
	PS> Get-CMLastTriggerTime

	This example runs the function and returns the last trigger times for the predefined Configuration Manager schedules.

	.NOTES
	The function uses the CIM cmdlets to query the `CCM_Scheduler_History` class in the `Root\CCM\Scheduler` namespace.
	Only schedules with non-empty properties are included in the output.
#>
	[CmdletBinding()]
	param (

	)

	[Hashtable]$ScheduleIds = @{
		HardwareInventory                        = '{00000000-0000-0000-0000-000000000001}'; # Hardware Inventory Collection Task
		SoftwareInventory                        = '{00000000-0000-0000-0000-000000000002}'; # Software Inventory Collection Task
		HeartbeatDiscovery                       = '{00000000-0000-0000-0000-000000000003}'; # Heartbeat Discovery Cycle
		SoftwareInventoryFileCollection          = '{00000000-0000-0000-0000-000000000010}'; # Software Inventory File Collection Task
		RequestMachinePolicy                     = '{00000000-0000-0000-0000-000000000021}'; # Request Machine Policy Assignments
		EvaluateMachinePolicy                    = '{00000000-0000-0000-0000-000000000022}'; # Evaluate Machine Policy Assignments
		RefreshDefaultMp                         = '{00000000-0000-0000-0000-000000000023}'; # Refresh Default MP Task
		RefreshLocationServices                  = '{00000000-0000-0000-0000-000000000024}'; # Refresh Location Services Task
		LocationServicesCleanup                  = '{00000000-0000-0000-0000-000000000025}'; # Location Services Cleanup Task
		SoftwareMeteringReport                   = '{00000000-0000-0000-0000-000000000031}'; # Software Metering Report Cycle
		SourceUpdate                             = '{00000000-0000-0000-0000-000000000032}'; # Source Update Manage Update Cycle
		PolicyAgentCleanup                       = '{00000000-0000-0000-0000-000000000040}'; # Policy Agent Cleanup Cycle
		RequestMachinePolicy2                    = '{00000000-0000-0000-0000-000000000042}'; # Request Machine Policy Assignments
		CertificateMaintenance                   = '{00000000-0000-0000-0000-000000000051}'; # Certificate Maintenance Cycle
		PeerDistributionPointStatus              = '{00000000-0000-0000-0000-000000000061}'; # Peer Distribution Point Status Task
		PeerDistributionPointProvisioning        = '{00000000-0000-0000-0000-000000000062}'; # Peer Distribution Point Provisioning Status Task
		ComplianceIntervalEnforcement            = '{00000000-0000-0000-0000-000000000071}'; # Compliance Interval Enforcement
		SoftwareUpdatesAgentAssignmentEvaluation = '{00000000-0000-0000-0000-000000000108}'; # Software Updates Agent Assignment Evaluation Cycle
		UploadStateMessage                       = '{00000000-0000-0000-0000-000000000111}'; # Send Unsent State Messages
		StateMessageManager                      = '{00000000-0000-0000-0000-000000000112}'; # State Message Manager Task
		SoftwareUpdatesScan                      = '{00000000-0000-0000-0000-000000000113}'; # Force Update Scan
		#AMTProvisionCycle                        = '{00000000-0000-0000-0000-000000000120}'; # AMT Provision Cycle
	}

	$SortedScheduleIds = $ScheduleIds.GetEnumerator() | Sort-Object Value
	$Triggers = [System.Collections.Specialized.OrderedDictionary]::new()

	foreach ($Schedule in $SortedScheduleIds) {

		$CimArgs = @{
			Query     = "SELECT * FROM CCM_Scheduler_History WHERE ScheduleID='$($Schedule.Value)' and UserSID='Machine'"
			Namespace = 'Root\CCM\Scheduler'
		}

		$Trigger = Get-CimInstance @CimArgs
		$Properties = [Ordered]@{}

		foreach ($Prop in $Trigger.CimInstanceProperties) {
			if ($Prop.Value) {
				$Properties.Add($Prop.Name, $Prop.Value)
			}
		}

		if ($Properties.Count -gt 0) {
			$Triggers.Add($Schedule.Key, [PSCustomObject]$Properties)
		}

	}

	return [PSCustomObject]$Triggers

}

function Verify-CMLastTriggers {
	[CmdletBinding()]
	param (

	)

	begin {

	}
	process {

	}
	end {

	}

}
Function Invoke-PolicyHandler {

	begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	process {

		# Reset the policy, and fetch new ones.

		Try {
			$SMSCli = [wmiclass] '\root\ccm:sms_client'

			$trapreturn = $SMSCli.ResetPolicy()
			Start-Sleep -Seconds 60
			$trapreturn = $SMSCli.RequestMachinePolicy()
			Start-Sleep -Seconds 60
			$trapreturn = $SMSCli.EvaluateMachinePolicy()

		} Catch {
			# Do nothing for now, but we should do some sort of handling here.
		}

	}
	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}

}

function Invoke-MECMRepair {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $ParameterName
	)

	begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	process {
		Start-RepairServices $Services
		Start-RegisterWindowsComponents $DLLComponents
		Reset-DCOMPermissions
		Repair-WMI
		Repair-SCCM
		Invoke-PolicyHandler
	}
	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}

}

#TODO: integrieren

function Invoke-HealthChecks {
	[CmdletBinding()]
	param (

	)

	begin {

		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

		#Variables
		# If any of the below variables is set to true in the code below it means remediation should be triggered
		$WMICheckStatus = $false
		$CcmExecCheckStatus = $false
		$LastMachinePolicyRequestStatus = $false
		$CurrentManagementPointStatus = $false

		#How many hours back within which the CCM Machine policy download date is deemed healthy
		$LastMachinePolicyHoursRang = 24

		#Cleanup Variables - useful when testing the script manually on an endpoint.
		$AggregateMessages = ''
		$PolicyRequestErrorMsg = ''
		$WMICheckErrorMsg = ''
		$CcmExecErrorMsg = ''
		$ManagementPointErrorMsg = ''
		$LastMachinePolicyRequest = ''
		$CcmExecStatus = ''
		$CurrentManagementPoint = ''

		$ErrorActionPreference = 'Stop'

		$CurrentTime = Get-Date -Format 'dd_MM_yyyy-HH_mm_ss'

		Function Reset-WMI {
			[CmdletBinding()]
			Param (
				$CCMSetupWait = 10
			)

			[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

			Write-Log -Message 'Stopping Malwarebytes Endpoint Agent' -Source ${CmdletName}
			$MLBEndpointAgent = 'C:\Program Files\Malwarebytes Endpoint Agent\UserAgent\EACmd.exe'
			Start-Process -FilePath $MLBEndpointAgent -ArgumentList '--stopmbamservice' -NoNewWindow -Wait

			while ((Get-Service MBAMService).Status -ne 'Stopped') {
				Start-Sleep -Milliseconds 10
			}

			####Do heal WMI
			$Message = 'Stopping winmgmt Service...'
			Write-Log -Message $Message -Source ${CmdletName}
			Stop-ServiceAndDependencies -Name 'Winmgmt' -SkipServiceExistsTest
			#Stop-Service winmgmt -Force

			$Message = 'Resetting WMI repo...'
			Write-Log -Message $Message -Source ${CmdletName}
			winmgmt /resetrepository

			$Message = 'Wait for 10 seconds...'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Sleep -Seconds 10

			#$Message = 'Restart ccmexec service...'
			#Write-Log -Message $Message -Source ${CmdletName}
			#Restart-Service ccmexec -Verbose -Force
			#Start-ServiceAndDependencies -Name CCMExec -SkipServiceExistsTest

			#Test-ServiceExists -Name 'CCMExec' -PassThru | Where-Object { $_ } | ForEach-Object { $_.Delete() }

			$Message = 'ReInstall CM Agent'
			Write-Log -Message $Message -Source ${CmdletName}
			Install-CCMClient

			$Message = 'Wait until ccmsetup is started...'
			Write-Log -Message $Message -Source ${CmdletName}
			$limit = (Get-Date).AddMinutes($CCMSetupWait)

			Do {

				$status = Get-Process ccmsetup -ErrorAction SilentlyContinue

				If (!($status)) {
					$Message = "Waiting for ccmsetup to start - time elapsed: $(($limit - (Get-Date)).minutes) minutes and $(($limit - (Get-Date)).seconds) seconds"
					Write-Log -Message $Message -Source ${CmdletName}
					Start-Sleep -Seconds 30
				} Else {
					$Message = "ccmsetup has started - time elapsed: $(($limit - (Get-Date)).minutes) minutes and $(($limit - (Get-Date)).seconds) seconds"
					Write-Log -Message $Message -Source ${CmdletName}
					$started = $true
				}

			}
			Until ( $started -or ((Get-Date) -gt $limit))

			#Report if the Do while exited without CCMSetup starting
			if ($started -eq $False) {
				$Message = "$($CCMSetupWait) minutes has passed and ccmsetup did not start"
				Write-Log -Message $Message -Source ${CmdletName} -Severity 3

				#Flag the result of this check as failed:
				$WMICheckResult = $False

			} elseif ($started -eq $true) {
				#Flag the result of this check as successful:
				$WMICheckResult = $true
			}

			#Check if CCMSetup has exited with code 0
			$Message = 'Wait until ccmsetup logs an event signalling a successful reconfiguration (Event 1035)...'
			Write-Log -Message $Message -Source ${CmdletName}
			$CCMEventFound = $false

			$limit = (Get-Date).AddMinutes($CCMSetupWait)

			DO {

				$filter = @{
					Logname   = 'Application'
					ID        = 1035
					StartTime = ((Get-Date).AddMinutes(-1))
					EndTime   = (Get-Date)
				}

				try {
					$CCMEvent = Get-WinEvent -FilterHashtable $filter -MaxEvents 1 -ErrorAction SilentlyContinue | Where-Object -Property Message -Like '*Product Name: Configuration Manager Client.*Reconfiguration success or error status: 0.'

					if ($CCMEvent) {
						$Message = "Event showing CCMSetup has reconfigured the client successfully was found at: $($CCMEvent.TimeCreated) - Message: $($CCMEvent.Message)"
						Write-Log -Message $Message -Source ${CmdletName}
						$CCMEventFound = $true
					}

				} catch {
					$CCMEventFound = $false
					Start-Sleep -Seconds 60
					$Message = "No event found at $(Get-Date)"
					Write-Log -Message $Message -Source ${CmdletName}
				}
			}
			Until ( $CCMEventFound -or ((Get-Date) -gt $limit))

			#Report if the Do while exited without CCMSetup starting
			if ($CCMEventFound -eq $False) {
				$Message = "$($CCMSetupWait) minutes has passed and ccmsetup did not report a success exit code 0 in the event logs"
				Write-Log -Message $Message -Source ${CmdletName} -Severity 3
				#Flag the result of this check as failed:
				$WMICheckResult = $False
			} elseif ($CCMEventFound -eq $true) {
				#Flag the result of this check as successful:
				$WMICheckResult = $true
			}

			return $WMICheckResult
		}

		Function Restore-CCMService {

			[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

			####Do heal Ccm Service
			$Message = 'Starting ccmexec Service...'
			Write-Log -Message $Message -Source ${CmdletName}
			#Start-Service ccmexec -Verbose
			Start-ServiceAndDependencies -Name CCMExec

			$Message = 'Wait for 3 minutes...'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Sleep -Seconds 180 -Verbose

			$Message = 'Triggering Machine Policy Refresh...'
			Write-Log -Message $Message -Source ${CmdletName}
			Invoke-SCCMTask -ScheduleID RequestMachinePolicy
			#([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000021}')

			if ((Get-Service ccmexec).status -eq 'Running') {
				$CcmExecCheckResult = $true
			} else {
				$CcmExecCheckResult = $False
			}

			Return $CcmExecCheckResult
		}

		Function Update-CCMMachinePolicy {
			[CmdletBinding()]
			Param (
				$LoopingWindowInMinutes = 60
			)

			[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

			####Do heal last policy refresh
			$Message = 'Killing ccmexec Service...'
			Write-Log -Message $Message -Source ${CmdletName}
			taskkill /IM 'CcmExec.exe' /F | Out-Null

			$Message = 'Wait for 30 seconds'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Sleep -Seconds 30 -Verbose

			$Message = 'Starting ccmexec Service...'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Service ccmexec -Verbose

			$Message = 'Wait for 3 minutes...'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Sleep -Seconds 180 -Verbose

			$Message = "Check last policy request date over the next $($LoopingWindowInMinutes) minutes..."
			Write-Log -Message $Message -Source ${CmdletName}
			$limit = (Get-Date).AddMinutes($LoopingWindowInMinutes)

			Do {
				$Message = 'Triggering Machine Policy Refresh...'
				Write-Log -Message $Message -Source ${CmdletName}
				Invoke-SCCMTask -ScheduleID RequestMachinePolicy
				#([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000021}')

				$Message = 'Wait for 5 minutes...'
				Write-Log -Message $Message -Source ${CmdletName}
				Start-Sleep -Seconds 300

				$LastMachinePolicyRequest = (Get-CimInstance -Query "SELECT LastTriggerTime FROM CCM_Scheduler_History WHERE ScheduleID='{00000000-0000-0000-0000-000000000021}' and UserSID='Machine'" -Namespace 'Root\CCM\Scheduler').LastTriggerTime
				#[datetime]$LastMachinePolicyRequestDate = ([WMI] '').ConvertToDateTime($LastMachinePolicyRequest)
				[datetime]$LastMachinePolicyRequestDate = $LastMachinePolicyRequest

				$Message = "Last policy request is currently showing: $($LastMachinePolicyRequestDate.ToString('dd.MM.yyyy HH:mm:ss'))"
				Write-Log -Message $Message -Source ${CmdletName}

			} until ((($LastMachinePolicyRequest.Length -gt 0) -and ($LastMachinePolicyRequestDate -gt (Get-Date).AddHours(-24))) -or ((Get-Date) -gt $limit))

			$Message = 'Triggering Data Discovery Collection Cycle...'
			Write-Log -Message $Message -Source ${CmdletName}
			Invoke-SCCMTask -ScheduleID HeartbeatDiscovery
			#([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000003}')

			$Message = 'Wait for 1 minutes...'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Sleep -Seconds 60 -Verbose

			$Message = 'Triggering Hardware Inventory Cycle...'
			Write-Log -Message $Message -Source ${CmdletName}
			Invoke-SCCMTask -ScheduleID HardwareInventory
			#([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000001}')

			$Message = 'Wait for 1 minutes...'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Sleep -Seconds 60 -Verbose

			$Message = 'Triggering Software Update Scan Cycle...'
			Write-Log -Message $Message -Source ${CmdletName}
			Invoke-SCCMTask -ScheduleID SoftwareUpdatesScan
			#([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000113}')

			$Message = 'Wait for 1 minutes...'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Sleep -Seconds 60 -Verbose

			if (($LastMachinePolicyRequest.Length -gt 0) -and ($LastMachinePolicyRequestDate -gt (Get-Date).AddHours(-24))) {
				#Machine is requesting policy within 24 hours
				$Message = "Last policy request is now showing: $($LastMachinePolicyRequestDate)"
				Write-Log -Message $Message -Source ${CmdletName}
				$LastMachinePolicyRequestResult = $true
			} else {
				#Machine is not requesting refresh
				$Message = "Last policy request is still showing older than 24 hours: $($LastMachinePolicyRequestDate)"
				Write-Log -Message $Message -Source ${CmdletName}
				$LastMachinePolicyRequestResult = $False
			}

			Return $LastMachinePolicyRequestResult
		}

		Function Update-CCMManagementPoint {

			[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

			$Message = 'Killing ccmexec Service...'
			Write-Log -Message $Message -Source ${CmdletName}
			taskkill /IM 'CcmExec.exe' /F | Out-Null

			$Message = 'Wait for 30 seconds'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Sleep -Seconds 30 -Verbose

			$Message = 'Starting ccmexec Service...'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Service ccmexec -Verbose

			$Message = 'Wait for 5 minutes'
			Write-Log -Message $Message -Source ${CmdletName}
			Start-Sleep -Seconds 300 -Verbose

			#Check Management Point entry
			$CurrentManagementPoint = (Get-CimInstance -Query 'SELECT * FROM SMS_Authority' -Namespace 'root\ccm').CurrentManagementPoint

			if ($CurrentManagementPoint.Length -gt 0) {
				#  CurrentManagementPoint is not null
				$Message = "Current Management Point is:  $($CurrentManagementPoint)"
				Write-Log -Message $Message -Source ${CmdletName}
				$CurrentManagementPointResult = $true

			} else {
				#Machine has empty string for Management Point Value
				$CurrentManagementPointResult = $False
				$Message = 'Machine has empty string for Management Point Value after remediation'
				Write-Log -Message $Message -Source ${CmdletName}
			}

			Return $CurrentManagementPointResult
		}

	}

	process {

		$Process = @{
			Name = 'ccmsetup'
		}

		$Status = Get-RunningProcesses -ProcessObjects $Process

		#$status = Get-Process ccmsetup -ErrorAction SilentlyContinue

		if ($status) {
			Write-Log -Message 'CCMSetup.exe is running, skipping detection/remediations for this interval' -Severity 0 -Source ${CmdletName}

			exit 0
		}

		#Check if CcmExec.exe exists, otherwise, exit gracefully
		if (Test-Path -Path $env:windir\CCM\CcmExec.exe) {

			Try {

				#Check if we can connect to WMI CCM namespace on the machine
				Get-CimInstance -Namespace 'root\ccm' -Class SMS_Client | Out-Null
				$AggregateMessages = 'Root\CCM is accessible'

				Try {
					#Check last policy Request
					$LastMachinePolicyRequest = (Get-CimInstance -Query "SELECT LastTriggerTime FROM CCM_Scheduler_History WHERE ScheduleID='{00000000-0000-0000-0000-000000000021}' and UserSID='Machine'" -Namespace 'Root\CCM\Scheduler').LastTriggerTime
					#[datetime]$LastMachinePolicyRequestDate = ([WMI] '').ConvertToDateTime($LastMachinePolicyRequest)
					[datetime]$LastMachinePolicyRequestDate = $LastMachinePolicyRequest

					$Message = "Last policy request date/time: $($LastMachinePolicyRequestDate.ToString('dd.MM.yyyy HH:mm:ss'))"
					Write-Log -Message $Message -Source ${CmdletName}

					if (($LastMachinePolicyRequest.Length -gt 0) -and ($LastMachinePolicyRequestDate -gt (Get-Date).AddHours(-$LastMachinePolicyHoursRang))) {
						#Machine is requesting policy within specified hours in variable $LastMachinePolicyHoursRang
						$AggregateMessages += " | Last policy request was within $($LastMachinePolicyHoursRang) hours"

						$Message = "Last policy request was within $($LastMachinePolicyHoursRang) hours from now"
						Write-Log -Message $Message -Source ${CmdletName} -Severity 0

					} else {
						#Machine is not requesting refresh
						$PolicyRequestErrorMsg = "Machine has not requested policies within the last $($LastMachinePolicyHoursRang) hours"
						$LastMachinePolicyRequestStatus = $true

						$Message = "Machine has not requested policies within the last $($LastMachinePolicyHoursRang) hours"
						Write-Log -Message $Message -Source ${CmdletName} -Severity 2
					}

				} Catch {
					#Failed to query last policy request
					$PolicyRequestErrorMsg = "Failed to query last policy request date: $($_.Exception.Message)"
					$LastMachinePolicyRequestStatus = $true

					Write-Log -Message $PolicyRequestErrorMsg -Severity 3 -Source ${CmdletName}
				}

				Try {
					#Check Management Point entry
					$CurrentManagementPoint = (Get-CimInstance -Query 'SELECT * FROM SMS_Authority' -Namespace 'root\ccm').CurrentManagementPoint

					if ($CurrentManagementPoint.Length -gt 0) {
						#  CurrentManagementPoint is not null
						$AggregateMessages += " | Current Management Point is:  $($CurrentManagementPoint) "

						$Message = "Current Management Point is:  $($CurrentManagementPoint)"
						Write-Log -Message $Message -Source ${CmdletName} -Severity 0

					} else {
						#Machine has empty string for Management Point Value
						$ManagementPointErrorMsg = 'Machine has empty string for Management Point Value'
						$CurrentManagementPointStatus = $true

						Write-Log -Message $ManagementPointErrorMsg -Severity 3 -Source ${CmdletName}
					}

				} Catch {
					#Failed to query Management Point value
					$ManagementPointErrorMsg = "Failed to query Management Point value: $($_.Exception.Message)"
					$CurrentManagementPointStatus = $true

					Write-Log -Message $ManagementPointErrorMsg -Severity 3 -Source ${CmdletName}
				}

			} catch {
				$WMICheckErrorMsg = "WMI CCM Namespace check failed: $($_.Exception.Message)"
				$WMICheckStatus = $true

				Write-Log -Message $WMICheckErrorMsg -Severity 3 -Source ${CmdletName}
			}

			#Check SMS service status
			Try {

				#Check if CCMEXEC service is running
				$CcmExecStatus = (Get-Service 'CcmExec').Status

				If ($CcmExecStatus -eq 'Running') {
					$AggregateMessages += ' | CcmExec service is running '

					$Message = 'CcmExec service is running'
					Write-Log -Message $Message -Source ${CmdletName} -Severity 0

				} else {
					$CcmExecErrorMsg = 'CCMExec Service is not running'
					$CcmExecCheckStatus = $true

					Write-Log -Message $CcmExecErrorMsg -Severity 3 -Source ${CmdletName}
				}

			} catch {
				$CcmExecErrorMsg = "Failed to query CcmExec: $($_.Exception.Message)"
				$CcmExecCheckStatus = $true

				Write-Log -Message $CcmExecErrorMsg -Severity 3 -Source ${CmdletName}
			}

			#Check overall status and determine exit codes
			If ($WMICheckStatus -or $CcmExecCheckStatus -or $LastMachinePolicyRequestStatus -or $CurrentManagementPointStatus) {

				If ($WMICheckStatus -eq $true) {
					$WMICheckResult = Reset-WMI

					Set-RegistryKey -Key $CHRegistryPath -Name 'WMICheckStatus' -Value '1' -Type DWord

					$Message = 'Created reg value WMICheckStatus = 1'
					Write-Log -Message $Message -Source ${CmdletName} -DebugMessage
				}

				If ($CcmExecCheckStatus -eq $true) {
					$CcmExecCheckResult = Restore-CCMService

					Set-RegistryKey -Key $CHRegistryPath -Name 'CcmExecCheckStatus' -Value '1' -Type DWord

					$Message = 'Created reg value CcmExecCheckStatus = 1'
					Write-Log -Message $Message -Source ${CmdletName} -DebugMessage
				}

				If ($LastMachinePolicyRequestStatus -eq $true) {
					$LastMachinePolicyRequestResult = Update-CCMMachinePolicy

					Set-RegistryKey -Key $CHRegistryPath -Name 'LastMachinePolicyRequestStatus' -Value '1' -Type DWord

					$Message = 'Created reg value LastMachinePolicyRequestStatus = 1'
					Write-Log -Message $Message -Source ${CmdletName} -DebugMessage
				}

				If ($CurrentManagementPointStatus -eq $true) {
					$CurrentManagementPointResult = Update-CCMManagementPoint

					Set-RegistryKey -Key $CHRegistryPath -Name 'CurrentManagementPointStatus' -Value '1' -Type DWord

					$Message = 'Created reg value CurrentManagementPointStatus = 1'
					Write-Log -Message $Message -Source ${CmdletName} -DebugMessage
				}

				#$Message = "Triggering remediations: $WMICheckErrorMsg | $PolicyRequestErrorMsg | $CcmExecErrorMsg | $ManagementPointErrorMsg"
				#Write-Log -Message $Message -Source ${CmdletName}

				#exit 1

				#WMI Check Report
				if ($WMICheckResult -eq $true) {
					$RemediationAggregateMessages += ' | Remediations logic has run for repairing WMI and passed successfully'
				} elseif ($WMICheckResult -eq $False) {
					$RemediationAggregateMessages += ' | Remediations logic has run for repairing WMI with errors - see log file'
				}

				#CCM Service Report
				if ($CcmExecCheckResult -eq $true) {
					$RemediationAggregateMessages += ' | Remediations has run for CCM Service being stopped and the service was started successfully'
				} elseif ($CcmExecCheckResult -eq $False) {
					$RemediationAggregateMessages += ' | Remediations has run for CCM Service being stopped but the service could not be restarted'
				}

				#Last Machine Policy Refresh Report
				if ($LastMachinePolicyRequestResult -eq $true) {
					$RemediationAggregateMessages += " | Remediations have run for last policy refresh being older than 24 hours. Result: Success. Last Machine Policy Download Date: $($LastMachinePolicyRequestDate) "
				} elseif ($LastMachinePolicyRequestResult -eq $False) {
					$RemediationAggregateMessages += " | Remediations have run for last policy refresh being older than 24 hours. Result: Failed. Last Machine Policy Download Date: $($LastMachinePolicyRequestDate) - see log file for details "
				}

				# Management Point Report
				if ($CurrentManagementPointResult -eq $true) {
					$RemediationAggregateMessages += " | Remediations have run for Management Point entry being empty. Result: Success. Current Management Point is:  $($CurrentManagementPoint) "
				} elseif ($CurrentManagementPointResult -eq $False) {
					$RemediationAggregateMessages += " | Remediations have run for Management Point entry being empty. Result: Failed. Current Management Point is empty:  $($CurrentManagementPoint) "
				}

				#If any of the checks is failed, exit with code 1 and return the messages from all checks
				#otherwise, exit with code 0 and return the messages from all checks
				Write-Log -Message $RemediationAggregateMessages -Source ${CmdletName}

				If (($WMICheckResult -eq $true) -or ($CcmExecCheckResult -eq $true) -or ($LastMachinePolicyRequestResult -eq $true) -or ($CurrentManagementPointResult -eq $true)) {
					Write-Log -Message 'Remediation failed' -Severity 3 -Source ${CmdletName}

					exit 0
				} else {
					Write-Log -Message 'Remediation success' -Severity 0 -Source ${CmdletName}

					exit 1
				}

			} else {

				Write-Log -Message $AggregateMessages -Source ${CmdletName}

				exit 0
			}
		}
		#If CCmExec is not found on the system, exit without triggering remediations
		else {
			$Message = "Cannot find $env:windir\CCM\CcmExec.exe | No remediation is required"
			Write-Log -Message $Message -Source ${CmdletName} -Severity 2

			exit 0
		}

	}

	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}

function Get-CHConfig {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $ConfigFile
	)



	if ($Config) {

		# Build the ConfigMgr Client Install Property string
		$propertyString = ''

		foreach ($property in $Xml.Configuration.ClientInstallProperty) {
			$propertyString = $propertyString + $property
			$propertyString = $propertyString + ' '
		}

		$clientCacheSize = Get-XMLConfigClientCache
		#replace to account for multiple skipreqs and escapee the character
		$clientInstallProperties = $propertyString.Replace(';', '`;')
		$clientAutoUpgrade = (Get-XMLConfigClientAutoUpgrade).ToLower()
		$AdminShare = Get-XMLConfigRemediationAdminShare
		$ClientProvisioningMode = Get-XMLConfigRemediationClientProvisioningMode
		$ClientStateMessages = Get-XMLConfigRemediationClientStateMessages
		$ClientWUAHandler = Get-XMLConfigRemediationClientWUAHandler
		$LogShare = Get-XMLConfigLoggingShare
	}
}
#endregion Functions

#region    Main

Test-ExistingPath -Path $configLogDir

$LogArgs = @{
	Message   = ''
	LogFolder = $configLogDir
	Log       = ''
	LogId     = $($MyInvocation.MyCommand).Name
	Severity  = 1
	Component = [string]::Format('{0}:{1}', $LogID, $($MyInvocation.ScriptLineNumber))
}


Write-Verbose "Script version: $Version"
Write-Verbose "PowerShell version: $envPSVersionMajor"

$script:installPhase = 'Check GPO'
Update-GroupPolicy

$script:installPhase = 'HealthChecks'
Invoke-HealthChecks

$script:installPhase = 'Gathering Device Data'
$FreeDiskSpace = Get-FreeDiskSpace
$HWPlatform = Get-HardwarePlatform


#endregion Main

Start-Sleep -Seconds 1
