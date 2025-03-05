
$RegistryData = @{
	ClientProperties = @{
		Path = 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Configuration\Client Properties'
	}
}

$HealthDict = @(
	[PSCustomObject]@{
		ResultCode  = 818
		ResultType  = 202
		Description = 'Verify CcmEval task has run in recent cycles.'
		Remediation = { $null = Start-Process 'C:\WINDOWS\CCM\ccmeval.exe' -PassThru }
	}
	[PSCustomObject]@{
		ResultCode  = 401
		ResultType  = 202
		Description = 'Verify/Remediate client WMI provider.'
		Remediation = { Invoke-WMIRepair }
	}
	[PSCustomObject]@{
		ResultCode  = 52429101
		ResultType  = 201
		Description = 'WMI Repository Integrity Test.'
		Remediation = {  }
	}
	[PSCustomObject]@{
		ResultCode  = 0
		ResultType  = 0
		Description = ''
		Remediation = {  }
	}
	[PSCustomObject]@{
		ResultCode  = 0
		ResultType  = 0
		Description = ''
		Remediation = {  }
	}
)


Function Get-RegistryValue {
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

Function Set-RegistryValue {
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

function Get-CCMEval {
	[CmdletBinding()]
	param (
		[Parameter()]
		[Switch] $LastRun,
		[Parameter()]
		[Switch] $Run,
		[Parameter()]
		[Switch] $Report
	)

	$CCMEvalPath = Get-RegistryValue -Path $RegistryData.ClientProperties.Path -Name 'Local SMS Path'

	if (Test-Path -Path $CCMEvalPath) {

		if ($LastRun -or $Report) {
			$CCMEval = Join-Path -Path $CCMEvalPath -ChildPath 'CcmEvalReport.xml'

			if ($LastRun) {
				$Result = (Get-Item -Path $CCMEval).LastWriteTime
			} elseif ($Report) {
				[Xml]$Result = Get-Content -Path $CCMEval
			}

			return $Result
		}

		if ($Run) {
			$CCMEval = Join-Path -Path $CCMEvalPath -ChildPath 'ccmeval.exe'
			$Result = (Start-Process -FilePath $CCMEval -PassThru)

			Start-Sleep -Seconds 15
			return $Result.Id
		}

	}
}

function Get-CMHealth {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $ParameterName
	)

	$CCMHealth = $null
	$ClientHealth = Get-CCMEval -Report

	if ($ClientHealth) {

		$ClientHealthReport = $ClientHealth.ClientHealthReport
		$Summary = $ClientHealthReport.Summary
		$HealthChecks = $ClientHealthReport.HealthChecks.HealthCheck

		$HealthChecksPassed = $HealthChecks |
			Where-Object { $_.'#text' -eq 'Passed' } |
				Select-Object -Property Description, '#text' |
					Sort-Object -Property Description

		$HealthChecksFailed = $HealthChecks |
			Where-Object { $_.'#text' -eq 'Failed' } |
				Select-Object -Property Description, '#text', ResultCode, ResultType, ResultDetail, StepDetail |
					Sort-Object -Property Description

		$RemediationFailed = $HealthChecks |
			Where-Object { $_.'#text' -eq 'Remediation Failed' } |
				Select-Object -Property Description, '#text', ResultCode, ResultType, ResultDetail, StepDetail |
					Sort-Object -Property Description

		$CCMHealth = [PSCustomObject]@{
			EvaluationTime    = $Summary.EvaluationTime
			EvaluationResult  = $Summary.'#text'
			HealthChecks      = $HealthChecks
			Passed            = $HealthChecksPassed
			Failed            = $HealthChecksFailed
			FailedRemediation = $RemediationFailed
		}

	}

	return $CCMHealth

}

function Invoke-WMIRepair {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $ParameterName
	)

    $SysRoot = $env:SystemRoot
    $WbemPath = "$SysRoot\System32\wbem"
    Push-Location -Path $WbemPath

    $WbemRepoPath = Join-Path -Path $WbemPath -ChildPath 'Repository'

	$MLBEndpointAgent = 'C:\Program Files\Malwarebytes Endpoint Agent\UserAgent\EACmd.exe'
	Start-Process -FilePath $MLBEndpointAgent -ArgumentList '--stopmbamservice' -NoNewWindow -Wait

	while ((Get-Service MBAMService).Status -ne 'Stopped') {
		Start-Sleep -Milliseconds 10
	}

	#Get-Service -Name MBAMService | Stop-Service -Force -ErrorAction SilentlyContinue
	#Get-Service -Name CcmExec | Stop-Service -Force -ErrorAction SilentlyContinue
	#Get-Service -Name Winmgmt | Stop-Service -Force -ErrorAction SilentlyContinue

	Stop-Service -Name 'Winmgmt' -Force -ErrorAction SilentlyContinue

	#while ((Get-Service Winmgmt).Status -ne 'Stopped') {
	#	Start-Sleep -Milliseconds 10
	#}

	#Stop-Service -Name CcmExec -Force -ErrorAction SilentlyContinue
	#Stop-Service -Name 'Winmgmt' -Force -ErrorAction SilentlyContinue

    try {
        Remove-Item -Path $WbemRepoPath -Recurse -Force

        # Register DLLs directly using full paths
        Start-Process -FilePath "regsvr32" -ArgumentList "/s $env:SystemRoot\system32\scecli.dll" -NoNewWindow -Wait
        Start-Process -FilePath "regsvr32" -ArgumentList "/s $env:SystemRoot\system32\userenv.dll" -NoNewWindow -Wait

        # Register all DLLs in the current directory and subdirectories
        Get-ChildItem -Recurse -Filter *.dll | ForEach-Object {
            Start-Process -FilePath "regsvr32" -ArgumentList "/s $($_.FullName)" -NoNewWindow -Wait
        }

        # Register various services
        Start-Process -FilePath "scrcons.exe" -ArgumentList "/regserver" -NoNewWindow -Wait
        Start-Process -FilePath "unsecapp.exe" -ArgumentList "/regserver" -NoNewWindow -Wait
        Start-Process -FilePath "winmgmt.exe" -ArgumentList "/regserver" -NoNewWindow -Wait
        Start-Process -FilePath "wmiadap.exe" -ArgumentList "/regserver" -NoNewWindow -Wait
        Start-Process -FilePath "wmiapsrv.exe" -ArgumentList "/regserver" -NoNewWindow -Wait
        Start-Process -FilePath "wmiprvse.exe" -ArgumentList "/regserver" -NoNewWindow -Wait

        # Compile MOF files
        mofcomp cimwin32.mof | Out-Null
        mofcomp cimwin32.mfl | Out-Null
        mofcomp rsop.mof | Out-Null
        mofcomp rsop.mfl | Out-Null

        # Compile all MOF and MFL files in the current directory
        Get-ChildItem -Filter *.mof | ForEach-Object {
            mofcomp $_.Name | Out-Null
        }
        Get-ChildItem -Filter *.mfl | ForEach-Object {
            mofcomp $_.Name | Out-Null
        }
    }
    catch {
        Write-Error -Message "[$($_.InvocationInfo.ScriptLineNumber)][Error] $($_.Exception.Message)"
    }
	finally {
		Pop-Location
	}

}

$CCMHealthReport = Get-CMHealth

if ($CCMHealthReport.Failed) {

	foreach ($Fail in $CCMHealthReport.Failed) {
		$Remediation = $HealthDict | Where-Object { $_.ResultCode -eq $Fail.ResultCode -and $_.ResultType -eq $_.ResultType }
		Invoke-Command -ScriptBlock $Remediation.Remediation
	}

}

#$CCMHealthReport
#$EvalLastRun = Get-CCMEval -LastRun

Start-Sleep -Seconds 1
