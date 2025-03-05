
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

if (-not(Get-Variable -Name 'ScheduleIds' -ErrorAction SilentlyContinue)) {
	. "$ScriptRoot\CMStaticValues.ps1"
}

function Get-CMLastTriggerTimes {
	[CmdletBinding()]
	param (

	)

	begin {
		[String]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header

		$SortedScheduleIds = $Script:ScheduleIds.GetEnumerator() | Sort-Object Value
		$Triggers = [System.Collections.Specialized.OrderedDictionary]::new()
	}
	process {

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
	end {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}

}

