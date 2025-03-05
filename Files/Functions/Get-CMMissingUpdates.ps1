
function Get-CMMissingUpdates {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $ComputerName
	)

	$CimArgs = @{
		Namespace = 'root\ccm\SoftwareUpdates\UpdatesStore'
		Query     = 'SELECT * FROM CCM_UpdateStatus'
	}

	if ($ComputerName) {
		$CimArgs.Add('ComputerName', $ComputerName)
	}

	$MissingUpdates = Get-CimInstance @CimArgs | Where-Object { $_.status -eq 'Missing' }

	return $MissingUpdates
}

