

# Define the function to check and remediate SCCM communication
function Test-And-Fix-SCCMCommunication {

	$CimArgs = @{
			ClassName = 'SMS_Client'
			Namespace = 'root\ccm'
			ErrorAction = 'Stop'
		}

	try {
		# Check if SCCM Client is installed
		if (Get-CimInstance @CimArgs) {
			Write-Output 'SCCM Client is installed.'
		}

		# Check communication with SCCM management point
		$CimArgs.Namespace = 'root\ccm\StatusAgent'
		$CimArgs.ClassName = 'SMS_ClientStatus'
		$MPStatus = (Get-CimInstance @CimArgs).MPCommunicationStatus

		if ($MPStatus -eq 1) {
			Write-Output 'SCCM Client is communicating with the Management Point successfully.'
		} else {
			Write-Output 'SCCM Client is not communicating with the Management Point. Attempting to remediate...'

			# Attempt to restart SCCM Client service
			Restart-Service -Name 'CcmExec' -Force
			Start-Sleep -Seconds 10  # Wait for service to restart
			$MPStatus = (Get-CimInstance @CimArgs).MPCommunicationStatus

			if ($MPStatus -eq 1) {
				Write-Output 'Remediation successful. SCCM Client communication restored.'
			} else {
				Write-Output 'Remediation failed. Manual intervention required.'
			}

		}
	} catch {
		Write-Output "Error: $($_.Exception.Message). Check if SCCM Client is correctly installed and running."
	}
}



# Define the function to check and remediate SCCM communication and inventories
function Test-And-Update-SCCMInventories {
	param (
		[int]$ThresholdDays = 7  # Default threshold set to 7 days
	)

	try {
		if (Get-CimInstance -Namespace root\ccm -ClassName SMS_Client -ErrorAction Stop) {
			Write-Output 'SCCM Client is installed.'
		}

		# Retrieve last activity dates
		$InvArgs = @{
			ClassName = 'inventoryagent'
			Namespace = 'root\ccm\invagt'
			ErrorAction = 'Stop'
		}

		$Inventory = Get-CimInstance @InvArgs
		$Heartbeat = $Inventory.LastHeartbeat
		$HardwareInventory = $Inventory.LastHardwareInventory
		$SoftwareInventory = $Inventory.LastSoftwareInventory

		# Convert to datetime and check against threshold
		$today = Get-Date
		$activities = @{
			'Heartbeat'          = $Heartbeat;
			'Hardware Inventory' = $HardwareInventory;
			'Software Inventory' = $SoftwareInventory
		}

		foreach ($activity in $activities.GetEnumerator()) {
			$lastUpdate = [DateTime]$activity.Value

			if (($today - $lastUpdate).Days -gt $ThresholdDays) {
				Write-Output "$($activity.Key) is older than $ThresholdDays days. Triggering update..."
				# Specific SCCM method to trigger update (Placeholder: Replace with actual method if applicable)
				# Example: Trigger-SCCMAction -Action $activity.Key
				Start-Sleep -Seconds 10  # Wait for action to complete
				# Recheck and verify if update was successful
				$updated = [DateTime]$Inventory.$($activity.Key)

				if (($today - $updated).Days -le $ThresholdDays) {
					Write-Output "$($activity.Key) update successful."
				} else {
					Write-Output "$($activity.Key) update failed."
				}

			} else {
				Write-Output "$($activity.Key) is up to date."
			}

		}

	} catch {
		Write-Output "Error: $_.Exception.Message. Check if SCCM Client is correctly installed and running."
	}
}

# Define the logging function
function Log-Action($message) {

	$logFile = 'C:\SCCMLogs\SCCM_Inventory_Check.log'

	if (-not (Test-Path -Path $logFile)) {
		New-Item -Path $logFile -ItemType File -Force | Out-Null
	}

	Add-Content -Path $logFile -Value ("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $message")

}

# Call the function to perform the check and log results
$result = Test-And-Update-SCCMInventories
Log-Action $result

