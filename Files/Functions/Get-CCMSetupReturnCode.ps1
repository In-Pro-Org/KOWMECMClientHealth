
# Function to return CCM log entries to PS objects
function Convert-CCMLogToObjectArray {
	[OutputType([System.Collections.ArrayList])]
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $LogPath,
		$LineCount = 500
	)

	# Custom class to define a log entry
	class LogEntry {
		[string]$LogText
		[datetime]$DateTime
		[string]$component
		[string]$context
		[int]$type
		[int]$thread
		[string]$file
	}

	# Function to extract the content between two strings in a string
	function Get-ExtractedString {
		[CmdletBinding()]
		param (
			[Parameter()]
			$LogLine,
			$SearchStringStart,
			$SearchStringEnd
		)

		$Length = $SearchStringStart.Length
		$StartIndex = $LogLine.IndexOf($SearchStringStart, 0) + $Length
		$EndIndex = $LogLine.IndexOf($SearchStringEnd, $StartIndex)

		return $LogLine.Substring($StartIndex, ($EndIndex - $StartIndex))
	}

	If (Test-Path $LogPath) {

		$LogContent = (Get-Content $LogPath -Raw) -split '<!'
		$LogEntries = [System.Collections.ArrayList]::new()

		foreach ($LogLine in ($LogContent | Select-Object -Last $LineCount)) {

			If ($LogLine.Length -gt 0) {
				$LogEntry = [LogEntry]::new()

				$LogEntry.LogText = Get-ExtractedString -LogLine $LogLine -SearchStringStart '[LOG[' -SearchStringEnd ']LOG'
				$time = Get-ExtractedString -LogLine $LogLine -SearchStringStart '<time="' -SearchStringEnd '"'
				$date = Get-ExtractedString -LogLine $LogLine -SearchStringStart 'date="' -SearchStringEnd '"'

				$DateTimeString = $date + ' ' + $time.Split('.')[0]
				$LogEntry.DateTime = [datetime]::ParseExact($DateTimeString, 'MM-dd-yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)

				$LogEntry.component = Get-ExtractedString -LogLine $LogLine -SearchStringStart 'component="' -SearchStringEnd '"'
				$LogEntry.context = Get-ExtractedString -LogLine $LogLine -SearchStringStart 'context="' -SearchStringEnd '"'
				$LogEntry.type = Get-ExtractedString -LogLine $LogLine -SearchStringStart 'type="' -SearchStringEnd '"'
				$LogEntry.thread = Get-ExtractedString -LogLine $LogLine -SearchStringStart 'thread="' -SearchStringEnd '"'
				$LogEntry.file = Get-ExtractedString -LogLine $LogLine -SearchStringStart 'file="' -SearchStringEnd '"'

				[void]$LogEntries.Add($LogEntry)
			}
		}

		return $LogEntries
	}
}

function Get-CCMLogReturnCode {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $ComputerName = $env:COMPUTERNAME,
		[String] $LogPath = "$env:WinDir\ccmsetup\Logs",
		[String] $LogName = 'ccmsetup.log'
	)

	$LogFilePath = Join-Path -Path $LogPath -ChildPath $LogName

	if (Test-Path -Path $LogFilePath) {

		$ReturnCodeEntry = Convert-CCMLogToObjectArray -LogPath $LogFilePath -LineCount 5 |
			Where-Object { $_.LogText -match 'CcmSetup is exiting with return code' -or $_.Logtext -match 'CcmSetup failed with error code' }


		If ($ReturnCodeEntry) {
			# Create the returnCode object
			#$AADDeviceID = Get-AADDeviceID
			$ReturnCodeObject = [PSCustomObject]@{
				ReturnCode   = $ReturnCodeEntry.LogText.Split()[-1]
				Date         = $ReturnCodeEntry.DateTime
				Age_Days     = ([DateTime]::Now - $ReturnCodeEntry.DateTime).Days
				#AADDeviceID  = $AADDeviceID
				ComputerName = $ComputerName
			}

			#$ReturnCodeJson = ConvertTo-Json $ReturnCodeObject -Compress

			# Post the json to LA workspace
			#$Post1 = Post-LogAnalyticsData -customerId $WorkspaceID -sharedKey $PrimaryKey -body ([System.Text.Encoding]::UTF8.GetBytes($ReturnCodeJson)) -logType 'CM_CCMSetupReturnCodes'
			#$StatusCodes = "$($Post1.StatusCode)"

			# If return code is not success or reboot, send recent warning and error log entries
			If ($ReturnCodeObject.ReturnCode -notin (0, 7)) {
				# Create the log entries object
				$Log = Convert-CCMLogToObjectArray -LogPath $LogFilePath
				$WarningErrorEntries = $Log | Where-Object { $_.type -notin @(0, 1) }
				$LineNumber = 0
				$DateTime = [DateTime]::Now #Get-Date ([DateTime]::UtcNow) -Format 's' # DateTime is added as sometimes not all entries are ingested at the same time, so TimeGenerated in LA can be different

				foreach ($WarningErrorEntry in $WarningErrorEntries) {
					$LineNumber ++
					#$WarningErrorEntry | Add-Member -MemberType NoteProperty -Name AADDeviceID -Value $AADDeviceID
					$WarningErrorEntry | Add-Member -MemberType NoteProperty -Name ComputerName -Value $ComputerName
					$WarningErrorEntry | Add-Member -MemberType NoteProperty -Name LineNumber -Value $LineNumber
					$WarningErrorEntry | Add-Member -MemberType NoteProperty -Name DatePosted -Value $DateTime
				}

				#$LogJson = ConvertTo-Json $WarningErrorEntries -Compress

				# Post the json to LA workspace
				#$Post2 = Post-LogAnalyticsData -customerId $WorkspaceID -sharedKey $PrimaryKey -body ([System.Text.Encoding]::UTF8.GetBytes($LogJson)) -logType 'CM_CCMSetupErrorLog'
				#$StatusCodes = $StatusCodes + "  |  $($Post2.StatusCode)"

				return $WarningErrorEntries

			} else {
				return $ReturnCodeObject
			}

			# Output status codes
			#Write-Output $StatusCodes


		} else {
			# Create the returnCode object
			#$AADDeviceID = Get-AADDeviceID
			$ReturnCodeObject = [PSCustomObject]@{
				ReturnCode   = $null
				Date         = [DateTime]::Now
				Age_Days     = 0
				#AADDeviceID  = $AADDeviceID
				ComputerName = $ComputerName
			}

			#$ReturnCodeJson = ConvertTo-Json $ReturnCodeObject -Compress

			# Post the json to LA workspace
			#$Post = Post-LogAnalyticsData -customerId $WorkspaceID -sharedKey $PrimaryKey -body ([System.Text.Encoding]::UTF8.GetBytes($ReturnCodeJson)) -logType 'CM_CCMSetupReturnCodes'

			# Output status code
			#Write-Output $Post.StatusCode
			return $ReturnCodeObject
		}
	}

}

function Wait-CCMSetup {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String] $ComputerName
	)

	$ScriptBlock = {

		$Running = $true
		do {
			Start-Sleep -Seconds 5

			if (Get-Process 'ccmsetup' -ErrorAction SilentlyContinue) {
				#Write-Verbose 'ConfigMgr Client installation still running'
				$Running = $true
			} else {
				$Running = $false
			}

		} while ($Running -eq $true)
		
	}

	Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock

}


$ComputerName = 'LP1183'
$LogPath = "\\$($ComputerName)\c$\Windows\ccmsetup\Logs"

$Result = Get-CCMLogReturnCode -ComputerName $ComputerName -LogPath $LogPath
$Result
