
# Documentation home: https://github.com/engrit-illinois/GpUpdate-Computer
function GpUpdate-Computer {

	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[string[]]$Queries,
		[string]$SearchBase = 'OU=Engineering,OU=Urbana,DC=ad,DC=uillinois,DC=edu',
		[int]$ThrottleLimit = 50,
		[switch]$Synchronous,
		[switch]$FullOutput,
		[switch]$NoColor,
		[PSCredential]$Credential
	)

	function log {
		param(
			[string]$Msg,
			[switch]$ExtraNewlineBefore
		)
		$ts = Get-Date -Format 'HH:mm:ss'
		$Msg = "[$ts] $Msg"
		if ($ExtraNewlineBefore) { $Msg = "`n$Msg" }
		Write-Host $Msg
	}

	function Get-ADComputerName {
		param (
			[string[]]$Queries,
			[string]$SearchBase
		)

		Get-ADComputerLike -Queries $Queries -SearchBase $SearchBase | Select-Object -ExpandProperty 'Name'
	}

	function Get-ADComputerLike {
		param(
			[string[]]$Queries,
			[string]$SearchBase
		)
		
		$allResults = @()
		foreach ($query in @($Queries)) {
			$results = Get-ADComputer -SearchBase $SearchBase -Filter "name -like `"$query`"" -Properties *
			$allResults += @($results)
		}
		$allResults
	}

	function Do-Stuff {
		$params = @{
			'Queries' = $Queries
		}
		if ($SearchBase) { $params.SearchBase = $SearchBase }
		$comps = Get-AdComputerName @params

		log 'Matching computers found:'
		$compsString = "`"" + ($comps -join "`",`"") + "`""
		log "    $compsString"

		# The following works on client computers with PS 5.1+
		$scriptBlock = {
			$comp = $_

			try {
				$FullOutput = $using:FullOutput
				$NoColor = $using:NoColor
				$Credential = $using:Credential
			} catch {
				# If any of these fail, it just means we're running synchronously, and we already have access to these variables.
				continue
			}

			function log {
				param(
					[string]$Msg,
					[string]$Comp,
					[switch]$ExtraNewlineBefore
				)

				if ($Comp) { $Msg = "[$Comp] $Msg" }

				$ts = Get-Date -Format 'HH:mm:ss'
				$Msg = "[$ts] $Msg"

				if ($ExtraNewlineBefore) { $Msg = "`n$Msg" }

				$params = @{
					Object = $Msg
				}

				if ($Msg -like "*``[color``:*``]*") {
					$regex = '^.*\[color\:([a-z]*)\].*$'
					$regexResult = $Msg -match $regex
					$color = $matches[1]
					$replace = "[color:$($color)]"
					$Msg = $Msg.Replace($replace, '')
					$params.Object = $Msg
					$params.ForegroundColor = $color
				}

				Write-Host @params
			}

			function Format-Results($results) {

				# Simplfy if requested
				$simplified = $results
				if (-not $FullOutput) {
					$simplified = $results | ForEach-Object {
						$line = $_
						$line = $line.Replace('Updating policy...', '')
						$line = $line.Replace('Computer Policy update has completed successfully.', 'Computer policy updated.')
						$line = $line.Replace('User Policy update has completed successfully.', 'User policy updated.')
						$line = $line.Replace('The following warnings were encountered during user policy processing:', '')
						$line = $line.Replace('The Group Policy Client Side Extension Folder Redirection was unable to apply one or more settings because the changes must be processed before system startup or user logon. The system will wait for Group Policy processing to finish completely before the next startup or logon for this user, and this may result in slow startup and boot performance.', 'Not all policies applied. Next processing after boot/login will be thorough.')
						$line = $line.Replace('For more detailed information, review the event log or run GPRESULT /H GPReport.html from the command line to access information about Group Policy results.', '')
						$line = $line.Replace('Certain user policies are enabled that can only run during logon.', 'Logoff requested and denied.')
						$line = $line.Replace('OK to log off? (Y/N)', '')
						$line
					}
				}

				# gpupdate returns an array of strings, with several blank lines
				$pruned = $simplified | Where-Object { $_ }

				# Add indentation
				$indented = $pruned | ForEach-Object { "    $_" }

				# Colorize certain lines for easier scanning
				$colorized = $indented
				if (-not $NoColor) {
					$colorized = $indented | ForEach-Object {
						$line = $_

						if (
							($line -like '*Computer Policy update has completed successfully*') -or
							($line -like '*Computer policy updated*') -or
							($line -like '*User Policy update has completed successfully*') -or
							($line -like '*User policy updated*')
						) {
							$line = "[color:green] $line"
						} elseif (
							($line -like '*The Group Policy Client Side Extension Folder Redirection was unable to apply one or more settings*') -or
							($line -like '*Not all policies applied*') -or
							($line -like '*Certain user policies are enabled that can only run during logon*') -or
							($line -like '*Logoff requested and denied*')
						) {
							$line = "[color:yellow] $line"
						} elseif (
							($line -like '*failed*') -or
							($line -like '*error*')
						) { $line = "[color:red] $line" }
						else {
							$line = $line
						}

						$line
					}
				}

				$colorized
			}

			log 'Processing...' -Comp $comp

			$scriptBlock = { Write-Output 'n' | gpupdate /force }
			$params = @{
				'ComputerName' = $comp
				'ScriptBlock'  = $scriptBlock
				'ErrorAction'  = 'Stop'
			}

			if ($Credential) { $params.Credential = $Credential }

			try {
				$results = Invoke-Command @params
			} catch {
				$results = $_.Exception.Message
			}

			log 'Results:' -Comp $comp
			$output = Format-Results $results
			$output | ForEach-Object { log $_ -Comp $comp }
			log 'Done processing.' -Comp $comp
		}

		if ($Synchronous) {
			$comps | ForEach-Object -Process $scriptBlock
		} else {
			$comps | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel $scriptBlock
		}
	}

	Do-Stuff

	log 'EOF'
}
