
if (-not(Get-Module AxSQLServerCe -ListAvailable -ErrorAction SilentlyContinue)) {
	Install-Module AxSQLServerCe
}

Import-Module AxSQLServerCe

$Computer = 'LP946'
$SDFPath = "\\$Computer\C$\Windows\CCM\CCMStore.sdf"

Connect-SdfFile -Path $SDFPath
$DataCi = Invoke-SdfCmd -TQuery 'SELECT * FROM ConfigurationItems'
$DataCiState = Invoke-SdfCmd -TQuery 'SELECT * FROM ConfigurationItemState'


<#
$ConnString = "Data Source=$SDFPath"
$Connection = [System.Data.SqlClient.SqlConnection]::new($ConnString)

$CMDCi = [System.Data.SqlClient.SqlCommand]::new()
$CMDCi.CommandType = [System.Data.CommandType]'Text'
$CMDCi.CommandText = 'SELECT * FROM ConfigurationItems'
$CMDCi.Connection = $Connection

$CMDCiState = [System.Data.SqlClient.SqlCommand]::new()
$CMDCiState.CommandType = [System.Data.CommandType]'Text'
$CMDCiState.CommandText = 'SELECT * FROM ConfigurationItemState'
$CMDCiState.Connection = $Connection

$DataCI = [System.Data.DataTable]::new()
$DataCIState = [System.Data.DataTable]::new()

$Connection.Open()
$DataCI.Load($CMDCi.ExecuteReader())
$DataCIState.Load($CMDCiState.ExecuteReader())
$Connection.Close()
#>

$RelevantProperties = @(
	'DisplayName',
	'Revision',
	'LatestRevision',
	'Applicability',
	'State',
	'DesiredState',
	'EvaluationState',
	'EnforcementState',
	'DCMDetectionState',
	'PersistOnWriteFilterDevices',
	'NotifyUser',
	'UserUIExperience',
	'ContentSize',
	'SuppressionState'
)

$Data = $DataCI | ForEach-Object {
	$CIState = $_

	$Model = ($_.ModelName).Replace('/RequiredApplication_', '/Application_')
	$App = $DataCiState | Where-Object { $_.ModelName -eq $Model }

	$AddData = [PSCustomObject]@{}

	if ($App) {
		# Get values
		$RelevantProperties | ForEach-Object {
			$Prop = $_
			$NewProp = "App-$Prop"
			# These could be either strings, or arrays, depending on the number of matching apps
			# If array, then combine values into a single string
			$Value = $App.$Prop
			$joinedValue = @($value) -join ','

			$AddData | Add-Member -NotePropertyName $NewProp -NotePropertyValue $JoinedValue
		}
	} else {
		# Use default "Not found" data
		$RelevantProperties | ForEach-Object {
			$Prop = $_
			$NewProp = "App-$Prop"
			$Value = 'Not found'

			$AddData | Add-Member -NotePropertyName $NewProp -NotePropertyValue $Value
		}
	}

	$RelevantProperties | ForEach-Object {
		$Prop = $_
		$NewProp = "App-$Prop"
		$Value = $AddData.$NewProp

		$CIState | Add-Member -NotePropertyName $NewProp -NotePropertyValue $Value -Force
	}

	$CIState
}

$RelevantPropsNew = $RelevantProperties | ForEach-Object {
	$prop = $_
	"App-$prop"
}

$Order = @('CiId', 'ModelName', 'Revision', 'Type') + @($relevantPropsNew)
$Data = $Data | Select-Object $Order | Sort-Object ModelName, Revision

# Don't really care about the Windows version requirement things
$Data = $Data | Where-Object { $_.ModelName -notlike 'Windows/*' }

$Data | Select-Object $Order | Out-GridView


$CIMArgs = @{
	ComputerName = $Computer
	Namespace    = 'root\ccm\Policy\Machine'
	Query        = 'Select * FROM CCM_ApplicationCIAssignment'
}

$Assignments = Get-CimInstance @CIMArgs

