

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

$Triggers



##################################################################################
$computer = $env:COMPUTERNAME
$namespace = 'ROOT\ccm\ClientSDK'
$classname = 'CCM_SoftwareUpdate'

Write-Output '====================================='
Write-Output "COMPUTER : $computer "
Write-Output "CLASS    : $classname "
Write-Output '====================================='

Get-CimInstance -ClassName $classname -ComputerName $computer -Namespace $namespace |
	Select-Object * -ExcludeProperty PSComputerName, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container |
		Format-List -Property [a-z]*
