
$Script:ScheduleIds = @{
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

$Script:Services = @(
	'BITS', # Background Intelligent Transfer Service
	'gpsvc', # Group Policy
	'Winmgmt', # WMI
	'wuauserv', # Windows Update Agent
	'Schedule', # Task Scheduler
	'CcmExec', # CCM Client
	'CmRcService'  # CCM Remote Connection
)

$Script:DLLComponents = @(
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

$Script:CCMSetupReturnCodes = @(
	
)
