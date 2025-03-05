

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
	Unregister-ScheduledTask -InputObject $Task -Confirm:$false
}

# Remove Folders and Files
$MyPath = $env:WinDir
Remove-Item -Path $MyPath\CCM -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path $MyPath\ccmsetup -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path $MyPath\ccmcache -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path $MyPath\SMSCFG.ini -Force -ErrorAction SilentlyContinue
Remove-Item -Path $MyPath\SMS*.mif -Force -ErrorAction SilentlyContinue


if ((! (@(($ENV:PATH).Split(';')) -contains "$env:SystemDrive\WINDOWS\System32\Wbem")) -and (! (@(($ENV:PATH).Split(';')) -contains '%systemroot%\System32\Wbem'))) {
	$text = 'WMI Folder not in search path!.'
	Write-Warning $text
}

$MLBEndpointAgent = 'C:\Program Files\Malwarebytes Endpoint Agent\UserAgent\EACmd.exe'
Start-Process -FilePath $MLBEndpointAgent -ArgumentList '--stopmbamservice' -NoNewWindow -Wait

while ((Get-Service MBAMService).Status -ne 'Stopped') {
	Start-Sleep -Milliseconds 10
}

Set-Service Winmgmt -StartupType Disabled
Stop-Service -Name 'Winmgmt' -Force

$WMIPath = $ENV:SystemRoot + '\System32\wbem'
Set-Location -Path $WMIPath
$WbemRepoPath = Join-Path -Path $WMIPath -ChildPath 'Repository'
Remove-Item -Path $WbemRepoPath -Recurse -Force

# Register DLLs directly using full paths
Start-Process -FilePath 'regsvr32' -ArgumentList "/s $env:SystemRoot\system32\scecli.dll" -NoNewWindow -Wait
Start-Process -FilePath 'regsvr32' -ArgumentList "/s $env:SystemRoot\system32\userenv.dll" -NoNewWindow -Wait

# Register all DLLs in the current directory and subdirectories
Get-ChildItem -Recurse -Filter *.dll | ForEach-Object {
	Start-Process -FilePath 'regsvr32' -ArgumentList "/s $($_.FullName)" -NoNewWindow -Wait
}

# Register various services
Start-Process -FilePath 'scrcons.exe' -ArgumentList '/regserver' -NoNewWindow -Wait
Start-Process -FilePath 'unsecapp.exe' -ArgumentList '/regserver' -NoNewWindow -Wait
Start-Process -FilePath 'winmgmt.exe' -ArgumentList '/regserver' -NoNewWindow -Wait
Start-Process -FilePath 'wmiadap.exe' -ArgumentList '/regserver' -NoNewWindow -Wait
Start-Process -FilePath 'wmiapsrv.exe' -ArgumentList '/regserver' -NoNewWindow -Wait
Start-Process -FilePath 'wmiprvse.exe' -ArgumentList '/regserver' -NoNewWindow -Wait

# Compile MOF files
mofcomp cimwin32.mof | Out-Null
mofcomp cimwin32.mfl | Out-Null
mofcomp rsop.mof | Out-Null
mofcomp rsop.mfl | Out-Null
mofcomp 'C:\Program Files\Microsoft Policy Platform\ExtendedStatus.mof' | Out-Null

# Compile all MOF and MFL files in the current directory
Get-ChildItem -Filter *.mof | ForEach-Object {
	mofcomp $_.Name | Out-Null
}
Get-ChildItem -Filter *.mfl | ForEach-Object {
	mofcomp $_.Name | Out-Null
}

Start-Service winmgmt
Set-Service Winmgmt -StartupType Automatic

Set-Service wuauserv -StartupType Automatic
Start-Service wuauserv


$DnsSuffix = 'kostweingroup.intern'
$CMMP = "atklsccm.$($DnsSuffix)"
$CMSiteCode = 'KOW'
$FilePath = 'C:\Windows\ccmsetup\ccmsetup.exe'

$SetupArgs = @{
	FilePath     = $FilePath
	ArgumentList = "/mp:$($CMMP) /source:http://$($CMMP)/CCM_Client CCMHTTPPORT=80 RESETKEYINFORMATION=TRUE SMSSITECODE=$($CMSiteCode) SMSSLP=$($CMMP) FSP=$($CMMP) DNSSUFFIX=$($DnsSuffix) /forceinstall"
	PassThru     = $true
	Wait         = $true
}

Start-Process @SetupArgs
#Start-Process -FilePath 'c:\windows\temp\ccmsetup.exe' -PassThru -Wait -ArgumentList "/mp:$($CMMP) /source:http://$($CMMP)/CCM_Client CCMHTTPPORT=80 RESETKEYINFORMATION=TRUE SMSSITECODE=$($CMSiteCode) SMSSLP=$($CMMP) FSP=$($CMMP)"




$MissingUpdates = Get-CimInstance -Query 'SELECT * FROM CCM_UpdateStatus' -Namespace 'root\ccm\SoftwareUpdates\UpdatesStore' | Where-Object { $_.status -eq 'Missing' }
$CMComponents = Get-CimInstance -Query 'SELECT * FROM CCM_InstalledComponent' -Namespace 'ROOT\ccm'

