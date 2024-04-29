
function Get-CMHealth {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String] $ComputerName
    )

    $RegistryPath = "HKLM:\SOFTWARE\Microsoft\SMS\Client\Configuration\Client Properties"
    $RegistryKey = "Local SMS Path"

    $ScriptBlock = {

        $SMSPath = (Get-ItemProperty($Using:RegistryPath)).$($Using:RegistryKey)
        [xml]$ccmeval = Get-Content -Path (Join-Path -Path $SMSPath -ChildPath "CcmEvalReport.xml")

        return $ccmeval
        
    }
    
    $ClientHealth = Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock
    
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

    return $CCMHealth

}

<#
Net Stop winmgmt
C:
CD %SystemRoot%\System32\wbem
RD /S /Q repository
regsvr32 /s %SystemRoot%\system32\scecli.dll
regsvr32 /s %SystemRoot%\system32\userenv.dll
for /f %%s in (‘dir /b /s *.dll’) do regsvr32 /s %%s
scrcons.exe /regserver
unsecapp.exe /regserver
winmgmt.exe /regserver
wmiadap.exe /regserver
wmiapsrv.exe /regserver
wmiprvse.exe /regserver
mofcomp cimwin32.mof
mofcomp cimwin32.mfl
mofcomp rsop.mof
mofcomp rsop.mfl
for /f %%s in (‘dir /b *.mof’) do mofcomp %%s
for /f %%s in (‘dir /b *.mfl’) do mofcomp %%s
#>

$RepairWMI = {
    Stop-Service -Name 'Winmgmt' -Force
    
    $SysRoot = $env:SystemRoot
    $WbemPath = "$SysRoot\System32\wbem"
    Set-Location -Path $WbemPath

    $WbemRepoPath = Join-Path -Path $WbemPath -ChildPath 'Repository'

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
        mofcomp cimwin32.mof
        mofcomp cimwin32.mfl
        mofcomp rsop.mof
        mofcomp rsop.mfl

        # Compile all MOF and MFL files in the current directory
        Get-ChildItem -Filter *.mof | ForEach-Object {
            mofcomp $_.Name
        }
        Get-ChildItem -Filter *.mfl | ForEach-Object {
            mofcomp $_.Name
        }
    }
    catch {
        Write-Error -Message "[$($_.InvocationInfo.ScriptLineNumber)][Error] $($_.Exception.Message)"
    }
    
}

$RegisterCommonDLLs = {
    regsvr32.exe /s "C:\WINDOWS\system32\actxprxy.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\atl.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\Bitsprx2.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\Bitsprx3.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\browseui.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\cryptdlg.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\dssenh.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\gpkcsp.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\initpki.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\jscript.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\mshtml.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\msi.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\mssip32.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\msxml3.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\msxml3r.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\msxml6.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\msxml6r.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\muweb.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\ole32.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\oleaut32.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\Qmgr.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\Qmgrprxy.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\rsaenh.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\sccbase.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\scrrun.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\shdocvw.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\shell32.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\slbcsp.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\softpub.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\urlmon.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\userenv.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\vbscript.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\Winhttp.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wintrust.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wuapi.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wuaueng.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wuaueng1.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wucltui.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wucltux.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wups.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wups2.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wuweb.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wuwebv.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\wbem\wmisvc.dll"
    regsvr32.exe /s "C:\WINDOWS\system32\Xpob2res.dll"
}

$DefaultLaunchPermission = {
    $Reg = [WMIClass]"root\default:StdRegProv"
    
    $DCOM = $Reg.GetBinaryValue(2147483650, "SOFTWARE\Microsoft\Ole", "DefaultLaunchPermission").uValue
    $Security = Get-CimInstance -Namespace 'root/cimv2' -ClassName '__SystemSecurity'

    $Converter = [System.Management.ManagementClass]::new('Win32_SecurityDescriptorHelper')
    #$converter = New-object system.management.ManagementClass Win32_SecurityDescriptorHelper
    $Converter.BinarySDToSDDL($DCOM).SDDL
}

$UninstallAgent = {
    
    #$ProductCode = (Get-WmiObject -Class CCM_InstalledProduct -Namespace "root\ccm").ProductCode    
    #Invoke-Expression("msiexec.exe /x '$ProductCode' REBOOT=ReallySuppress /q")

    #C:\Windows\ccmsetup\ccmsetup.exe /uninstall

    $ccm = (Get-Process 'ccmsetup' -ErrorAction SilentlyContinue) 
    if ($ccm -ne $null) { 
        $ccm.kill(); 
    }

    Start-Process -Wait C:\Windows\ccmsetup\ccmsetup.exe /uninstall
    Start-Sleep 30

    Remove-Item C:\Windows\CCM -force -recurse
    Remove-Item C:\Windows\SMSCFG.ini
    Stop-Process 'ccmsetup' -Force
}

$InstallAgent = {
    $CMMP = 'atklsccm.kostweingroup.intern'
    $CMSiteCode = 'KOW'

    $ErrorActionPreference = "SilentlyContinue" 

    try { 
        #Get ccm cache path for later cleanup... 
        try { 
            $ccmcache = ([wmi]"ROOT\ccm\SoftMgmtAgent:CacheConfig.ConfigKey='Cache'").Location 
        }
        catch {} 

        #download ccmsetup.exe from MP 
        $webclient = New-Object System.Net.WebClient 
        $url = "http://$($CMMP)/CCM_Client/ccmsetup.exe" 
        $file = "c:\windows\temp\ccmsetup.exe" 
        $webclient.DownloadFile($url, $file) 

        #stop the old sms agent service 
        stop-service 'ccmexec' -ErrorAction SilentlyContinue 

        #Cleanup cache 
        if ($ccmcache -ne $null) { 
            try { 
                Get-ChildItem $ccmcache '*' -directory | ForEach-Object { [io.directory]::delete($_.fullname, $true) } -ErrorAction SilentlyContinue 
            }
            catch {} 
        } 

        #Cleanup Execution History 
        #Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS\Mobile Client\*' -Recurse -ErrorAction SilentlyContinue 
        #Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\*' -Recurse -ErrorAction SilentlyContinue 

        #kill existing instances of ccmsetup.exe 
        $ccm = (Get-Process 'ccmsetup' -ErrorAction SilentlyContinue) 
        if ($ccm -ne $null) { 
            $ccm.kill(); 
        } 

        #run ccmsetup
        $MP = "/mp:$($CMMP)"
        $Source = "/source:http://$($CMMP)/CCM_Client"
        $Port = "CCMHTTPPORT=80"
        $ResetKey = "RESETKEYINFORMATION=TRUE"
        $Site = "SMSSITECODE=$($CMSiteCode)"
        $SMSSLP = "SMSSLP=$($CMMP)"
        $FSP = "FSP=$($CMMP)"
        $AllowMetered = "/allowmetered"

        $Arguments = "$MP $Source $Port $ResetKey $Site $SMSSLP $FSP $AllowMetered"

        $CCMArgs = @{
            FilePath     = 'c:\windows\temp\ccmsetup.exe'
            ArgumentList = $Arguments
            PassThru     = $True
            Wait         = $true
        }
        
        $null = Start-Process @CCMArgs
        Start-Sleep(5) 
        "ccmsetup started..." 

    }
    catch { 
        "an Error occured..." 
        $error[0] 
    } 
}

$InstallAgent02 = {

    $CMMP = 'atklsccm.kostweingroup.intern'
    $CMSiteCode = 'KOW'

    #kill existing instances of ccmsetup.exe 
    $ccm = (Get-Process 'ccmsetup' -ErrorAction SilentlyContinue) 
    if ($ccm -ne $null) { 
        $ccm.kill(); 
    }

    #$InstArgs = "/service /forceinstall /retry:1 /MP:$($CMMP) /BITSPriority:FOREGROUND /Source:'\\$($CMMP)\SCCM-CLIENT' SMSSITECODE=$($CMSiteCode) RESETKEYINFORMATION=TRUE"

    #Start-Process c:\windows\ccmsetup\ccmsetup.exe $($InstArgs) -Wait

    C:\windows\ccmsetup\ccmsetup.exe /service /forceinstall /retry:1 /MP:atklsccm /BITSPriority:FOREGROUND /Source:"\\atklsccm\SCCM-CLIENT" SMSSITECODE=KOW RESETKEYINFORMATION=TRUE

    Start-Sleep 20
    schtasks /Run /TN "Microsoft\Configuration Manager\Configuration Manager Client Retry Task"

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
        Remediation = {  }
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

function Invoke-DeviceCheck {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String[]] $Computers
    )

    # Path to log file
    $BaselogPath = "\\atklsccm\sources`$\Logs\DeviceCheckLogs"

    # Maximum number of concurrent jobs
    $maxConcurrency = 5

    # Running commands in parallel
    $computers | ForEach-Object -Parallel {
        $Computer = $_
        $logPath = Join-Path -Path $using:BaselogPath -ChildPath "$computer.log"

        # Script block for logging
        $logScriptBlock = {
            param (
                $message, 
                $logPath
            )

            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            "$timestamp - $message" | Out-File -FilePath $logPath -Append
        }


        try {
            # Check connectivity
            $ping = Test-Connection -ComputerName $computer -Count 1 -Quiet
            if (-not $ping) {
                &$logScriptBlock "[$Computer] Cannot connect. Skipping..." $logPath
                return
            }

            # Running gpupdate
            &$logScriptBlock "[$Computer] Running gpupdate" $logPath
            $GPUpdateResult = Invoke-Command -ComputerName $computer -ScriptBlock {
                gpupdate /force
            } -ErrorAction Stop
            &$logScriptBlock "[$Computer] GPUpdate: `n`r$GPUpdateResult" $logPath

            # Running sfc /scannow
            &$logScriptBlock "[$Computer] Running sfc /scannow" $logPath
            $SFCResult = Invoke-Command -ComputerName $computer -ScriptBlock {
                sfc /scannow
            } -ErrorAction Stop
            &$logScriptBlock "[$Computer] SFC: `n`r$SFCResult" $logPath

            &$logScriptBlock "[$Computer] Commands completed successfully." $logPath

        }
        catch {
            &$logScriptBlock "[$Computer] Error running commands: `n`r$_" $logPath
            #$errorResult = "Error on $($computer): $_"
            #$using:resultsQueue.Enqueue($errorResult)
        }

    } -ThrottleLimit $maxConcurrency

    
}

# List of computers to run the commands on
$Computers = @("LP843", "LP1071", 'LP662', 'LP1039', 'LP704', 'LP767', 'LP891', 'LP1092', 'LP841', 'LP839', 'LP589')
Invoke-DeviceCheck -Computers $Computers

