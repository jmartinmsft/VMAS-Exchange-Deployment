<#
# DeployVMASServer-Step3.ps1
# Modified 16 November 2022
# Last Modifier:  Jim Martin
# Project Owner:  Jim Martin
# Version: v20221116.0903

# Script should automatically start when the virtual machine starts
# Syntax for running this script:
#
# .\DeployVMASServer-Step3.ps1
#
#
//***********************************************************************
//
// Copyright (c) 2018 Microsoft Corporation. All rights reserved.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//**********************************************************************​
#>
function Force-ADSync {
    param(
        [string]$domainController,
        [string]$adDomain
    )
    $successfulSync = $false
    while($successfulSync -eq $false) {
        $syncResults = Sync-AdConfigPartition $domainController $adDomain
        $successfulSync = Check-SyncResults
        Start-Sleep -Seconds 5
    }
    $successfulSync = $false
    while($successfulSync -eq $false) {
        $syncResults = Sync-AdDirectoryPartition $domainController $adDomain
        $successfulSync = Check-SyncResults
        Start-Sleep -Seconds 5
    }
    $successfulSync = $false
    while($successfulSync -eq $false) {
        $syncResults = Sync-AdSchemaPartition $domainController $adDomain
        $successfulSync = Check-SyncResults
        Start-Sleep -Seconds 5
    }
}
function Sync-AdConfigPartition {
    param(
        [string]$domainController,
        [string]$adDomain
    )
    ## Synchronize the Configuration partition of Active Directory across all replication partners
    Get-ADReplicationConnection -Filter *  -ErrorAction Ignore | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        [string]$configPartition = "CN=Configuration,$adDomain"
        $ScriptBlock = { Param ($param1,$param2,$param3) repadmin /replicate $param1 $param2 "$param3" /force }
        Invoke-Command  -ComputerName $domainController -ScriptBlock $scriptBlock -ArgumentList $toServer, $fromServer, $configPartition
    }
}
function Check-SyncResults {
    if($syncResults -ne $null) {
        foreach($s in $syncResults) {
            if($s -like "*to $fromDC*" -and $s -like "*completed successfully.") {
                return $true
            }
        }
    }
    else {return $true}
    return $false
}
function Sync-AdDirectoryPartition {
    param(
        [string]$domainController,
        [string]$adDomain
    )
    ## Synchronize the Configuration partition of Active Directory across all replication partners
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        $ScriptBlock = { Param ($param1,$param2,$param3) repadmin /replicate $param1 $param2 "$param3" /force }
        Invoke-Command  -ComputerName $domainController -ScriptBlock $scriptBlock -ArgumentList $toServer, $fromServer, $adDomain
    }
}
function Sync-AdSchemaPartition {
    param(
        [string]$domainController,
        [string]$adDomain
    )
    ## Synchronize the Configuration partition of Active Directory across all replication partners
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        [string]$schemaPartition = "CN=Schema,CN=Configuration,$adDomain"
        $ScriptBlock = { Param ($param1,$param2,$param3) repadmin /replicate $param1 $param2 "$param3" /force }
        Invoke-Command  -ComputerName $domainController -ScriptBlock $scriptBlock -ArgumentList $toServer, $fromServer, $schemaPartition
    }    
}
function Check-SetupLog {
    if((Select-String -Path c:\ExchangeSetupLogs\ExchangeSetup.log -Pattern "The Exchange Server setup operation completed successfully.")) {
        return $false
    }
    return $true
}
function Test-PendingReboot {
    ## https://docs.microsoft.com/en-us/previous-versions/office/exchange-server-analyzer/cc164360(v=exchg.80)?redirectedfrom=MSDN
    if((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Ignore).PendingFileRenameOperations) { return $true }
    [int]$regCheck = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Updates" -Name UpdateExeVolatile -ErrorAction Ignore
    if($regCheck -ne 0) { return $true }
    return $false
}
function Reboot-FailedSetup {
    ## Prepare Windows to automatically login after reboot and run the next step
    $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ExchangeSetup" -Force -ErrorAction Ignore | Out-Null
    Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployVMASServer-Step3.ps1')
    $WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $ExchangeInstall_LocalizedStrings.Username
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $ExchangeInstall_LocalizedStrings.DomainPassword
    Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
    Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "5" 
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ExchangeInstall_LocalizedStrings.Domain
    Write-Warning "Setup failed and should retry"
    Restart-Computer
}
#region StartScript
Start-Transcript -Path C:\Temp\DeployServer-Log.txt -Append -NoClobber | Out-Null
Write-Host "Running the Step3.ps1 script now..." -ForegroundColor Yellow
Write-Host "Getting server name..." -ForegroundColor Green -NoNewline
## Get the server name from the registry
$ServerName = $env:COMPUTERNAME
Write-Host "COMPLETE"
## Get variables from previous user input
Write-Host "Getting variables for setup..." -ForegroundColor Green -NoNewline
Import-LocalizedData -BindingVariable ExchangeInstall_LocalizedStrings -FileName $ServerName"-ExchangeInstall-strings.psd1" -BaseDirectory C:\Temp
Write-Host "COMPLETE"
#endregion
#region Enable AutoLogon
Write-Host "Preparing server for the next step..." -ForegroundColor Green -NoNewline
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
$WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "5" 
Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $ExchangeInstall_LocalizedStrings.Username
Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ExchangeInstall_LocalizedStrings.Domain
Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $ExchangeInstall_LocalizedStrings.DomainPassword
Write-Host "COMPLETE"
#endregion
#region Check for domain
Write-Host "Verifying the domain can be resolved..." -ForegroundColor Green -NoNewline
$domain = $ExchangeInstall_LocalizedStrings.Domain
$serverReady = $false
while($serverReady -eq $false) {
    $domainController = (Resolve-DnsName $domain -Type SRV -Server $ExchangeInstall_LocalizedStrings.DomainController -ErrorAction Ignore).PrimaryServer
    if($domainController -like "*$domain") { $serverReady = $true }
    Start-Sleep -Seconds 5
}
Write-Host "COMPLETE"
#endregion
#region Get DN for domain
Write-Host "Importing the Active Directory PowerShell module..." -ForegroundColor Green
Import-Module ActiveDirectory
$adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
$exchContainer = "CN=Microsoft Exchange,CN=Services,CN=Configuration,$adDomain"
while($adDomain.Length -lt 1) {
    Import-Module ActiveDirectory    
    $adDomain = (Get-ADDomain -Server $domainController -ErrorAction Ignore).DistinguishedName ## The given key was not present in the dictionary
    Start-Sleep -Seconds 10
}
#endregion
#region Pending reboot check
Write-Host "Checking if there is a pending reboot prior to installing Exchange..." -ForegroundColor Green -NoNewline
if(Test-PendingReboot) {
    Reboot-FailedSetup
}
Write-Host "COMPLETE"
#endregion
#region Enable run key for next step
Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployVMASServer-Step4.ps1')
#endregion
#region Wait for Exchange organization to exist for additional installs
if($ExchangeInstall_LocalizedStrings.ExchangeOrgMissing -eq 1 -and $ExchangeInstall_LocalizedStrings.ExchangeOrgName.Length -eq 0) {
    Write-Host "Waiting for Active Directory replication..." -ForegroundColor Green -NoNewline
    ## Synchronize Active Directory to ensure Exchange is not waiting on replication
    Force-ADSync $domainController $adDomain
    Write-Host "COMPLETE"
    Write-Host "Verifying Exchange organization is ready for additional Exchange servers..." -ForegroundColor Green
    $servicesContainer = "CN=Services,CN=Configuration,$adDomain"
    $exchContainer = Get-ADObject -LDAPFilter "(objectClass=msExchConfigurationContainer)" -SearchBase $servicesContainer -SearchScope OneLevel -ErrorAction Ignore
    ## First we want to locate the Exchange container
    Write-Host "Checking for the Exchange organization container..." -ForegroundColor Green -NoNewline
    while($exchContainer.Length -lt 1) {
        try {$exchContainer = Get-ADObject -Server $domainController -LDAPFilter "(objectClass=msExchConfigurationContainer)" -SearchBase $servicesContainer -SearchScope OneLevel -ErrorAction Ignore}
        catch {Write-Host "..." -ForegroundColor Green -NoNewline }
        Force-ADSync $domainController $adDomain
        Start-Sleep -Seconds 15
    }
    Write-Host "COMPLETE"
    $exchServer = Get-ADObject -LDAPFilter "(objectClass=msExchExchangeServer)" -SearchBase $exchContainer -SearchScope Subtree
    Write-Host "Checking for an Exchange server..." -ForegroundColor Green -NoNewline
    ## Then we can look for the first server
    while($exchServer.Length -lt 1) {
        try {$exchServer = Get-ADObject -Server $domainController -LDAPFilter "(objectClass=msExchExchangeServer)" -SearchBase $exchContainer -SearchScope Subtree -ErrorAction Ignore}
        catch { Write-Host "..." -ForegroundColor Green -NoNewline }
        Force-ADSync $domainController $adDomain
        Start-Sleep -Seconds 30
    }
    Write-Host "COMPLETE"
}
## Confirm a DC exists in the site where Exchange is being installed
$serverSite = (nltest /dsgetsite)[0]
Write-Host "Verifying a configuration domain controller is available in $serverSite..." -ForegroundColor Green -NoNewline
$siteDC = Get-ADDomainController -Discover -SiteName $serverSite -ErrorAction Ignore
while($siteDC.Length -lt 1) {
    Write-Host "..." -ForegroundColor Green -NoNewline
    Start-Sleep -Seconds 30
    $siteDC = Get-ADDomainController -Discover -SiteName $serverSite -ErrorAction Ignore
}
Write-Host "COMPLETE"
#endregion
#region Install Exchange
$setupSuccess = $false
while($setupSuccess -eq $false) {
    $file = "C:\Temp\exSetup.bat"
    ## Clearing any previous setup log
    Remove-Item -Path c:\ExchangeSetupLogs\ExchangeSetup.log -Force -ErrorAction Ignore | Out-Null
    ## Reset setup command if failed
    (Get-Content $file) -replace "/IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF", "/IAcceptExchangeServerLicenseTerms" | Set-Content $file
    ## Install Exchange
    if($ExchangeInstall_LocalizedStrings.ExchISOPath -ne $null) {
        if(!(Test-Path $ExchangeInstall_LocalizedStrings.ExchSetupPath)) {
            Mount-DiskImage -ImagePath $ExchangeInstall_LocalizedStrings.ExchISOPath
        }
    }
    ## Update the setup command for September 2021 CU releases
    $setupCommand = (Select-String -Path $file -Pattern setup).Line
    $setupFile = $setupCommand.Substring(0, $setupCommand.IndexOf(" "))
    switch ($ExchangeInstall_LocalizedStrings.ExchangeVersion) { ## Checking the version of Exchange being installed
        1 { 
            if((Get-Item $setupFile -ErrorAction Ignore).VersionInfo.ProductVersion -ge "15.01.2375.007") {
                (Get-Content $file) -replace "/IAcceptExchangeServerLicenseTerms", "/IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF" | Set-Content $file
            }
        }
        2 {
            if((Get-Item $setupFile -ErrorAction Ignore).VersionInfo.ProductVersion -ge "15.02.0986.005") {
                (Get-Content $file) -replace "/IAcceptExchangeServerLicenseTerms", "/IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF" | Set-Content $file
            }
        }
    }
    C:\Temp\exSetup.bat
    ## Check if setup failed
    if(Check-SetupLog) {
        Write-Warning "Exchange setup failed"
        Reboot-FailedSetup
    }
    else { $setupSuccess = $true }
}
## Exchange setup completed
Restart-Computer -Force
#endregion
