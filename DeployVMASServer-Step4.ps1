<#
# DeployVMASServer-Step4.ps1
# Modified 2021/10/21
# Last Modifier:  Jim Martin
# Project Owner:  Jim Martin
# Version: v1.2.1

# Script should automatically start when the virtual machine starts
# Syntax for running this script:
#
# .\DeployVMASServer-Step4.ps1
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
## Functions for Exchange configuration
function Install-ExchSU {
    switch($ExchangeInstall_LocalizedStrings.res_0003){
        0 {Install-Exch2013SU}
        1 {Install-Exch2016SU}
        2 {Install-Exch2019SU}
    }
}
function Install-Exch2013SU {
    ## Download and install January 2022 Security Update for Exchange 2013 CU23
    Write-Host "Downloading Security Update for Exchange 2013 CU23..." -ForegroundColor Green 
    Invoke-WebRequest -Uri "https://download.microsoft.com/download/b/a/f/baf576c9-f5d6-44e0-84c1-c97add5f627b/Exchange2013-KB5008631-x64-en.msp" -OutFile "C:\Temp\Exchange2013-KB5008631-x64-en.msp" 
    Write-Host "Installing January 2022 Security Update for Exchange 2013 CU23..." -ForegroundColor Green -NoNewline
    Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2013-KB5008631-x64-en.msp /passive /norestart"
    Start-Sleep -Seconds 10
    while(Get-Process msiexec | where {$_.MainWindowTitle -eq "Security Update for Exchange Server 2013 Cumulative Update 23 (KB5008631)"} -ErrorAction SilentlyContinue) {
        Write-Host "..." -ForegroundColor Green -NoNewline
        Start-Sleep -Seconds 10
    }
    Write-Host "COMPLETE"
}
function Install-Exch2016SU{
## Download and install Security Update for Exchange 2016
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.01.2308*") {
        Write-Host "Downloading Security Update for Exchange 2016 CU21..." -ForegroundColor Green 
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/a/a/a/aaa3b6bf-543e-49f9-9403-faf3a8afe5a9/Exchange2016-KB5008631-x64-en.msp" -OutFile "C:\Temp\Exchange2016-KB5008631-x64-en.msp" 
    }
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.01.2375*") {
        Write-Host "Downloading Security Update for Exchange 2016 CU22..." -ForegroundColor Green
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/8/0/9/80947b03-7fd2-44fe-877f-7870f9bedfb8/Exchange2016-KB5008631-x64-en.msp" -OutFile "C:\Temp\Exchange2016-KB5008631-x64-en.msp" 
    }
    if(Get-Item C:\Temp\Exchange2016-KB5007409-x64-en.msp -ErrorAction Ignore) {
        Write-Host "Installing January 2022 Security Update for Exchange 2016..." -ForegroundColor Green -NoNewline
        Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2016-KB5008631-x64-en.msp /passive /norestart"
        Start-Sleep -Seconds 10
        while(Get-Process msiexec | where {$_.MainWindowTitle -like "*KB5008631*"} -ErrorAction SilentlyContinue) {
            Write-Host "..." -ForegroundColor Green -NoNewline
            Start-Sleep -Seconds 10
        }
        Write-Host "COMPLETE"
    }
}
function Install-Exch2019SU{
    ## Download and install January 2022 Security Update for Exchange 2019
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.02.0922*") {
        Write-Host "Downloading Security Update for Exchange 2019 CU10..." -ForegroundColor Green 
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/4/d/9/4d9bc4d8-d64b-4237-a39a-792e4907bfff/Exchange2019-KB5008631-x64-en.msp" -OutFile "C:\Temp\Exchange2019-KB5008631-x64-en.msp" 
    }
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.02.0986*") {
        Write-Host "Downloading Security Update for Exchange 2019 CU11..." -ForegroundColor Green 
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/e/6/4/e643edcb-923f-4a47-8948-5e088196fcd6/Exchange2019-KB5008631-x64-en.msp" -OutFile "C:\Temp\Exchange2019-KB5008631-x64-en.msp" 
    }
    if(Get-Item C:\Temp\Exchange2019-KB5007409-x64-en.msp -ErrorAction Ignore) {
        Write-Host "Installing January 2022 Security Update for Exchange 2019..." -ForegroundColor Green -NoNewline
        Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2019-KB5008631-x64-en.msp /passive /norestart"
        Start-Sleep -Seconds 10
        while(Get-Process msiexec | where {$_.MainWindowTitle -like "*KB5008631*"} -ErrorAction SilentlyContinue) {
            Write-Host "..." -ForegroundColor Green -NoNewline
            Start-Sleep -Seconds 10
        }
        Write-Host "COMPLETE"
    }
}
function Get-DomainControllers {
    ## Get one online domain controller for each site to confirm AD replication
    $sites = New-Object System.Collections.ArrayList
    $ADDomainControllers = New-Object System.Collections.ArrayList
    Get-ADDomainController -Filter * -ErrorAction Ignore | ForEach-Object {
        if($sites -notcontains $_.Site) {
            if(Test-Connection $_.HostName -Count 1 -ErrorAction Ignore) {
                $sites.Add($_.Site) | Out-Null
                $ADDomainControllers.Add($_.Hostname) |Out-Null
            }
        }
    }
    return ,$ADDomainControllers
}
function Prepare-DatabaseAvailabilityGroup {
    New-ADComputer -Name $dagName -AccountPassword (ConvertTo-SecureString -String "Pass@word1" -AsPlainText -Force) -Description 'Database Availability Group cluster name' -Enabled:$False -SamAccountName $dagName
    Set-ADComputer $dagName -add @{"msDS-SupportedEncryptionTypes"="28"}
    $adComputer = (Get-ADComputer $dagName).DistinguishedName
    $acl = get-acl "ad:$adComputer"
    $exchGroup = Get-ADGroup "Exchange Servers"
    $sid = [System.Security.Principal.SecurityIdentifier] $exchGroup.SID
    # Create a new access control entry to allow access to the OU
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
    # Add the ACE to the ACL, then set the ACL to save the changes
    $acl.AddAccessRule($ace)
    Set-acl -aclobject $acl "ad:$adComputer"
}
function Check-FileShareWitness {
    ## Checking to see if the file share witness is a domain controller and
    ## Adding the Exchange Trusted Subsytem to the Administrators group to preven quorum failures
    $adDomain = (Get-ADDomain).DistinguishedName
    [string]$fsw = (Get-DatabaseAvailabilityGroup $DagName).WitnessServer
    if($fsw -like "*.*") {
        $fsw = $fsw.Substring(0, $fsw.IndexOf("."))
    }
    if((Get-ADObject -LDAPFilter "(&(name=*$fsw*)(objectClass=Computer))" -SearchBase $adDomain -SearchScope Subtree -Properties rIDSetReferences -ErrorAction Ignore).rIDSetReferences) {
            Write-Host "File share witness is a domain controller. Setup will add the Exchange Trusted Subsystem to the Administrators group." -ForegroundColor Yellow -BackgroundColor Black
            Add-ADGroupMember -Identity Administrators -Members "Exchange Trusted Subsystem" -Confirm:$False    
    }
}
function Enable-TLS {
## Check for and enable TLS 1.2 on the server
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Name "TLS 1.2" | Out-Null
    }
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\' -Name Server | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name Enabled -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name Enabled -Value 1 -Force
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name Enabled -Value 1 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name DisabledByDefault -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name DisabledByDefault -Value 0
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name DisabledByDefault -Value 0 -PropertyType DWORD | Out-Null
    }
## Check for TLS 1.2 being enabled for the server as a client
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\' -Name Client | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -Value 1 -Force
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -Value 1 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name DisabledByDefault -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name DisabledByDefault -Value 0
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name DisabledByDefault -Value 0 -PropertyType DWORD | Out-Null
    }

## Check for and enable TLS 1.2 for .NET framework 3.5
    if(Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 -Name SystemDefaultTlsVersions -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 -Name SystemDefaultTlsVersions -Value 1
    }
    else {
        New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 -Name SystemDefaultTlsVersions -Value 1 -PropertyType DWORD | Out-Null
    }

## Check for and enable TLS 1.2 for .NET framework 4.0
    if(Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319 -Name SystemDefaultTlsVersions -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319 -Name SystemDefaultTlsVersions -Value 1
    }
    else {
        New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319 -Name SystemDefaultTlsVersions -Value 1 -PropertyType DWORD | Out-Null
    }
}
function Sync-ADConfigPartition {
    ## Synchronize the Configuration container in Active Directory
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
    [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
    $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
    [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
    $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
    [string]$configPartition = "CN=Configuration,$adDomain"
    repadmin /replicate $fromServer $toServer $configPartition /force
    }
}
function Sync-ADDirectoryPartition {
    ## Synchronize the Configuration container in Active Directory
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
    [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
    $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
    [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
    $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
    repadmin /replicate $fromServer $toServer $adDomain /force | Out-Null
    }
}
function Add-DatabaseCopies {
## Adding the database copies the Exchange server previously had configured
    param( [parameter(mandatory=$true)] [string]$readFile )
    $reader = New-Object System.IO.StreamReader($readFile)
    while(($currentLine = $reader.ReadLine()) -ne $null) {
        $db = $currentLine.Substring(0, $currentLine.IndexOf(","))
        $copyFound = $false
        while($copyFound -eq $false) {
            $currentLine = $currentLine.Substring($currentLine.IndexOf("[") + 1)
            $server = $currentLine.Substring(0, $currentLine.IndexOf(","))
            if($server -eq $ServerName) {
                $currentLine = $currentLine.Substring($currentLine.IndexOf(",")+2)
                $replayLagTime = $currentLine.Substring(0, $currentLine.IndexOf("]"))
                $copyFound = $true
                Write-Host "Adding database copy for $db with a replay lag time of $replayLagTime" -ForegroundColor Green -NoNewline
                Add-MailboxDatabaseCopy $db -MailboxServer $ServerName -ReplayLagTime $replayLagTime | Out-Null
                Write-Host "COMPLETE"
            }
        }
    }
}
function Set-ActivationPreferences {
## Resetting the activation preferences for the database copies
param( [parameter(mandatory=$true)] [string]$readFile )
    $reader = New-Object System.IO.StreamReader($readFile)
    while(($currentLine = $reader.ReadLine()) -ne $null) {
        $db = $currentLine.Substring(0, $currentLine.IndexOf(","))
        $currentLine = $currentLine.Substring($currentLine.IndexOf(",")+1)
        $endOfLine = $false
        while($endOfLine -eq $false) {
            $endChar = $currentLine.IndexOf(",")
            $server = $currentLine.Substring(1, $endChar-1)
            $currentLine = $currentLine.Substring($endChar+2)
            $prefNumber = $currentLine.Substring(0, $currentLine.IndexOf("]"))
            $copyName = $db + "\" + $server
            Write-Host "Setting $db on $server with an activation preference of $prefNumber..." -ForegroundColor Green
            Set-MailboxDatabaseCopy $copyName -ActivationPreference $prefNumber | Out-Null
            if($currentLine -notlike "*,*") {
                $endOfLine = $true
            }
            else {
                $currentLine = $currentLine.Substring($currentLine.IndexOf("["))
                $currentLine
            }
        }
    }
}
function Check-MSExchangeRepl {
    ## Check if the Microsoft Exchange Replication service is running
    if((Get-Service -ComputerName $ServerName MSExchangeRepl).Status -eq "Running") {
        return $true
    }
    else {
        ## Attempt to start the Microsoft Exchange Replication service
        Invoke-Command -ComputerName $ServerName -ScriptBlock { Start-Service MSExchangeRepl }
        return $false
    }
}
Start-Transcript -Path C:\Temp\DeployServer-Log.txt -Append -NoClobber | Out-Null
Write-Warning "Running the Step4 script now..."
## Clean up the registry from the automatic login information
Write-Host "Removing auto-logon registry keys..." -ForegroundColor Green -NoNewline
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Force | Out-Null
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Force | Out-Null
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Force | Out-Null
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -Force | Out-Null
Write-Host "COMPLETE"
## Get the server name from the registry
Write-Host "Getting server name..." -ForegroundColor Green -NoNewline
$ServerName = $env:COMPUTERNAME
Write-Host "COMPLETE"
## Get variables from previous user input
Write-Host "Getting variables for setup..." -ForegroundColor Green -NoNewline
Import-LocalizedData -BindingVariable ExchangeInstall_LocalizedStrings -FileName $ServerName"-ExchangeInstall-strings.psd1"
Write-Host "COMPLETE"
## Verify that the domain can be resolved before continuing
Write-Host "Verifying the domain can be resolved..." -ForegroundColor Green -NoNewline
$domain = $ExchangeInstall_LocalizedStrings.res_0014
$serverReady = $false
while($serverReady -eq $false) {
    $domainController = (Resolve-DnsName $domain -Type SRV -Server $ExchangeInstall_LocalizedStrings.res_0031 -ErrorAction Ignore).PrimaryServer
    if($domainController -like "*$domain") { $serverReady = $true }
    Start-Sleep -Seconds 5
}
Write-Host "COMPLETE"
## Get the AD Domain
$adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
## Finalize Exchange setup
Write-Host "Finalizing Exchange setup..." -ForegroundColor Green
## Open WinRM for future Exchange installs where the VM host is not on the same subnet
Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Where {$_.Profile -eq "Public" } | Set-NetFirewallRule -RemoteAddress Any
if($ExchangeInstall_LocalizedStrings.res_0003 -ne 2) {
    Write-Host "Enabling TLS 1.2 on the server..." -ForegroundColor Green
    ## Enable TLS 1.2 on the server
    Enable-TLS
    Write-Host "Complete"
}
## Verify all Exchange services are running
Get-Service MSExch* | Where { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" } | ForEach-Object { Start-Service $_ -ErrorAction Ignore}
## Connect a remote PowerShell session to the server
$exchConnection = $false
while($exchConnection -eq $false) {
    Write-Host "Connecting a remote PowerShell session with $ServerName..." -ForegroundColor Yellow
    try {Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ServerName/PowerShell" -AllowRedirection -Authentication Kerberos) | Out-Null}
    catch { Start-Sleep -Seconds 30 }
    if(Get-ExchangeServer $ServerName) {
        $exchConnection = $true
    }
    else {
        Write-Host "..." -ForegroundColor Green -NoNewline
        Start-Sleep -Seconds 30
    }
}
Sync-AdConfigPartition
## Disable Exchange diagnostic and monitoring services
Write-Host "Disabling unwanted Exchange services for lab environment..." -ForegroundColor Green -NoNewline
switch ($ExchangeInstall_LocalizedStrings.res_0003) {
    1 { Set-Service MSExchangeHMRecovery -StartupType Disabled }
    2 { Set-Service MSExchangeHMRecovery -StartupType Disabled }
}
Set-Service MSExchangeDiagnostics -StartupType Disabled
Set-Service MSExchangeHM -StartupType Disabled
Write-Host "COMPLETE"
## Finish Exchange configuration
$DagName = $ExchangeInstall_LocalizedStrings.res_0001
## Updating the Exchange certificate
if($ExchangeInstall_LocalizedStrings.res_0002 -ne $null) {        
    Write-Host "Importing Exchange certificate and assigning services..." -ForegroundColor Green
    $transportCert = (Get-TransportService $ServerName).InternalTransportCertificateThumbprint
    Import-ExchangeCertificate -Server $ServerName -FileName "C:\Temp\$ServerName-Exchange.pfx" -Password (ConvertTo-SecureString -String "Pass@word1" -AsPlainText -Force) -PrivateKeyExportable:$True | Out-Null
    Enable-ExchangeCertificate -Thumbprint $ExchangeInstall_LocalizedStrings.res_0002 -Services IIS,SMTP -Server $ServerName -Force
    ## Reset the transport service certificate back to the original self-signed certificate
    Enable-ExchangeCertificate -Thumbprint $transportCert -Services SMTP -Server $ServerName -Force
}
## Configure the Exchange virtual directories
$intHostname = $ExchangeInstall_LocalizedStrings.res_0020
$extHostname = $ExchangeInstall_LocalizedStrings.res_0021
if($intHostname -ne $null -and $extHostname -ne $null) {
    Write-Host "Configuring virtual directories..." -ForegroundColor Green
    Write-Host "Updating Autodiscover URL..." -ForegroundColor Green -NoNewline
    Get-ClientAccessServer $ServerName | Set-ClientAccessServer -AutoDiscoverServiceInternalUri https://$intHostname/Autodiscover/Autodiscover.xml
    Write-Host "COMPLETE"
    Write-Host "Updating Exchange Control Panel virtual directory..." -ForegroundColor Green -NoNewline
    Get-EcpVirtualDirectory -Server $ServerName |Set-EcpVirtualDirectory -InternalUrl https://$intHostname/ecp -ExternalUrl https://$extHostname/ecp
    Write-Host "COMPLETE"
    Write-Host "Updating Exchange Web Services virtual directory..." -ForegroundColor Green -NoNewline
    Get-WebServicesVirtualDirectory -Server $ServerName | Set-WebServicesVirtualDirectory -InternalUrl https://$intHostname/ews/exchange.asmx -ExternalUrl https://$extHostname/ews/exchange.asmx -Force
    Write-Host "COMPLETE"
    Write-Host "Updating Mapi over Http virtual directory..." -ForegroundColor Green -NoNewline
    Get-MapiVirtualDirectory -Server $ServerName | Set-MapiVirtualDirectory -InternalUrl https://$intHostname/mapi -ExternalUrl https://$extHostname/mapi
    Write-Host "COMPLETE"
    Write-Host "Updating Exchange ActiveSync virtual directory..." -ForegroundColor Green -NoNewline
    Get-ActiveSyncVirtualDirectory -Server $ServerName | Set-ActiveSyncVirtualDirectory -ExternalUrl https://$extHostname/Microsoft-Server-ActiveSync
    Write-Host "COMPLETE"
    Write-Host "Updating Offline Address Book virtual directory..." -ForegroundColor Green -NoNewline
    Get-OabVirtualDirectory -Server $ServerName | Set-OabVirtualDirectory -InternalUrl https://$intHostname/oab -ExternalUrl https://$extHostname/oab
    Write-Host "COMPLETE"
    Write-Host "Updating Outlook Anywhere settings..." -ForegroundColor Green -NoNewline
    Get-OutlookAnywhere -Server $ServerName | Set-OutlookAnywhere -InternalClientAuthenticationMethod Negotiate -InternalHostname $intHostname -InternalClientsRequireSsl:$False -ExternalClientAuthenticationMethod Ntlm -ExternalClientsRequireSsl:$True -ExternalHostname $extHostname
    Write-Host "COMPLETE"
    Write-Host "Updating Outlook Web App virtual directory..." -ForegroundColor Green -NoNewline
    Get-OwaVirtualDirectory -Server $ServerName | Set-OwaVirtualDirectory -InternalUrl https://$intHostname/owa -ExternalUrl https://$extHostname/owa -LogonFormat UserName -DefaultDomain $ExchangeInstall_LocalizedStrings.res_0014
    Write-Host "COMPLETE"
}
## Check whether to create a new DAG or to end the script
switch ($ExchangeInstall_LocalizedStrings.res_0004) { ## Checking new or restore
    0 { switch ($ExchangeInstall_LocalizedStrings.res_0015) { ## Checking if existing or new DAG
            0 { }## Add the Exchange server to the database availability group
            1 { ## Creating a new Database Availability Group
                Write-Host "Creating the new Database Availability group named $DagName..." -ForegroundColor Green -NoNewline
                ## Determine if there is an administrative access point or not
                if($ExchangeInstall_LocalizedStrings.res_0032 -eq 0) {
                    New-DatabaseAvailabilityGroup -Name $DagName -WitnessServer $ExchangeInstall_LocalizedStrings.res_0018 -WitnessDirectory $ExchangeInstall_LocalizedStrings.res_0019 -DatabaseAvailabilityGroupIpAddresses ([System.Net.IPAddress]::None) | Out-Null                              
                        Write-Host "COMPLETE"
                }
                else {
                    ## Create the cluster node object in Active Directory and sync those changes
                    Prepare-DatabaseAvailabilityGroup
                    Sync-ADDirectoryPartition
                    ## Get the IP addresses for the DAG and then create the DAG
                    $dagIPs = $ExchangeInstall_LocalizedStrings.res_0033.Split(" ")
                    $dagIPs | ForEach-Object { [IPAddress]$_.Trim() } | Out-Null
                    New-DatabaseAvailabilityGroup -Name $DagName -WitnessServer $ExchangeInstall_LocalizedStrings.res_0018 -WitnessDirectory $ExchangeInstall_LocalizedStrings.res_0019 -DatabaseAvailabilityGroupIpAddresses $dagIPs | Out-Null                              
                }
            }
            2 { ## Standalone server install
                ## Install security update
                Install-ExchSU
                Write-Host "Server installation complete"
                Restart-Computer
            }
        }
    }
    1 { ## This was a recover server and must determine whether a DAG member or standalone server
        if($DagName -eq $null) {
            ## Install security update
            Install-ExchSU
            Write-Host "Server installation complete"
            Start-Sleep -Seconds 5
            Restart-Computer
        }
    }
}
## Make sure the MSExchangeRepl service is running before attempting to add Exchange server to the DAG
Write-Host "Verifying MSExchangeRepl service is running on $ServerName..." -ForegroundColor Green -NoNewline
$exchReplServiceRunning = $false
while($exchReplServiceRunning -eq $false) {
    $exchReplServiceRunning = Check-MSExchangeRepl
    Write-Host "..." -ForegroundColor Green -NoNewline
}
Write-Host "COMPLETE"
## Check to ensure the DAG is available before joining
Write-Host "Verifying $DagName is available.." -ForegroundColor Green -NoNewline
$dagAvailable = $false
while($dagAvailable -eq $false) {
    if(Get-DatabaseAvailabilityGroup $DagName -ErrorAction Ignore) {
        $dagAvailable = $true
    }
    else {
        Sync-AdConfigPartition
        Write-Host "..." -ForegroundColor Green -NoNewline
        Start-Sleep -Seconds 5
    }
}
## Check if the FSW is a DC
Check-FileShareWitness
## Add the Exchange server the the DAG
Write-Host "Adding server to the DAG..." -ForegroundColor Green
Add-DatabaseAvailabilityGroupServer $DagName -MailboxServer $ServerName
## Synchronize Active Directory with the new DAG member
Write-Host "Synchronizing Active Directory with the latest update..." -ForegroundColor Green
Sync-AdConfigPartition
Write-Host "COMPLETE"
## Confirm Active Directory replication is updated across sites
Write-Host "Verifying AD replication has completed..." -ForegroundColor Yellow
$domainController = $ExchangeInstall_LocalizedStrings.res_0031
$domainControllers = New-Object System.Collections.ArrayList
$domainControllers = Get-DomainControllers
$domainControllers | ForEach-Object { 
    $serverFound = $false
    Write-Host "Checking for $serverName in $DagName on $_ ..." -ForegroundColor Green -NoNewline
    while( $serverFound -eq $False) {
        if((Get-DatabaseAvailabilityGroup $DagName -DomainController $_).Servers -match $serverName) {
            Write-Host "COMPLETE"
            $serverFound = $True
        }
        else {
            Sync-AdConfigPartition
            Start-Sleep -Seconds 5
        }
        Write-Host "..." -ForegroundColor Green -NoNewline
    }
}
## Add the mailbox database copies for the recovered server
if($ExchangeInstall_LocalizedStrings.res_0004 -eq 1 -and $DagName -ne $null) {
    ## Check if there are database copies to add
    if($ExchangeInstall_LocalizedStrings.res_0025 -eq 1) {
        ## Add the mailbox database copies for this Exchange server
        Write-Host "Adding database copies to the server..." -ForegroundColor Green
        Add-DatabaseCopies "c:\Temp\$ServerName-DatabaseCopies.txt"
        ## Reset the activation preferences for the databases
        Write-Host "Setting database activation preferences..." -ForegroundColor Yellow
        Set-ActivationPreferences "c:\Temp\$ServerName-$DagName-ActivationPreferences.txt"
    }
}
## Exchange server setup is complete
## Install security update
Install-ExchSU
Restart-Computer

# SIG # Begin signature block
# MIIDZgYJKoZIhvcNAQcCoIIDVzCCA1MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCbRnK/0aIyNOQX
# fPyr33UCvLANSTZTjbGID3EHmYqdSqCCAZQwggGQMIIBFaADAgECAggmFxDWcEY7
# FTAKBggqhkjOPQQDAzAvMS0wKwYDVQQDEyQ3ZDMxYjI0NC05N2Y5LTQxZDAtYjQ5
# OS1mYzI0NjMxYmE1YTIwHhcNMjIwMTA0MDE1NjM2WhcNMjMwMTA0MTM1NjM2WjAv
# MS0wKwYDVQQDEyQ3ZDMxYjI0NC05N2Y5LTQxZDAtYjQ5OS1mYzI0NjMxYmE1YTIw
# djAQBgcqhkjOPQIBBgUrgQQAIgNiAASUaEmnP41/+lLXJYyUrAgHkTJAAh5eGabX
# yxoIVZ37/dE/Iyiy8rOraIaAkOEvswb4feDM96Chr0Dvd5DAVGWuxyVSh2xjFfyN
# P8jCulJgDFNospS9R5aX2h4y5WEn4XUwCgYIKoZIzj0EAwMDaQAwZgIxAJE52jMb
# c2lnsNMc5DrmsWk9mcWp2nR61oCAY+kBFkVXG229SrsU2QDG/4aCV3i74gIxAJ2p
# Ym1jSnD1MLCS6W4mpeHGgXoXbXOJ9jqRbWqc3g5ZdDxUXiUo66sVuT2YElKsgDGC
# ASgwggEkAgEBMDswLzEtMCsGA1UEAxMkN2QzMWIyNDQtOTdmOS00MWQwLWI0OTkt
# ZmMyNDYzMWJhNWEyAggmFxDWcEY7FTANBglghkgBZQMEAgEFAKBeMBAGCisGAQQB
# gjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMC8GCSqGSIb3DQEJ
# BDEiBCCU67YiLuyWbdA93ySE7RXIXnbizsvjFAWV9l+4OwfaljALBgcqhkjOPQIB
# BQAEZjBkAjAon3DNCPUUmu4TKkmHJ+r9RlHFvrjiFeF2y23y+C4jU+rxjGs/KEsy
# 0KyOE9T01LsCMFQEZqzX84XR0L4rE3l/W+AVM4C/rdCvsha1xprVd3LQFZJXZbGH
# BfEAhTIX6PstkQ==
# SIG # End signature block
