﻿<#
# Deploy-ExchangeServer.ps1
# Modified 20 November 2023
# Last Modifier:  Jim Martin
# Project Owner:  Jim Martin
# Version: v20231120.0922
# Syntax for running this script:
#
# .\Deploy-ExchangeServer.ps1
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
param(
    [Parameter(Mandatory=$false)] [string]$SetupExePath
)
Clear-Host
function Test-ADAuthentication {
    $UserName = $UserName.Substring(0, $UserName.IndexOf("@"))
    (New-Object DirectoryServices.DirectoryEntry "",$UserName,$Password).PsBase.Name -ne $null
}
function CheckServerCore {
    if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\').InstallationType -eq "Server Core") {
        Add-Content -Path $serverVarFile -Value ('ServerCore = 1')
        $SetupExePath = $SetupExePath.Replace("\","\\")
        Add-Content -Path $serverVarFile -Value ('ExchSetupPath = ' + $SetupExePath)
        return $true
    }
    return $false
}
function Get-ExchangeISO {
        Write-Host "Please select the Exchange ISO" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{InitialDirectory="M:\ISO"; Title="Select the Exchange ISO"}
        $fileBrowser.Filter = "ISO (*.iso)| *.iso"
        $fileBrowser.ShowDialog()
        [string]$exchISO = $fileBrowser.FileName
        Mount-DiskImage -ImagePath $exchISO
        $exchISO = $exchISO.Replace("\","\\")
        Add-Content -Path $serverVarFile -Value ('ExchISOPath = ' + $exchISO)
}
function PromptExchangeDownload {
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $downloadResult = $Host.UI.PromptForChoice("Server deployment script","Would you like to download the latest Exchange server Cumulative Update?", $yesNoOption, 0)
    if($downloadResult -eq 0) {
        switch($exVersion) {
            2{  
                Write-Host "Downloading Exchange 2019 CU13..." -ForegroundColor Green -NoNewline
                $Url = "https://download.microsoft.com/download/7/5/f/75f4d77e-002c-419c-a03a-948e8eb019f2/ExchangeServer2019-x64-CU13.ISO"
                $Path = "C:\Temp\Exchange2019_CU13.iso"
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($url, $Path)
                Write-Host "COMPLETE"
                Mount-DiskImage -ImagePath $Path
                $Path = $Path.Replace("\","\\")
                Add-Content -Path $serverVarFile -Value ('ExchISOPath = ' + $path)
                }
            1{
                Write-Host "Downloading Exchange 2016 CU23..." -ForegroundColor Green -NoNewline
                $Url = "https://download.microsoft.com/download/8/d/2/8d2d01b4-5bbb-4726-87da-0e331bc2b76f/ExchangeServer2016-x64-CU23.ISO"
                $Path = "C:\Temp\Exchange2016_CU23.iso"
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($url, $Path)
                Write-Host "COMPLETE"
                Mount-DiskImage -ImagePath $Path
                $Path = $Path.Replace("\","\\")
                Add-Content -Path $serverVarFile -Value ('ExchISOPath = ' + $Path)
                }
            0{
                Write-Host "Downloading Exchange 2013 CU23..." -ForegroundColor Green -NoNewline
                $Url = "https://download.microsoft.com/download/7/F/D/7FDCC96C-26C0-4D49-B5DB-5A8B36935903/Exchange2013-x64-cu23.exe"
                $Path = "C:\Temp\Exchange2013_CU23.exe"
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($url, $path)
                Write-Host "COMPLETE"
                Write-Warning "Please extract the files before continuing."
                Start-Sleep -Seconds 3
                }
        }
    }
    else {
        if($exVersion -ne 0) {
            if($SetupExePath -like $null) {
                $isoResult = $Host.UI.PromptForChoice("Server deployment script","Would you like to mount an Exchange ISO now?", $yesNoOption, 0)
                if($isoResult -eq 0) {Get-ExchangeISO}
            }
            else {
                $isoResult = $Host.UI.PromptForChoice("Server deployment script","Is an Exchange ISO mounted locally?", $yesNoOption, 0)
                if($isoResult -eq 0) {Get-ExchangeISO}
            }
        }
    }
}
function CheckExchangeVersion {
    $latestVersion = 0
    Get-ExchangeServer | ForEach-Object {
        [int]$serverVersion = $_.AdminDisplayVersion.Substring(11,1)
        if($serverVersion -gt $latestVersion) {
            $latestVersion = $serverVersion
        }
    }
    return $latestVersion
}
function Move-MailboxDatabase {
    param ( [Parameter(Mandatory=$true)][string]$database )
    $stopDbCheck = $false
    #$bestEffort = $false
    while($stopDbCheck -eq $false) {
        $copyStatus = Get-MailboxDatabaseCopyStatus $database | Where-Object {$_.Status -ne "Mounted"}
        [string]$healthyCopy = $null
        foreach($c in $copyStatus) {
            if($c.ContentIndexState -eq "Healthy" -and $c.CopyQueueLength -eq 0 -and $c.Status -eq "Healthy") {
                $healthyCopy = $c.Name
                $healthyCopy = $healthyCopy.Substring($healthyCopy.IndexOf("\")+1)
                $stopDbCheck = $true
                break
            }
        }
        if($healthyCopy.Length -eq 0) {
            Write-Warning "No server has a healthy copy to activate."
            Start-Sleep -Seconds 2
            return $false
        }
    }
    Write-Host "Moving database to $healthyCopy" -ForegroundColor Green
    $moveSuccess = (Move-ActiveMailboxDatabase $database -ActivateOnServer $healthyCopy).Status
    $moveSuccess = ($moveSuccess | Out-String).Trim()
    if($moveSuccess -eq "Succeeded") {
        Sync-AdConfigPartition
        return $true 
    }
    return $false
}
function Move-MailboxDatabaseBestEffort {
    param ( [Parameter(Mandatory=$true)][string]$database)
    $stopDbCheck = $false
    #$bestEffort = $false
    while($stopDbCheck -eq $false) {
        $copyStatus = Get-MailboxDatabaseCopyStatus $database | Where-Object {$_.Status -ne "Mounted"}
        [string]$healthyCopy = $null
        foreach($c in $copyStatus) {
            if($c.Status -eq "Healthy") {
                $healthyCopy = $c.Name
                $healthyCopy = $healthyCopy.Substring($healthyCopy.IndexOf("\")+1)
                $stopDbCheck = $true
                break
            }
        }
        if($healthyCopy.Length -eq 0) {
            Write-Warning "No server has a healthy copy to activate."
            Start-Sleep -Seconds 2
            return $false
        }
    }
    if($null -ne $healthyCopy) {
        Write-Host "Moving database to $healthyCopy with best effort" -ForegroundColor Green
        if(Test-Connection $healthyCopy -Count 1) {
            $moveSuccess = (Move-ActiveMailboxDatabase $database -SkipClientExperienceChecks -MountDialOverride:BestEffort -SkipHealthChecks -Confirm:$False -ErrorAction SilentlyContinue).Status
        }
        else {
            if((Get-MailboxDatabaseCopyStatus $database).Status -notcontains "Mounted") {
                $moveSuccess = (Move-ActiveMailboxDatabase $database -Confirm:$False -SkipActiveCopyChecks -MountDialOverride:BestEffort -SkipClientExperienceChecks).Status
            }
            else {
                $moveSuccess = (Move-ActiveMailboxDatabase $database -Confirm:$False -SkipActiveCopyChecks -SkipClientExperienceChecks -MountDialOverride:BestEffort).Status
            }
        }
        $moveSuccess = ($moveSuccess | Out-String).Trim()
        if($moveSuccess -eq "Succeeded") { 
            Sync-AdConfigPartition
            return $true
        }
    }
    return $false
}
function Get-DAGIPAddress {
    ## There must be at least one IP address for the DAG but there may be more
    $dagIPAddresses = New-Object System.Collections.ArrayList
    #$checkDagIP = $null
    [int]$x = 1 ## Count for the number of DAG IP addresses
    $addDagIP = $true
    ## Add IP addresses for the DAG until a null value is supplied
    while($addDagIP -eq $true) {
        $ipCheck = $null
        ## Get input from the user
        $dagIPAddress = AskForDAGIPAddress $x
        ## Verify the format of the input
        if($dagIPAddress.Length -ne 0) {
            $ipCheck = Test-IP($dagIPAddress)
            ## Verify the IP address is not in use
            if($null -ne $ipCheck) {
                if(Test-Connection $dagIPAddress -Count 1 -ErrorAction Ignore) {
                    Write-Warning "IP addresses provided already in use"
                    $dagIPAddress = $null
                }
            }
            ## Invalid input
            else { $dagIPAddress = $null}
            ## Make sure there is a value before adding to the IP array
            if($dagIPAddress.Length -gt 0) {
                $dagIPAddresses.Add($dagIPAddress) | Out-Null
                $x++
                #$checkDagIP = $null
            }
        }
        else {
            ## Make sure there is at least one IP address before exiting
            if($dagIPAddresses.Count -gt 0) {
                $addDagIP = $false
            }
        }
    }
    Add-Content -Path $serverVarFile -Value ('DagIpAddress = ' + $dagIPAddresses)
}
function AskForDAGIPAddress {
    param([int]$ipCount)
    $dagIP = $null
    $dagIP = Read-HostWithColor "Enter the Database Availability Group IP Addresses[$ipCount]: "
    return $dagIP
}
function Get-DomainControllers {
    ## Get one online domain controller for each site to confirm AD replication
    $sites = New-Object System.Collections.ArrayList
    $ADDomainControllers = New-Object System.Collections.ArrayList
    Get-ADDomainController -Filter * -Server $domainController -Credential $credential | ForEach-Object {
        if($sites -notcontains $_.Site) {
            if(Test-Connection $_.HostName -Count 1 -ErrorAction Ignore) {
                $sites.Add($_.Site) | Out-Null
                $ADDomainControllers.Add($_.Hostname) |Out-Null
            }
        }
    }
    return ,$ADDomainControllers
}
function Connect-Exchange {
    Write-Host "Connecting an Exchange remote PowerShell session to $exchServer..." -ForegroundColor Green
    try { Import-PSSession (New-PSSession -Name ExchangeShell -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchServer/PowerShell -AllowRedirection -Authentication Kerberos -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck) -ErrorAction Ignore) -AllowClobber -ErrorAction Stop | Out-Null}
    catch { Write-Warning "Connection attempt to $exchServer failed. Retrying..."
        Start-Sleep -Seconds 5
        Connect-Exchange
    }
}
function Read-HostWithColor() {
    ## Prompt the user for information with a string in color
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [string]$msg,
        [string]$ForegroundColor = "Yellow"
    )
    Write-Host -ForegroundColor $ForegroundColor -NoNewline $msg;
    return Read-Host
}
function Select-ExchangeVersion {
    ## Select the version of Exchange to be installed
    $ex15 = New-Object System.Management.Automation.Host.ChoiceDescription 'Exchange 201&3', 'Exchange version: Exchange 2013'
    $ex16 = New-Object System.Management.Automation.Host.ChoiceDescription 'Exchange 201&6', 'Exchange version: Exchange 2016'
    $ex19 = New-Object System.Management.Automation.Host.ChoiceDescription 'Exchange 201&9', 'Exchange version: Exchange 2019'
    $exOption = [System.Management.Automation.Host.ChoiceDescription[]]($ex15, $ex16, $ex19)
    $exVersion = $Host.UI.PromptForChoice("Server deployment script","What version of Exchange are you installing", $exOption, 2)
    Add-Content -Path $serverVarFile -Value ('ExchangeVersion = ' + $exVersion)
    return $exVersion
}
function Get-MailboxDatabaseStatus {
    ## Check to see if the database is mounted on the server being restored
    param ([Parameter(Mandatory=$true)][string]$database)
    if((Get-MailboxDatabase $database -DomainController $domainController -Status).MountedOnServer -like '*' + $ServerName + '*') {
        return $true
    }
    return $false
}
function Sync-AdConfigPartition {
    ## Synchronize the Configuration partition of Active Directory across all replication partners
    $repUser = "$domain\$UserName"
    Get-ADReplicationConnection -Filter * -Server $domainController -Credential $credential | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        [string]$configPartition = ($_.ReplicateToDirectoryServer).Substring($_.ReplicateToDirectoryServer.IndexOf("CN=Configuration"))
        $ScriptBlock = { Param ($param1,$param2,$param3,$param4,$param5) repadmin /replicate $param1 $param2 "$param3" /u:$param4 /pw:$param5 /force }
        Invoke-Command  -ComputerName $exchServer -ScriptBlock $scriptBlock -Credential $credential -ArgumentList $fromServer, $toServer, $configPartition, $repUser, $Password | Out-Null
    }
}
function Test-IP() {
    ## Validate the IP address is proper format
    param(
        [Parameter(Mandatory=$True)]
        [ValidateScript({$_ -match [IPAddress]$_ })]
        [String]$ip
    )
    return $ip
}
function Get-ExchangeExe {
    ## Add something to get the Exchange install path
    [string]$exchSetupExe = (Get-Volume | Where-Object {$_.FileSystemLabel -like "EXCHANGESERVER*"}).DriveLetter
    $exchSetupExe = "$($exchSetupExe):\\setup.exe"
    Add-Content -Path $serverVarFile -Value ('ExchSetupPath = ' + $exchSetupExe)
    return $exchSetupExe
}
function ValidateDagName {
    ## Verify the DAG name provided is present
    if($null -ne (Get-DatabaseAvailabilityGroup $DagName -ErrorAction SilentlyContinue).Name) { return $true }
    else { return $false }
}
function Get-CertificateFromServerCheck {
    ## Check if the Exchange certificate from server where the script is running should be used
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $certResult = $Host.UI.PromptForChoice("Server deployment script","Would you like to import the Exchange certificate from this server onto the new Exchange server?", $yesNoOption, 0)
    if($certResult -eq 0) { return $true }
    else { return $false }
}
function Get-ServerCertificate {
    ## Determine the SSL binding information for the Default Web Site
    $scriptBlock = { Import-Module WebAdministration;
        (Get-WebBinding -Name "Default Web Site" -Protocol https | Where-Object {$_.bindingInformation -notlike "127.0.0.1:443:" }).certificateHash
    }
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $certServer -Force
    $session = New-PSSession -Credential $credential -ComputerName $certServer -Name CertificateConfig
    [string]$thumbprint = (Invoke-Command -Session $session -ScriptBlock $scriptBlock)
    $scriptBlock = { Get-ChildItem -Path "Cert:\LocalMachine\My\" -Recurse  }
    $certs = Invoke-Command -Session $session -ScriptBlock $scriptBlock
    foreach($c in $certs) {
        if($c.Thumbprint -eq $thumbprint) {
            if($c.Subject -like "*$certServer*") {
                Write-Host "COMPLETE"
                Write-Host "Current certificate is self-signed certificate and cannot be used" -ForegroundColor Yellow
                $exportCert = $false
            }
        }
    }
    if($exportCert -eq $false) { return $null }
    else { 
        Add-Content -Path $serverVarFile -Value ('CertThumprint = ' + $thumbprint)
        $thumbprint = $thumbprint | Out-String
         return $thumbprint
        
    }
    Disconnect-PSSession -Name CertificateConfig
    Remove-PSSession -Name CertificateConfig
    
    }
function CreateNewDAG {
    ## Get information for create a new database availability group
    $DagName = Read-HostWithColor "Enter the name for the new Database Availability Group: "
    Add-Content -Path $serverVarFile -Value ('DagName = ' + $DagName)
    $witnessServer = Read-HostWithColor "Enter the name of the witness server: "
    Add-Content -Path $serverVarFile -Value ('WitnessServer = ' + $witnessServer)
    $witnessDirectory = Read-HostWithColor "Enter the path for the witness directory: "
    $witnessDirectory = $witnessDirectory.Replace("\","\\")
    Add-Content -Path $serverVarFile -Value ('WitnessDirectory = ' + $witnessDirectory)
}
function Skip-DagCheck {
    ## Don't verify the existence of the DAG for multiple server deployments
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $continueResult= $Host.UI.PromptForChoice("Exchange Database Availability Group not found.","Do you want to continue?", $yesNoOption, 0)
    if($continueResult -eq 0) {
        Write-Warning "You should verify the DAG exists prior to starting the next step"
        return $true
    }
    return $false
}
function CheckNewDeployment {
    ## If this is a new deployment of multiple servers we may not was to validate the DAG
    $validDag = Skip-DagCheck
    if($validDag -eq $false) {
        CreateNewDAG 
    }
    else {
        $DagName = Read-HostWithColor "Enter the Database Availability Group name: "
        Add-Content -Path $serverVarFile -Value ('DagName = ' + $DagName)
    }
}
function CreateServerVariableFile {
    ## Create psd1 with variables for the VM to use for setup
    $serverVarFileName = "c:\Temp\$ServerName-ExchangeInstall-strings.psd1"
    if(Get-Item $serverVarFileName -ErrorAction Ignore) {Remove-Item $serverVarFileName -Confirm:$false -ErrorAction Ignore -Force}
    New-Item -Name "Temp" -ItemType Directory -Path "c:\" -ErrorAction SilentlyContinue | Out-Null
    New-Item $serverVarFileName -ItemType File -ErrorAction SilentlyContinue | Out-Null
    Add-Content -Path $serverVarFileName -Value "ConvertFrom-StringData @'"
    Add-Content -Path $serverVarFileName -Value '###PSLOC'
    Add-Content -Path $serverVarFileName -Value 'ServerType = 0'
    return $serverVarFileName
}
#region Start script
[string]$ServerName = $env:COMPUTERNAME
$serverVarFile = CreateServerVariableFile
Add-Content -Path $serverVarFile -Value ('ServerName = ' + $ServerName)
Write-Warning "You will have the option to download the Exchange installation files if they aren't already available."
Add-Type -AssemblyName System.Windows.Forms
#endregion
#region Server core check
$isServerCore = CheckServerCore
if($isServerCore -eq $true -and $SetupExePath -like $null) {
        Write-Warning "You must specify the setup path when running Server Core."
        Remove-Item -Path $serverVarFile -Force
        Start-Sleep -Seconds 3
        break
}
#endregion
#region AD PowerShell module check
Write-Host "Checking for prerequisites..." -ForegroundColor Green
if(!(Get-WindowsFeature RSAT-AD-PowerShell).Installed) {
    Write-Host "Installing Active Directory PowerShell module..." -ForegroundColor Green
    Install-WindowsFeature -Name RSAT-AD-PowerShell | Out-Null
}
#endregion
#region Get admin credentials
#$validUPN = $false
$domain = $env:USERDNSDOMAIN
$UserName = $env:USERNAME
$upn = "$UserName@$domain"
$credential = Get-Credential -UserName $upn -Message "Domain admin credentials"
[string]$domainController = (Resolve-DnsName $domain -Type SRV -Server $tempDNS -ErrorAction Ignore).PrimaryServer
$Password = $credential.GetNetworkCredential().Password
## Check if the account is a member of domain admins
Write-Host "Checking account permissions..." -ForegroundColor Green
Write-Host "Using $UserName from the $Domain domain for the install" -ForegroundColor Cyan
$isDomainAdmin = $false
Get-ADGroupMember "Domain Admins" | ForEach-Object { if((Get-ADObject $_ -Properties SamAccountName).SamAccountName -eq $UserName) { $isDomainAdmin = $true }}
if($isDomainAdmin -eq $false) {
    Write-Warning "Your account is not a member of the Domain Admins group. Please update group membership prior to running the next step."
    Start-Sleep -Seconds 2
}
## Check if the account is a member of schema admins
$isSchemaAdmin = $false
Get-ADGroupMember "Schema Admins" | ForEach-Object { if((Get-ADObject $_ -Properties SamAccountName).SamAccountName -eq $UserName) { $isSchemaAdmin = $true }}
if($isSchemaAdmin -eq $false) {
    Write-Host "Your account is not a member of the Schema Admins group. Please update group membership or ensure the schema has been updated prior to running the next step." -ForegroundColor Red
    Start-Sleep -Seconds 2
}
Add-Content -Path $serverVarFile -Value ('DomainPassword = ' + $Password)
Add-Content -Path $serverVarFile -Value ('Domain = ' + $domain)
Add-Content -Path $serverVarFile -Value ('DomainController = ' + $domainController)
Add-Content -Path $serverVarFile -Value ('Username = ' + $UserName)
#endregion
#region Exchange organization and recover server check
$askForCertificateLater = $true
$exchServer = $null
$exchOrgPresent = $false
Import-Module ActiveDirectory
$exchServer = $null
$exInstallType = 0
$adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
Write-Host "Checking for an Exchange organization..." -ForegroundColor Green
$servicesContainer = "CN=Services,CN=Configuration,$adDomain"
$exchContainer = (Get-ADObject -LDAPFilter "(objectClass=msExchConfigurationContainer)" -SearchBase $servicesContainer -SearchScope OneLevel -ErrorAction Ignore).DistinguishedName
if($exchContainer -notlike $null) {
    $exchServersContainer = Get-ADObject -LDAPFilter "(objectClass=msExchServersContainer)" -SearchBase $exchContainer -SearchScope Subtree -ErrorAction Ignore | Where-Object {$_.DistinguishedName -like "*FYDIBOHF23*"}
    if($exchServersContainer.DistinguishedName.Length -gt 0) {
        Write-Host "Checking for existing Exchange servers..." -ForegroundColor Green
        $exchServers = Get-ADObject -LDAPFilter "(objectClass=msExchExchangeServer)" -SearchBase $exchServersContainer -SearchScope OneLevel -Properties msExchCurrentServerRoles
        if($exchServers -notlike $null) {
            $exchOrgPresent = $true
            if($exchServers -match $ServerName) {
                Write-Warning "This is a recover server"
                $exInstallType = 1
            }
            $serverFound = $false
            while($serverFound -eq $false) {
                $exchServer = Get-Random -InputObject $exchServers -Count 1
                if($exchServer.Name -ne $ServerName -and $exchServer.msExchCurrentServerRoles -ne 64) {
                    if(Test-Connection $exchServer.Name -Count 1 -ErrorAction Ignore) { $serverFound = $true }                 
                }
            }
        }
    }
    else { Write-Host "No Exchange organization found." -ForegroundColor Green  }
    $exchServer = $exchServer.Name
}
Add-Content -Path $serverVarFile -Value ('ExchangeInstallType = ' + $exInstallType)
#endregion
#region Connect to remote PowerShell
## Check for an Exchange management session, otherwise verify there is no Exchange organization in the forest
if(!(Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" } )) {
    if($exchOrgPresent -eq $true) { Connect-Exchange }
    else {
        Add-Content -Path $serverVarFile -Value ('ExchangeOrgMissing = 1')
        ## Prompt the user for an Exchange server to setup a remote PowerShell session
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
        $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
        $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $newOrgResult= $Host.UI.PromptForChoice("Server deployment script","Would you like to create a new Exchange organization?", $yesNoOption, 0)
        if($newOrgResult -eq 0) { 
            $exOrgName = Read-HostWithColor "Enter the name for the new Exchange organization: "
            Add-Content -Path $serverVarFile -Value ('ExchangeOrgName = ' + $exOrgName)
        }
    }
}
else { $exchServer = (Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" } | Select-Object -Last 1).ComputerName }
#endregion
#region Exchange install prompts
switch ($exInstallType) {
    0 { $exReady = $false
        while($exReady -eq $false) {
            ## Get the Exchange version
            $exVersion = Select-ExchangeVersion
            ## Get the latest version of Exchange in the forest
            if($exchOrgPresent -eq $true) {
                $currentVersion = CheckExchangeVersion
            }
            ## New forest - set current version less than 2013
            else { $currentVersion = -1 }
            ## Check to see if a version of Exchange is being skipped
            if(((($exVersion -ne $currentVersion -and $exVersion-$currentVersion) -gt 1)) -or ($exchOrgPresent -eq $false -and $exVersion -gt 0)) {
                Write-Warning "One or more versions of Exchange is not installed"
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $exContinue = $Host.UI.PromptForChoice("Server deployment script","Would you like to continue?", $yesNoOption, 0)
                if($exContinue -eq 0) {
                    $exReady = $true
                }
            }
            else { $exReady = $true }
        }
        ## Get the setup path for the Exchange install
        if($SetupExePath -like $null) { 
            Write-Warning "You must download the ISO before running this script."
            PromptExchangeDownload
            $SetupExePath = Get-ExchangeExe
        }
        else{
            $SetupExePath = $SetupExePath.Replace("\","\\")
            Add-Content -Path $serverVarFile -Value ('ExchSetupPath = ' + $SetupExePath)
        }
        switch ($exVersion) {
            2 { $exMbxRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Mailbox', 'Mailbox server role'
                $exEdgeRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Edge Transport', 'Edge Transport server role'
                $exRoleOption = [System.Management.Automation.Host.ChoiceDescription[]]($exMbxRole, $exEdgeRole)
                $exRoleResult = $Host.UI.PromptForChoice("Server deployment script","What Exchange server roles should be installed:", $exRoleOption, 0)
                Add-Content -Path $serverVarFile -Value ('ExchangeRole = ' + $exRoleResult)
            }
            1 { $exMbxRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Mailbox', 'Mailbox server role'
                $exEdgeRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Edge Transport', 'Edge Transport server role'
                $exRoleOption = [System.Management.Automation.Host.ChoiceDescription[]]($exMbxRole, $exEdgeRole)
                $exRoleResult = $Host.UI.PromptForChoice("Server deployment script","What Exchange server roles should be installed:", $exRoleOption, 0)
                Add-Content -Path $serverVarFile -Value ('ExchangeRole = ' + $exRoleResult)
            }
            0{  $exAllRoles = New-Object System.Management.Automation.Host.ChoiceDescription '&All', 'All roles'
                $exMbxRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Mailbox', 'Mailbox server role'
                $exCasRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Client Access', 'Client Access server role'
                $exEdgeRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Edge Transport', 'Edge Transport server role'
                $exRoleOption = [System.Management.Automation.Host.ChoiceDescription[]]($exAllRoles, $exMbxRole, $exCasRole, $exEdgeRole)
                $exRoleResult = $Host.UI.PromptForChoice("Server deployment script","What Exchange server roles should be installed:", $exRoleOption, 0)
                Add-Content -Path $serverVarFile -Value ('ExchangeRole = ' + $exRoleResult)
                ## Ask which version of Microsoft .NET Framework to install
                $seven = New-Object System.Management.Automation.Host.ChoiceDescription '.NET 4.&7.2', '4.7.2'
                $eight = New-Object System.Management.Automation.Host.ChoiceDescription '.NET 4.&8', '4.8'
                $dotNetOption = [System.Management.Automation.Host.ChoiceDescription[]]($eight, $seven)
                $dotNetResult = $Host.UI.PromptForChoice("Server deployment script","Which version of the Microsoft .NET Framework do you want to instll?", $dotNetOption, 0)
                Add-Content -Path $serverVarFile -Value ('DotNetResult = ' + $dotNetResult)
            }
        }
        ## Check if the certificate from the remote PowerShell session Exchange server should be used
        if($exchOrgPresent) {
            if(Get-CertificateFromServerCheck) {
                ## Need to fix the next line
                if($exchServer -like "*.*") { $certServer = $exchServer.Substring(0, $exchServer.IndexOf(".")) }
                else { $certServer = $exchServer }
                [string]$thumb = Get-ServerCertificate
            }
        }
        ## Get hostname values for the Exchange virtual directories

        $intHostname = (Read-HostWithColor "Enter the hostname for the internal URLs: ").ToLower()
        Add-Content -Path $serverVarFile -Value ('internalHostname = ' + $intHostname)
        $extHostname = (Read-HostWithColor "Enter the hostname for the external URLs: ").ToLower()
        Add-Content -Path $serverVarFile -Value ('externalHostname = ' + $extHostname)
        ## Check whether the Exchange server should be added to an existing DAG, a new DAG, or none
        $ExistingDag = New-Object System.Management.Automation.Host.ChoiceDescription '&Existing', 'Existing'
        $NewDag = New-Object System.Management.Automation.Host.ChoiceDescription '&New', 'New'
        $NoDag = New-Object System.Management.Automation.Host.ChoiceDescription '&Standalone', 'None'
        $dagOption = [System.Management.Automation.Host.ChoiceDescription[]]($ExistingDag, $NewDag, $NoDag)
        $dagResult = $Host.UI.PromptForChoice("Server deployment script","Would you like to join and existing DAG, create a new DAG, or make a standalone server?", $dagOption, 0)
        Add-Content -Path $serverVarFile -Value ('DagResult = ' + $dagResult)
        switch ($dagResult) {
            0 { ## Join a DAG if Exchange is present otherwise create a DAG
                if($exchOrgPresent -eq $true) {
                    ## Look for existing DAG and so admin can see what is available
                    if(Get-DatabaseAvailabilityGroup) {
                        Get-DatabaseAvailabilityGroup | Format-Table Name
                        $validDag = $false
                        while($validDag -eq $false) {
                            $DagName = Read-HostWithColor "Enter the Database Availability Group name: "
                            $validDag = ValidateDagName
                            if($validDag -eq $false) {
                                $validDag = Skip-DagCheck
                            }
                        }
                        Add-Content -Path $serverVarFile -Value ('DagName = ' + $DagName)
                    }
                    ## Create a new DAG if there is no DAG in the environment or skip for deploying multiple servers
                    else { CheckNewDeployment }
                }
                ## Cannot verify DAG so either create a new DAG or join a DAG for new deployments
                else { CheckNewDeployment }
            }
            1 { ## Get information for the new DAG
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                $dagTypeOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $dagType = $Host.UI.PromptForChoice("Server deployment script","Do you want to create the DAG without an administrative access point? (aka:IP-less)", $dagTypeOption, 0)
                Add-Content -Path $serverVarFile -Value ('DagType = ' + $dagType)
                CreateNewDAG
                if($dagType -eq 1) {
                    Get-DAGIPAddress
                }
            }
        }
    }
    1 { ## Determine what version of Exchange the server has installed
        $exVersion = (Get-ExchangeServer $ServerName).AdminDisplayVersion
        $exVersion = $exVersion.Substring(11,1)
        switch($exVersion) {
            0 {Add-Content -Path $serverVarFile -Value ('ExchangeVersion = 0')}
            1 {Add-Content -Path $serverVarFile -Value ('ExchangeVersion = 1')}
            2 {Add-Content -Path $serverVarFile -Value ('ExchangeVersion = 2')}
        }
        ## Get the ISO for Exchange install
        if($SetupExePath -like $null) { 
            PromptExchangeDownload
            Get-ExchangeExe
        }
        else{
            $SetupExePath = $SetupExePath.Replace("\","\\")
            Add-Content -Path $serverVarFile -Value ('ExchSetupPath = ' + $SetupExePath)
        }
        ## Clearing Edge Sync credentials to allow server to be recovered that is part of an Edge subscription
            Write-Host "Checking for Edge subscription..." -ForegroundColor Green -NoNewline
            $serverSite = (Get-ExchangeServer $ServerName).Site
            Get-EdgeSubscription | ForEach-Object {
                if($_.Site -eq $serverSite) {
                    Write-Host "FOUND"
                    $serverSite = $serverSite.Substring($serverSite.IndexOf("/Sites/")+7)
                    Add-Content -Path $serverVarFile -Value ('EdgeDomain = ' + $_.Domain)
                    Add-Content -Path $serverVarFile -Value ('EdgeName = ' + $_.Name)
                    Add-Content -Path $serverVarFile -Value ('EdgeSite = ' + $serverSite)
                    Write-Host "Removing existing Edge sync credentials..." -ForegroundColor Green -NoNewline
                    $dc = (Get-ExchangeServer $ServerName).OriginatingServer
                    [int]$startChar = $ServerName.Length + 4
                    $searchBase = (Get-ExchangeServer $ServerName).DistinguishedName
                    $searchBase = $searchBase.Substring($startChar)
                    Get-ADObject -SearchBase $searchBase -Filter 'cn -eq $ServerName' -SearchScope OneLevel -Properties msExchEdgeSyncCredential -Server $domainController -Credential $credential | Set-ADObject -Clear msExchEdgeSyncCredential -Server $domainController -Credential $credential
                    Write-Host "COMPLETE"
                    $EdgeAdmin = Read-HostWithColor "Enter the admin username for the Edge server ($($_.Name): "
                    $EdgePassword = Read-Host "Enter the admin password for the Edge server ($($_.Name)) " -AsSecureString
                    $EdgePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EdgePassword))
                    Add-Content -Path $serverVarFile -Value ('EdgeAdmin = ' + $EdgeAdmin)
                    Add-Content -Path $serverVarFile -Value ('EdgePassword = ' + $EdgePassword)
                }
            }
        ## Check if the servers was offline and if we need the certificate
        if($askForCertificateLater) {
            if(Get-CertificateFromServerCheck) {
                if($exchServer -like "*.*") {
                    $certServer = $exchServer.Substring(0, $exchServer.IndexOf("."))
                }
                else { $certServer = $exchServer }
                [string]$thumb = Get-ServerCertificate
            }
        }
        ##Check if the Exchange server is a member of a DAG
        Write-Host "Checking if the Exchange server is a member of a DAG..." -ForegroundColor Green -NoNewline
        if(Get-DatabaseAvailabilityGroup -DomainController $domainController | Where-Object { $_.Servers -match $ServerName }) {
            Write-Host "MEMBER"
            [string]$DagName = Get-DatabaseAvailabilityGroup -DomainController $domainController  | Where-Object { $_.Servers -like '*' + $ServerName + '*'}
            Add-Content -Path $serverVarFile -Value ('DagName = ' + $DagName)
            ## Check if the databases have multiple copies
            $dbHasCopies = $false
            Write-Host "Checking if the databases for this server have multiple copies..." -ForegroundColor Green
            Get-MailboxDatabase -Server $ServerName | ForEach-Object {
                if($_.ReplicationType -eq "Remote") {
                    $dbHasCopies = $true
                    ## Check the number of copies of the database
                    if(((Get-MailboxDatabase $_.Name).AllDatabaseCopies).count -eq 2){
                        if((Get-MailboxDatabase $_.Name).CircularLoggingEnabled) {
                            ## Need to disable circular logging before removing the database copy
                            Write-Host "Disabling circular logging for this $_.Name..." -ForegroundColor Green -NoNewline
                            Set-MailboxDatabase $_.Name -CircularLoggingEnabled:$False -Confirm:$False | Out-Null
                            Write-Host "COMPLETE"
                        }
                    }
                    ## Get a list of databases and the replay lag times for the Exchange server
                    $replayLagTime = [string](Get-MailboxDatabase $_.Name | Where-Object {$_.ReplayLagTimes -like "*$ServerName*" }).ReplayLagTimes
                    $_.Name + "," + $replayLagTime | Out-File "c:\Temp\$ServerName-DatabaseCopies.txt" -Append
                    ## Get the current activation preferences for the mailbox databases in the DAG
                    $activationPreference = [string](Get-MailboxDatabase $_.Name | Select-Object Name -ExpandProperty ActivationPreference)
                    $_.Name + "," + $activationPreference | Out-File "c:\Temp\$ServerName-$DagName-ActivationPreferences.txt" -Append
                    ## Check if the database is mounted on this server
                    $dbMounted = $true
                    while($dbMounted -eq $true) {
                        $dbMounted = Get-MailboxDatabaseStatus $_.Name 
                        if($dbMounted -eq $true) {
                            [int]$moveAttempt = 0
                            $moveComplete = (Move-MailboxDatabase $_.Name)
                            while($moveAttempt -lt 6) {
                                if($moveComplete -eq $false) {
                                    if ($moveAttempt -eq 5) {
                                        Write-Warning "Failed to move the database copy to another server."
                                        exit
                                    }
                                    Get-MailboxDatabaseCopyStatus $_.Name | Format-Table Name,Status,CopyQueueLength,ReplayQueueLength,ContentIndexState
                                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                                    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                                    $moveOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                                    $moveResult= $Host.UI.PromptForChoice("Server deployment script","Do you want to attempt to move the database with best effort?", $moveOption, 0)
                                    if($moveResult -eq 0) {
                                        Start-Sleep -Seconds 3
                                        $moveAttempt++
                                        $moveComplete = (Move-MailboxDatabaseBestEffort $_.Name)
                                    }
                                }
                                else { break }
                            }
                        }
                    }
                    ## Remove existing database copies and then remove server from DAG
                    Write-Host "Removing database copy for $_ from the server..." -ForegroundColor Green -NoNewline
                    $dbCopy = $_.Name + "\$ServerName"
                    Remove-MailboxDatabaseCopy $dbCopy -DomainController $domainController -Confirm:$False | Out-Null
                    Write-Host "COMPLETE"
                }
            }
            if($dbHasCopies -eq $true) { Add-Content -Path $serverVarFile -Value ('DbHasCopies = 1') }
            ##Remove the Exchange server from the database availability group
            Write-Host "Checking DAC mode for the DAG..." -ForegroundColor Green -NoNewline
            if((Get-DatabaseAvailabilityGroup $DagName -DomainController $domainController ).DatacenterActivationMode -eq "DagOnly") {
                Write-Host "DagOnly"
                Add-Content -Path $serverVarFile -Value ('DatacenterActivationMode = DagOnly')
                Write-Host "Checking the number of servers in the DAG..." -ForegroundColor Green
                if((Get-DatabaseAvailabilityGroup -DomainController $domainController ).Servers.Count -eq 2) {
                    Write-Host "Disabling datacenter activation mode..." -ForegroundColor Yellow
                    Set-DatabaseAvailabilityGroup $DagName -DatacenterActivationMode Off -DomainController $domainController -Confirm:$False | Out-Null
                }
            }
            else { 
                Write-Host "OFF"
                Add-Content -Path $serverVarFile -Value ('DatacenterActivationMode = Off')
            }
            Write-Host "Removing server from the DAG..." -ForegroundColor Green -NoNewline
            if($serverOnline -eq $true) {
                Remove-DatabaseAvailabilityGroupServer $DagName -MailboxServer $ServerName -DomainController $domainController -Confirm:$False -ErrorAction Ignore
            }
            else {
                Remove-DatabaseAvailabilityGroupServer $DagName -MailboxServer $ServerName -DomainController $domainController -ConfigurationOnly -Confirm:$False -ErrorAction Ignore
                Start-Sleep -Seconds 5
                Write-Host "COMPLETE"
                Write-Host "Removing $ServerName from the Windows cluster..." -ForegroundColor Green -NoNewline
                $scriptBlock = { Param ($param1) Remove-ClusterNode -Name $param1 -Force -ErrorAction Ignore }
                Invoke-Command -ScriptBlock $scriptBlock -ComputerName $exchServer -ArgumentList $ServerName
            }
            Write-Host "COMPLETE"
            ## Check if the remove succeeded
            if((Get-DatabaseAvailabilityGroup $DagName -DomainController $domainController).Servers -notcontains $serverName) {
                ## Synchrnoize Active Directory so all sites are aware of the change
                Write-Host "Synchronizing Active Directory with the latest changes..." -ForegroundColor Green -NoNewline
                Sync-AdConfigPartition
                Write-Host "COMPLETE"
                ## Verify the Exchange server is no longer a member of the DAG in each AD site
                $domainControllers = New-Object System.Collections.ArrayList
                $domainControllers = Get-DomainControllers
                $domainControllers | ForEach-Object { 
                    $serverFound = $true
                    Write-Host "Checking for $serverName in $DagName on $_..." -ForegroundColor Green -NoNewline
                    while($serverFound -eq $true) {
                        if((Get-DatabaseAvailabilityGroup $DagName -DomainController $_ -ErrorAction Ignore).Servers -contains $serverName) {
                            Write-Host "..." -ForegroundColor Green -NoNewline
                            Sync-AdConfigPartition
                            Start-Sleep -Seconds 10
                        }
                        else {
                            Write-Host "COMPLETE"
                            $serverFound = $false
                        }
                    }
                }
            }
            else {
                Write-Host "Failed to remove $ServerName from $DagName. You can attempt to resolve the issue and try again later." -ForegroundColor Red
                ## Script failed to remove the server from the DAG so we are removing it from the VM list and deleting files
                Remove-Item -Path c:\Temp\$ServerName* -Force
            }
        }
        else {
            Write-Host "STANDALONE"
        }
    }
}
#endregion
#region Extended Protection
$yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
$no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
$yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$extendedProtectionEnabled = $Host.UI.PromptForChoice("Server deployment script","Do you want to enable Exchange Extended Protection?", $yesNoOption, 0)
switch ($extendedProtectionEnabled) {
    0 {Add-Content -Path $serverVarFile -Value ('ExchangeExtendedProtection = 0')}
    1 {Add-Content -Path $serverVarFile -Value ('ExchangeExtendedProtection = 1')}
}
#endregion
#region Exchange certificate    
if($thumb.Length -gt 1) {
    ## Export the Exchange certificate
    Write-Host "Exporting current Exchange certificate with thumbprint $thumb from $certServer..." -ForegroundColor Green -NoNewline
    ## Need to check for c:\Temp
    New-Item -ItemType Directory -Path "\\$exchServer\c$\Temp" -ErrorAction Ignore | Out-Null
    $cert = Export-ExchangeCertificate -Server $exchServer -Thumbprint $thumb -BinaryEncoded -Password (ConvertTo-SecureString -String 'Pass@word1' -AsPlainText -Force)
    Set-Content -Path "c:\Temp\$ServerName-Exchange.pfx" -Value $cert.FileData -Encoding Byte
    Write-Host "COMPLETE"
}
#endregion
#region Finalize the psd1 file
Add-Content -Path $serverVarFile -Value ('RunFromServer = ' + $exchServer)
Add-Content -Path $serverVarFile -Value '###PSLOC'
Add-Content -Path $serverVarFile -Value "'@"
#endregion
#region Close PSSession
Write-Host "Removing the Exchange remote PowerShell session..." -ForegroundColor Green
Remove-PSSession -Name ExchangeShell -ErrorAction Ignore
#endregion
#region Prepare for Exchange install
Write-Host "Getting variables for setup..." -ForegroundColor Green -NoNewline
Import-LocalizedData -BindingVariable ExchangeInstall_LocalizedStrings -FileName $ServerName"-ExchangeInstall-strings.psd1" -BaseDirectory c:\Temp
Write-Host "COMPLETE"
#region Enable AutoLogon
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
$WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
## Set AutoLogon for the next step
Write-Host "Preparing server for the next step..." -ForegroundColor Green -NoNewline
Set-ItemProperty -Path $RunOnceKey -Name "JoinDomain" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployVMASServer-Step2.ps1')
Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ExchangeInstall_LocalizedStrings.Domain
Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $ExchangeInstall_LocalizedStrings.Username
Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $ExchangeInstall_LocalizedStrings.DomainPassword
Write-Host "COMPLETE"
#endregion
## Enable Remote Desktop
Write-Host "Enabling remote desktop on the server..." -ForegroundColor Green -NoNewline
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host "COMPLETE"
if($isServerCore -eq $false) {
    ## Disable IE Enhance Security Configuration
    Write-Host "Disabling IE Enhanced security configuration..." -ForegroundColor Green -NoNewline
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
    Write-Host "COMPLETE"
}
#region Create batch file for setup
$domainController = $ExchangeInstall_LocalizedStrings.DomainController
$exInstallPath = $ExchangeInstall_LocalizedStrings.ExchSetupPath
$exResult = $ExchangeInstall_LocalizedStrings.ExchangeVersion
## Create batch file for the Exchange install
Write-Host "Creating the Exchange setup script..." -ForegroundColor Green -NoNewline
$installBat = "c:\Temp\exSetup.bat"
if(Get-Item $installBat -ErrorAction Ignore) {Remove-Item $installBat -ErrorAction Ignore -Force}
New-Item $installBat -ItemType File -ErrorAction SilentlyContinue | Out-Null
switch ($ExchangeInstall_LocalizedStrings.ExchangeInstallType) { ## Checking whether is install is new or recover
    0 { switch ($exResult) { ## Checking the version of Exchange to install
            2 { switch ($ExchangeInstall_LocalizedStrings.ExchangeRole) { ## Checking the roles to install for 2019
                    0 { if((Get-Item $SetupExePath -ErrorAction Ignore).VersionInfo.ProductVersion -ge "15.02.0986.005") {
                            $exSetupLine = ($exInstallPath + ' /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF')
                        }
                        else {$exSetupLine = ($exInstallPath + ' /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms')} 
                    }
                    1 { if((Get-Item $SetupExePath -ErrorAction Ignore).VersionInfo.ProductVersion -ge "15.02.0986.005") {
                            $exSetupLine =  ($exInstallPath + ' /mode:install /roles:et /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF')
                        }
                        else {$exSetupLine =  ($exInstallPath + ' /mode:install /roles:et /IAcceptExchangeServerLicenseTerms') }
                    }
                }
            }
            1 { switch ($ExchangeInstall_LocalizedStrings.ExchangeRole) { ## Checking the roles to install for 2016
                    0 { if((Get-Item $SetupExePath -ErrorAction Ignore).VersionInfo.ProductVersion -ge "15.01.2375.007") {
                            $exSetupLine =  ($exInstallPath + ' /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF') 
                        }
                        else {$exSetupLine =  ($exInstallPath + ' /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms')}
                    }
                    1 { if((Get-Item $SetupExePath -ErrorAction Ignore).VersionInfo.ProductVersion -ge "15.01.2375.007") {
                            $exSetupLine =  ($exInstallPath + ' /mode:install /roles:et /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF')
                        }
                        else{$exSetupLine =  ($exInstallPath + ' /mode:install /roles:et /IAcceptExchangeServerLicenseTerms')} 
                    }
                }
            }
            0 { switch ($ExchangeInstall_LocalizedStrings.ExchangeRole) { ## Checking the roles to install for 2013
                    0 { $exSetupLine =  ($exInstallPath + ' /mode:install /roles:mb,ca /IAcceptExchangeServerLicenseTerms') }
                    1 { $exSetupLine =  ($exInstallPath + ' /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms') }
                    2 { $exSetupLine =  ($exInstallPath + ' /mode:install /roles:ca /IAcceptExchangeServerLicenseTerms') }
                    3 { $exSetupLine =  ($exInstallPath + ' /mode:install /roles:et /IAcceptExchangeServerLicenseTerms') }
                }
            }
        }
        if($ExchangeInstall_LocalizedStrings.ExchangeOrgMissing -eq 1 -and $null -ne $ExchangeInstall_LocalizedStrings.ExchangeOrgName) {
        $exSetupLine = $exSetupLine + " /OrganizationName:" + $ExchangeInstall_LocalizedStrings.ExchangeOrgName
    }
    Add-Content -Path $installBat -Value $exSetupLine
    }
    1 { Add-Content -Path $installBat -Value ($exInstallPath + ' /mode:recoverserver /IAcceptExchangeServerLicenseTerms') } ## Exchange recover server
}
Write-Host "COMPLETE"
#endregion
#region Install Windows prequisite roles and features
Write-Host "Installing required Windows features for Exchange..." -ForegroundColor Green -NoNewline
switch ($ExchangeInstall_LocalizedStrings.ExchangeVersion) { ## Checking the version of Exchange
    0 { Install-WindowsFeature Server-Media-Foundation, Failover-Clustering,RSAT-ADDS,NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation }
    1 { Install-WindowsFeature Server-Media-Foundation, Failover-Clustering,RSAT-ADDS,NET-Framework-45-Core, NET-Framework-45-ASPNET, NET-WCF-HTTP-Activation45, NET-WCF-Pipe-Activation45, NET-WCF-TCP-Activation45, NET-WCF-TCP-PortSharing45, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation }
    2 { if($ExchangeInstall_LocalizedStrings.ServerCore -eq 1) {Install-WindowsFeature Server-Media-Foundation, Failover-Clustering,RSAT-ADDS,NET-Framework-45-Core, NET-Framework-45-ASPNET, NET-WCF-HTTP-Activation45, NET-WCF-Pipe-Activation45, NET-WCF-TCP-Activation45, NET-WCF-TCP-PortSharing45, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Metabase, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI}
        else {Install-WindowsFeature Server-Media-Foundation, Failover-Clustering,RSAT-ADDS,NET-Framework-45-Core, NET-Framework-45-ASPNET, NET-WCF-HTTP-Activation45, NET-WCF-Pipe-Activation45, NET-WCF-TCP-Activation45, NET-WCF-TCP-PortSharing45, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation}}
}
Write-Host "COMPLETE"
Restart-Computer -Force
#endregion
#endregion
