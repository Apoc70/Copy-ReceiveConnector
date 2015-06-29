<# 
    .SYNOPSIS 
    Copy a selected receive connector and it's configuration and permissions to other Exchange Servers

    Thomas Stensitzki 

    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE  
    RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER. 

    Version 1.2, 2015-06-29

    Please send ideas, comments and suggestions to support@granikos.eu 

    .LINK 
    More information can be found at http://www.granikos.eu/en/scripts

    .DESCRIPTION 
    This script copies a receive connector from a source Exchange Server to a single target
    Exchange server or to all Exchange servers.
    
    Configured permissions are copied as well 
 
    .NOTES 
    Requirements 
    - Windows Server 2008 R2 SP1, Windows Server 2012 or Windows Server 2012 R2  
    
    Revision History 
    -------------------------------------------------------------------------------- 
    1.0      Initial community release 
    1.1      Domain Controller parameter added, permissions group copy added
    1.2      Move to FrontendTransport added, optional permission copy added, reset bindings added 

    .PARAMETER ConnectorName  
    Name of the connector the new IP addresses should be added to  

    .PARAMETER SourceServer
    Name of the receive connector to copy

    .PARAMETER TargetServer
    Target Exchange server to copy the selected receive connector to

    .PARAMETER DomainController
    Domain Controller name

    .PARAMETER CopyToAllOther
    Switch to copy to all other Exchange servers

    .PARAMETER CopyPermissions
    Copy non inherited source receive AD permissions to target receive connector. Inherited permissions will not be copied

    .PARAMETER MoveToFrontend
    Change source connector transport role to FrontendTransport. This is required when you copy a receive connector from Exchange 2007 to Exchange 2013

    .PARAMETER ResetBindings
    Do not copy bindings but reset receive connector network bindings to 0.0.0.0:25

    .PARAMETER ViewEntireForest
    View entire Active Directory forest

    .EXAMPLE 
    Copy Exchange 2013 receive connector nikos-one-RC2 from server MBX01 to server MBX2
    .\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName nikos-one-RC2 -TargetServer MBX2 -DomainController MYDC1.mcsmemail.de

    .EXAMPLE 
    Copy Exchange 2013 receive connector nikos-one-RC2 from server MBX01 to all other Exchange 2013 servers 
    .\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName nikos-one-RC1 -CopyToAllOther -DomainController MYDC1.mcsmemail.de

    .EXAMPLE 
    Copy Exchange 2013 receive connector "nikos-two relay" from Exchange 2007 server MBX2007 to Exchange 2013 server MBX01 and reset network bindings 
    .\Copy-ReceiveConnector.ps1 -SourceServer MBX2007 -ConnectorName "nikos-two relay" -TargetServer MBX01 -MoveToFrontend -ResetBindings -DomainController MYDC1.mcsmemail.de 
#> 

param(
	[parameter(Mandatory=$true,HelpMessage='Source Exchange server to copy from')]
		[string] $SourceServer,
	[parameter(Mandatory=$true,HelpMessage='Name of the receive connector to copy')]
		[string] $ConnectorName,
	[parameter(Mandatory=$false,HelpMessage='Target Exchange server to copy the selected receive connector to')]
		[string] $TargetServer = "",
	[parameter(Mandatory=$true,HelpMessage='Domain Controller name')]
		[string] $DomainController = "",
    [parameter(Mandatory=$false,HelpMessage='Copy to all other Exchange servers')]
        [switch] $CopyToAllOther,
    [parameter(Mandatory=$false,HelpMessage='Copy non inherited source receive AD permissions to target receive connector')]
        [switch] $CopyPermissions,
    [parameter(Mandatory=$false,HelpMessage='Move receive connector to FrontEnd transport (i.e. Exchange 2007 -> Exchange 2013)')]
        [switch] $MoveToFrontend,
    [parameter(Mandatory=$false,HelpMessage='Reset network bindings to listen on all adapters on port 25')]
        [switch] $ResetBindings,
    [parameter(Mandatory=$false,HelpMessage='View entire forest')]
        [switch] $ViewEntireForest
)

Set-StrictMode -Version Latest

Import-Module ActiveDirectory 

$sourceRC = $null
$secondsToWait = 60

### FUNCTIONS -----------------------------

function CopyToServer {
    param(
        [string]$TargetServerName
    )

    $sourceRC = Get-ReceiveConnector -Server $SourceServer | ?{$_.Name -eq $ConnectorName} -ErrorAction SilentlyContinue

    $targetRC = Get-ReceiveConnector -Server $TargetServerName | ?{$_.Name -eq $ConnectorName} -ErrorAction SilentlyContinue

    if(($sourceRC -ne $null) -and ($targetRC -eq $null)){

        Write-Host "Adding new receive connector $($ConnectorName) to $($TargetServerName)"

        # clear permission groups for Exchange Server 2013 (thanks to Jeffery Land, https://jefferyland.wordpress.com)
        $tempPermissionGroups = @($sourceRC.PermissionGroups) -split ", " | Select-String -Pattern "Custom" -NotMatch
        $temp = "$($tempPermissionGroups)"
        $sourceRC.PermissionGroups = $temp.Replace(" ", ", ")

        if($MoveToFrontend) {
            # Move receive connector to FrontEnd Transpport
            $sourceRC.TransportRole = "FrontendTransport"
        }

        if($ResetBindings) {
            # Reset network bindungs to listen on all adapters using port 25
            $sourceRC.Bindings = "0.0.0.0:25"
        }

        # create new Receive Connector
        New-ReceiveConnector -Name $sourceRC.Name `
        -TransportRole $sourceRC.TransportRole `
        -RemoteIPRanges $sourceRC.RemoteIPRanges `
        -Bindings $sourceRC.Bindings `
        -Banner $sourceRC.Banner `
        -ChunkingEnabled $sourceRC.ChunkingEnabled `
        -DefaultDomain $sourceRC.DefaultDomain `
        -DeliveryStatusNotificationEnabled $sourceRC.DeliveryStatusNotificationEnabled `
        -EightBitMimeEnabled $sourceRC.EightBitMimeEnabled `
        -DomainSecureEnabled $sourceRC.DomainSecureEnabled `
        -LongAddressesEnabled $sourceRC.LongAddressesEnabled `
        -OrarEnabled $sourceRC.OrarEnabled `
        -Comment $sourceRC.Comment `
        -Enabled $sourceRC.Enabled `
        -ConnectionTimeout $sourceRC.ConnectionTimeout `
        -ConnectionInactivityTimeout $sourceRC.ConnectionInactivityTimeout `
        -MessageRateLimit $sourceRC.MessageRateLimit `
        -MaxInboundConnection $sourceRC.MaxInboundConnection `
        -MaxInboundConnectionPerSource $sourceRC.MaxInboundConnectionPerSource `
        -MaxInboundConnectionPercentagePerSource $sourceRC.MaxInboundConnectionPercentagePerSource `
        -MaxHeaderSize $sourceRC.MaxHeaderSize `
        -MaxHopCount $sourceRC.MaxHopCount `
        -MaxLocalHopCount $sourceRC.MaxLocalHopCount `
        -MaxLogonFailures $sourceRC.MaxLogonFailures `
        -MaxMessageSize $sourceRC.MaxMessageSize `
        -MaxProtocolErrors $sourceRC.MaxProtocolErrors `
        -MaxRecipientsPerMessage $sourceRC.MaxRecipientsPerMessage `
        -PermissionGroups $sourceRC.PermissionGroups `
        -PipeliningEnabled $sourceRC.PipeLiningEnabled `
        -ProtocolLoggingLevel $sourceRC.ProtocolLoggingLevel `
        -RequireEHLODomain $sourceRC.RequireEHLODomain `
        -RequireTLS $sourceRC.RequireTLS `
        -EnableAuthGSSAPI $sourceRC.EnableAuthGSSAPI `
        -ExtendedProtectionPolicy $sourceRC.ExtendedProtectionPolicy `
        -SizeEnabled $sourceRC.SizeEnabled `
        -TarpitInterval $sourceRC.TarpitInterval `        -EnhancedStatusCodesEnabled  $sourceRC.EnhancedStatusCodesEnabled `        -Server $TargetServerName 

        if($CopyPermissions) {
            # fetch non inherited permissons from source connector
            $sourcePermissions = Get-ReceiveConnector -Identity $sourceRC | Get-ADPermission | where {$_.IsInherited -eq $false}

            # we wait some time for domain controller to get stuff done
            Write-Host "Wait $($secondsToWait) seconds for domain controller to update"
            Start-Sleep -Seconds $secondsToWait

            Write-Verbose "Adding AD permissions"

            # set access rights on target connector
            $sourcePermissions | foreach {
                 Get-ReceiveConnector "$($TargetServerName)\$($sourceRC.Name)" -DomainController $DomainController | Add-ADPermission -DomainController $DomainController -User $_.User -Deny:$_.Deny -AccessRights $_.AccessRights -ExtendedRights $_.ExtendedRights | Out-Null
            }
        }
    }
    else {
        Write-Output "Receive connector is null or target connector already exists, nothing to do here."
    }
}

function CopyToAllServers {
    Write-Verbose "Copy receive connector to all other Exchange 2013 servers"

    $frontendServers = Get-ExchangeServer | ?{($_.AdminDisplayVersion.Major -eq 15) -and (([string]$_.ServerRole).Contains("ClientAccess")) -and ($_.Name -ne $SourceServer)}
    
    foreach($server in $frontendServers){
        Write-Output "Adding to server: $server"
        CopyToServer -TargetServerName $server
    }

    Write-Verbose "Copying to all Exchange servers done"
}

### MAIN ----------------------------------

if($ViewEntireForest) {
    Write-Verbose "Setting ADServerSettings -ViewEntireForest $true"
    Set-ADServerSettings -ViewEntireForest $true
}

if((-not $CopyToAllOther) -and ($TargetServer -eq "")){
    Write-Output "You need to either specific a dedicated target server using the -TargetServer "
    Write-Output "attribute or select the -CopyToAllOther switch"
    break
}
elseif($TargetServer -ne ""){
    # Copy to a single Exchange server
    CopyToServer -TargetServerName $TargetServer  
}
elseif($CopyToAllOther){
    # Copy to all other Exchange 2013 servers
    CopyToAllServers
}