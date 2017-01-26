<# 
    .SYNOPSIS 
    Copy a selected receive connector and it's configuration and permissions to other Exchange Servers

    Thomas Stensitzki 

    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE  
    RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER. 

    Version 1.41, 2016-07-26

    Please send ideas, comments and suggestions to support@granikos.eu 

    .LINK 
    More information can be found at http://scripts.granikos.eu

    .DESCRIPTION 
    This script copies a receive connector from a source Exchange Server to a single target Exchange server or to all Exchange servers.
    
    Configured permissions are copied as well, if required
 
    .NOTES 
    Requirements 
    - Windows Server 2008 R2 SP1, Windows Server 2012 or Windows Server 2012 R2 
    - Exchange Server 2007/2010 
    - Exchange Server 2013/2016 
    
    Revision History 
    -------- ----------------------------------------------------------------------- 
    1.0      Initial community release 
    1.1      Domain Controller parameter added, permissions group copy added
    1.2      Move to FrontendTransport added, optional permission copy added, reset bindings added 
    1.3      Update receive connector, if receive connector exists
    1.4      Fix to handle connector updates properly
    1.41     Minor fixes and update for Exchange 2016

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
    Copy Exchange 2013/2016 receive connector nikos-one-RC2 from server MBX01 to server MBX2
    .\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName nikos-one-RC2 -TargetServer MBX2 -DomainController MYDC1.mcsmemail.de

    .EXAMPLE 
    Copy Exchange 2013/2016 receive connector nikos-one-RC2 from server MBX01 to all other Exchange 2013 servers 
    .\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName nikos-one-RC1 -CopyToAllOther -DomainController MYDC1.mcsmemail.de

    .EXAMPLE 
    Copy Exchange 2013/2016 receive connector "nikos-two relay" from Exchange 2007 server MBX2007 to Exchange 2013 server MBX01 and reset network bindings 
    .\Copy-ReceiveConnector.ps1 -SourceServer MBX2007 -ConnectorName "nikos-two relay" -TargetServer MBX01 -MoveToFrontend -ResetBindings -DomainController MYDC1.mcsmemail.de 
#> 

param(
	[parameter(Mandatory=$true,HelpMessage='Source Exchange server to copy from')]
		[string] $SourceServer,
	[parameter(Mandatory=$true,HelpMessage='Name of the receive connector to copy')]
		[string] $ConnectorName,
	[parameter(Mandatory=$false,HelpMessage='Target Exchange server to copy the selected receive connector to')]
		[string] $TargetServer = '',
	[parameter(Mandatory=$true,HelpMessage='Domain Controller name')]
		[string] $DomainController = '',
    [parameter(Mandatory=$false,HelpMessage='Copy to all other Exchange servers')]
        [switch] $CopyToAllOther,
    [parameter(Mandatory=$false,HelpMessage='Copy non inherited source receive AD permissions to target receive connector')]
        [switch] $CopyPermissions,
    [parameter(Mandatory=$false,HelpMessage='Move receive connector to FrontEnd transport (i.e. Exchange 2007 -> Exchange 2013/2016)')]
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

function Request-Choice {
    param([string]$Caption)
    $choices =  [System.Management.Automation.Host.ChoiceDescription[]]@('&Yes','&No')
    [int]$defaultChoice = 1

    $choiceReturn = $Host.UI.PromptForChoice($Caption, '', $choices, $defaultChoice)

    return $choiceReturn   
}

function Copy-ToServer {
    param(
        [string]$TargetServerName
    )

    $sourceRC = Get-ReceiveConnector -Server $SourceServer | Where-Object{$_.Name -eq $ConnectorName} -ErrorAction SilentlyContinue

    $targetRC = Get-ReceiveConnector -Server $TargetServerName | Where-Object{$_.Name -eq $ConnectorName} -ErrorAction SilentlyContinue

    if(($sourceRC -ne $null) -and ($targetRC -eq $null)){

        Write-Host
        Write-Host "Working on $($TargetServerName) and receive connector $($ConnectorName)"

        # clear permission groups for Exchange Server 2013 (thanks to Jeffery Land, https://jefferyland.wordpress.com)
        $tempPermissionGroups = @($sourceRC.PermissionGroups) -split ', ' | Select-String -Pattern 'Custom' -NotMatch
        $temp = ("$($tempPermissionGroups)").Replace(' ', ', ').Replace(' ','')

        if($temp -ne '') {
            $sourceRC.PermissionGroups = $temp
        }

        if($MoveToFrontend) {
            # Move receive connector to FrontEnd Transpport
            $sourceRC.TransportRole = 'FrontendTransport'
        }

        if($ResetBindings) {
            # Reset network bindungs to listen on all adapters using port 25
            $sourceRC.Bindings = '0.0.0.0:25'
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
        -TarpitInterval $sourceRC.TarpitInterval `        -EnhancedStatusCodesEnabled  $sourceRC.EnhancedStatusCodesEnabled `        -Server $TargetServerName `
        -AuthMechanism $sourceRC.AuthMechanism

        if($CopyPermissions) {
            # fetch non inherited permissons from source connector
            $sourcePermissions = Get-ReceiveConnector -Identity $sourceRC | Get-ADPermission | Where-Object {$_.IsInherited -eq $false}

            # we wait some time for domain controller to get stuff done
            Write-Host "Wait $($secondsToWait) seconds for domain controller to update"
            Start-Sleep -Seconds $secondsToWait

            Write-Verbose 'Adding AD permissions'

            # set access rights on target connector
            $sourcePermissions | foreach {
                 Get-ReceiveConnector "$($TargetServerName)\$($sourceRC.Name)" -DomainController $DomainController | Add-ADPermission -DomainController $DomainController -User $_.User -Deny:$_.Deny -AccessRights $_.AccessRights -ExtendedRights $_.ExtendedRights | Out-Null
            }
        }
    }
    elseif($sourceRC -ne $null) {
        Write-Output 'Target connector already exists.'
        
        if((Request-Choice -Caption "Do you want to UPDATE the receive connector $($ConnectorName) on server $($TargetServerName)?") -eq 0) {
            Write-Host "Updating server $($TargetServerName)"

            # clear permission groups for Exchange Server 2013 (thanks to Jeffery Land, https://jefferyland.wordpress.com)
            $tempPermissionGroups = @($sourceRC.PermissionGroups) -split ', ' | Select-String -Pattern 'Custom' -NotMatch
            $temp = ("$($tempPermissionGroups)").Replace(' ', ', ').Replace(' ','')

            if($temp -ne '') {
                $sourceRC.PermissionGroups = $temp
            }

            Get-ReceiveConnector "$($TargetServerName)\$($sourceRC.Name)" | Set-ReceiveConnector `
                -RemoteIPRanges $sourceRC.RemoteIPRanges `
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
                -TarpitInterval $sourceRC.TarpitInterval `                -EnhancedStatusCodesEnabled  $sourceRC.EnhancedStatusCodesEnabled `
                -AuthMechanism $sourceRC.AuthMechanism 
#                -Bindings $targetRC.Bindings `
#                -TransportRole $sourceRC.TransportRole `

            if($CopyPermissions) {
                # fetch non inherited permissons from source connector
                $sourcePermissions = Get-ReceiveConnector -Identity $sourceRC | Get-ADPermission | Where-Object {$_.IsInherited -eq $false}

                # we wait some time for domain controller to get stuff done
                Write-Host "Wait $($secondsToWait) seconds for domain controller to update"
                Start-Sleep -Seconds $secondsToWait

                Write-Verbose 'Adding AD permissions'

                # set access rights on target connector
                $sourcePermissions | foreach {
                Get-ReceiveConnector "$($TargetServerName)\$($sourceRC.Name)" -DomainController $DomainController | Add-ADPermission -DomainController $DomainController -User $_.User -Deny:$_.Deny -AccessRights $_.AccessRights -ExtendedRights $_.ExtendedRights | Out-Null
                }
            }
        }
    }
    else {
        Write-Host 'There seems to be an issue with the source connector information provided.'
        Write-Host "Source connector $($SourceServer)\$($ConnectorName) cannot be accessed or does not exist!"
    }
}

function Copy-ToAllServers {
    Write-Verbose 'Copy receive connector to all other Exchange 2013 servers'

    $frontendServers = Get-ExchangeServer | Where-Object{($_.AdminDisplayVersion.Major -eq 15) -and (([string]$_.ServerRole).Contains('ClientAccess')) -and ($_.Name -ne $SourceServer)} | Sort-Object Name
    
    foreach($server in $frontendServers){
        Write-Output "Working on server: $server"
        Copy-ToServer -TargetServerName $server
    }

    Write-Verbose 'Copying to all Exchange servers done'
}

### MAIN ----------------------------------

if($ViewEntireForest) {
    Write-Verbose "Setting ADServerSettings -ViewEntireForest $true"
    Set-ADServerSettings -ViewEntireForest $true
}

if((-not $CopyToAllOther) -and ($TargetServer -eq '')){
    Write-Output 'You need to either specific a dedicated target server using the -TargetServer '
    Write-Output 'attribute or select the -CopyToAllOther switch'
    break
}
elseif($TargetServer -ne ''){
    # Copy to a single Exchange server
    Copy-ToServer -TargetServerName $TargetServer  
}
elseif($CopyToAllOther){
    # Copy to all other Exchange 2013/2016 servers
    Copy-ToAllServers
}