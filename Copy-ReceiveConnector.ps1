<# 
    .SYNOPSIS 
    Copy a selected receive connector and it's configuration and permissions to other Exchange Servers

    Thomas Stensitzki 

    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE  
    RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER. 

    Version 1.7, 2020-03-15

    Please submit ideas, comments, and suggestions using GitHub. 

    .LINK 
    http://scripts.granikos.eu

    .DESCRIPTION 

    This script copies a receive connector from a source Exchange Server to a single target Exchange server or to all Exchange servers.
    
    Configured permissions are copied as well, if required.
 
    .NOTES 

    Requirements 
    - Windows Server 2016, Windows Server 2019
    - Exchange Server 2013/2016/2019 Management Shell
    
    Revision History 
    -------- ----------------------------------------------------------------------- 
    1.0      Initial community release 
    1.1      Domain Controller parameter added, permissions group copy added
    1.2      Move to FrontendTransport added, optional permission copy added, reset bindings added 
    1.3      Update receive connector, if receive connector exists
    1.4      Fix to handle connector updates properly
    1.41     Minor fixes and update for Exchange 2016
    1.5      Issue #2 fixed
    1.6      Issue #3 fixed
    1.6.1    Minor fixes and tested with Exchange Server 2019 
    1.7      UpdateExistingConnector added (issue #6), tested with Exchange Server 2019

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

    .PARAMETER UpdateExistingConnector
    Update an existing receive connector without confirmation prompt.

    .PARAMETER ViewEntireForest
    View entire Active Directory forest

    .EXAMPLE 

    Copy Exchange 2013/2016/2019 receive connector MYRECEIVECONNECTOR from server MBX01 to server MBX2

    .\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName MYRECEIVECONNECTOR -TargetServer MBX2 -DomainController MYDC1.mcsmemail.de

    .EXAMPLE 

    Copy Exchange 2013/2016/2019 receive connector MYRECEIVECONNECTOR from server MBX01 to all other Exchange 2013+ servers 

    .\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName MYRECEIVECONNECTOR -CopyToAllOther -DomainController MYDC1.mcsmemail.de

    .EXAMPLE 

    Copy Exchange 2013/2016/2019 receive connector MYRECEIVECONNECTOR from server MBX01 to all other Exchange 2013+ servers without confirmation prompt if connectors already exists

    .\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName MYRECEIVECONNECTOR -CopyToAllOther -DomainController MYDC1.mcsmemail.de -UpdateExitingConnector

    .EXAMPLE 

    Copy Exchange 2013/2016/2019 receive connector MYRECEIVECONNECTOR from Exchange 2010 server MBX2010 to Exchange 2016 server MBX01, make it a FrontEnd-Connector, and reset network bindings 

    .\Copy-ReceiveConnector.ps1 -SourceServer MBX2010 -ConnectorName MYRECEIVECONNECTOR -TargetServer MBX01 -MoveToFrontend -ResetBindings -DomainController MYDC1.mcsmemail.de 
#> 

param(
  [parameter(Mandatory,HelpMessage='Source Exchange server to copy from')]
  [string]$SourceServer,
  [parameter(Mandatory,HelpMessage='Name of the source receive connector')]
  [string]$ConnectorName,
  [string]$TargetServer = '',
  [parameter(Mandatory,HelpMessage='Domain Controller name')]
  [string]$DomainController = '',
  [switch]$CopyToAllOther,
  [switch]$CopyPermissions,
  [switch]$MoveToFrontend,
  [switch]$ResetBindings,
  [switch]$UpdateExitingConnector,
  [switch]$ViewEntireForest
)

Import-Module -Name ActiveDirectory 

$sourceRC = $null
$secondsToWait = 60

### FUNCTIONS -----------------------------

function Request-Choice {
  [CmdletBinding()]
  param(
    [string]$Caption = 'Really?'
  )
  $choices =  [System.Management.Automation.Host.ChoiceDescription[]]@('&Yes','&No')
    
  [int]$defaultChoice = 1

  $choiceReturn = $Host.UI.PromptForChoice($Caption, '', $choices, $defaultChoice)

  return $choiceReturn   
}

function Copy-ToServer {
  [CmdletBinding()]
  param(
    [string]$TargetServerName = ''
  )

  $ExchangeGroups = @('Externally Secured Servers','Edge Transport Servers','Hub Transport Servers','Exchange Servers','ExchangeLegacyInterop')
    
  if ($TargetServerName -ne '') { 

    $sourceRC = Get-ReceiveConnector -Server $SourceServer -DomainController $DomainController  | Where-Object{$_.Name -eq $ConnectorName} -ErrorAction SilentlyContinue

    $targetRC = Get-ReceiveConnector -Server $TargetServerName -DomainController $DomainController | Where-Object{$_.Name -eq $ConnectorName} -ErrorAction SilentlyContinue

    if(($sourceRC -ne $null) -and ($targetRC -eq $null)){

      Write-Host ('Working on [{0}] and receive connector [{1}]' -f $TargetServerName.ToUpper(), $ConnectorName)

      # clear permission groups for Exchange Server 2013 (thanks to Jeffery Land, https://jefferyland.wordpress.com)
      $tempPermissionGroups = @($sourceRC.PermissionGroups) -split ', ' | Select-String -Pattern 'Custom' -NotMatch
      $temp = (('{0}' -f $tempPermissionGroups)).Replace(' ', ', ').Replace(' ','')

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

      $TargetFqdn = $sourceRC.Fqdn

      # Check if source fqdn contains server name fqdn
      if(([string]$sourceRC.Fqdn.Domain).ToLower().Contains([string]$sourceRC.Server.Name.ToLower())) {
        Write-Verbose -Message 'Source connector uses server Fqdn. Changing to target server Fqdn.'

        $TargetFqdn = ('{0}.{1}' -f $TargetServerName,(Get-ExchangeServer $TargetServerName).Domain.ToString()).ToLower()
      }

      $FixAuthMechanism = $false

      # change permission groups settings temporarily
      if(([string]$sourceRC.AuthMechanism).Split(',').Trim().Contains('ExternalAuthoritative')) {
        Write-Verbose -Message 'Connector is set to ExternalAuthoritative and needs special treatment.'
        
        # keep current source connector configuration
        $AuthMechanism = $sourceRC.AuthMechanism
        $PermissioNGroups = $sourceRC.PermissionGroups

        # set ExternalAuthoritative only
        # $sourceRC.AuthMechanism = 'ExternalAuthoritative'
        $sourceRC.PermissionGroups = 'ExchangeServers'

        $FixAuthMechanism = $true
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
      -TarpitInterval $sourceRC.TarpitInterval `
      -EnhancedStatusCodesEnabled  $sourceRC.EnhancedStatusCodesEnabled `
      -Server $TargetServerName `
      -AuthMechanism $sourceRC.AuthMechanism `
      -Fqdn $TargetFqdn `
      -DomainController $DomainController

      if($FixAuthMechanism) {

        Write-Verbose -Message ('Wait {0} seconds for domain controller to update' -f $secondsToWait)
        Start-Sleep -Seconds $secondsToWait

        $newConnector = Get-ReceiveConnector -Identity ('{0}\{1}' -f $TargetServerName, $sourceRC.Name) -DomainController $DomainController

        Write-Verbose -Message ('Updating PermissionGroups for {0}\{1}' -f $TargetServerName, $sourceRC.Name)

        $newConnector | Set-ReceiveConnector -PermissionGroups $PermissionGroups

      }

      if($CopyPermissions) {
        # fetch non inherited permissons from source connector
        $sourcePermissions = Get-ReceiveConnector -Identity $sourceRC -DomainController $DomainController | Get-ADPermission | Where-Object {$_.IsInherited -eq $false}

        # we wait some time for domain controller to get stuff done
        Write-Host ('Wait {0} seconds for domain controller to update' -f $secondsToWait)
        Start-Sleep -Seconds $secondsToWait

        Write-Verbose -Message 'Adding AD permissions'

        # set access rights on target connector
        $null = Get-ReceiveConnector -Identity ('{0}\{1}' -f $TargetServerName, $sourceRC.Name) -DomainController $DomainController | Add-ADPermission -DomainController $DomainController -User $_.User -Deny:$_.Deny -AccessRights $_.AccessRights -ExtendedRights $_.ExtendedRights -ErrorAction SilentlyContinue
        
        Write-Verbose -Message 'Adding AD permissions finished'
      }
    }
    elseif($sourceRC -ne $null) {

      # target connector already exists
      Write-Output 'Target connector already exists.'
        
      if(($UpdateExitingConnector) -or (Request-Choice -Caption ('Do you want to UPDATE the receive connector {0} on server {1}?' -f $ConnectorName, $TargetServerName)) -eq 0) {
      
        Write-Host ('Updating connector on server {0}' -f $TargetServerName)

        # clear permission groups for Exchange Server 2013 (thanks to Jeffery Land, https://jefferyland.wordpress.com)
        $tempPermissionGroups = @($sourceRC.PermissionGroups) -split ', ' | Select-String -Pattern 'Custom' -NotMatch
        $temp = (('{0}' -f $tempPermissionGroups)).Replace(' ', ', ').Replace(' ','')

        if($temp -ne '') {
          $sourceRC.PermissionGroups = $temp
        }

        $TargetFqdn = $sourceRC.Fqdn

        # Check if source fqdn contains server name fqdn
        if(([string]$sourceRC.Fqdn.Domain).ToLower().Contains([string]$sourceRC.Server.Name.ToLower())) {
          Write-Verbose -Message 'Source connector uses server Fqdn. Changing to target server Fqdn.'

          $TargetFqdn = ('{0}.{1}' -f $TargetServerName,(Get-ExchangeServer $TargetServerName).Domain.ToString()).ToLower()
        }

        Get-ReceiveConnector -Identity ('{0}\{1}' -f ($TargetServerName), $sourceRC.Name) | Set-ReceiveConnector `
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
        -TarpitInterval $sourceRC.TarpitInterval `
        -EnhancedStatusCodesEnabled  $sourceRC.EnhancedStatusCodesEnabled `
        -AuthMechanism $sourceRC.AuthMechanism `
        -Fqdn $TargetFqdn

        if($CopyPermissions) {

          # fetch non inherited permissons from source connector
          $sourcePermissions = Get-ReceiveConnector -Identity $sourceRC | Get-ADPermission | Where-Object {$_.IsInherited -eq $false}

          # we wait some time for domain controller to get stuff done
          Write-Host ('Wait {0} seconds for domain controller to update' -f $secondsToWait)
          Start-Sleep -Seconds $secondsToWait

          Write-Verbose -Message 'Adding AD permissions'

          # set access rights on target connector
          $sourcePermissions | ForEach-Object {
            $null = Get-ReceiveConnector -Identity ('{0}\{1}' -f $TargetServerName, $sourceRC.Name) -DomainController $DomainController | Add-ADPermission -DomainController $DomainController -User $_.User -Deny:$_.Deny -AccessRights $_.AccessRights -ExtendedRights $_.ExtendedRights
          }
        }
      }
    }
    else {
      Write-Host 'There seems to be an issue with the source connector information provided.'
      Write-Host ('Source connector {0}\{1} cannot be accessed or does not exist!' -f $SourceServer, $ConnectorName)
    }
  }
  else {
    Write-Verbose -Message 'No target server name specified'
  }
}

function Copy-ToAllServers {
  Write-Verbose -Message 'Copy receive connector to all other Exchange 2013+ servers'

  # Quick fix for issue #3, assuming that you've deployed Exchange 2013 multi-role
  $frontendServers = Get-ExchangeServer | Where-Object{($_.AdminDisplayVersion.Major -eq 15) -and (([string]$_.ServerRole).Contains('Mailbox')) -and ($_.Name -ne $SourceServer)} | Sort-Object -Property Name
    
  foreach($server in $frontendServers){
    Write-Output -InputObject ('Working on server: {0}' -f $server)
    Copy-ToServer -TargetServerName $server
  }

  Write-Verbose -Message 'Finished copying connector to all modern Exchange servers done'
}

### MAIN ----------------------------------

if($ViewEntireForest) {
  Write-Verbose -Message ('Setting ADServerSettings -ViewEntireForest {0}' -f $true)
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
  # Copy to all Exchange 2013/2016/2019 servers
  Copy-ToAllServers
}