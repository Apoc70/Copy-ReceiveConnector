# Copy-ReceiveConnector.ps1

Copy a selected receive connector and it's configuration and permissions to other Exchange Servers

## Description

This script copies a receive connector from a source Exchange Server to a single target Exchange server or to all Exchange servers.

Configured permissions are copied as well, if required.

## Requirements

- Windows Server 2016, Windows Server 2019
- Exchange Server 2013/2016/2019 Management Shell

## Parameters

### ConnectorName

Name of the connector the new IP addresses should be added to

### SourceServer

Name of the receive connector to copy

### TargetServer

Target Exchange server to copy the selected receive connector to

### DomainController

Domain Controller name

### CopyToAllOther

Switch to copy to all other Exchange servers

### CopyPermissions

Copy non inherited source receive AD permissions to target receive connector. Inherited permissions will not be copied

### MoveToFrontend

Change source connector transport role to FrontendTransport. This is required when you copy a receive connector from Exchange 2007 to Exchange 2013+

### ResetBindings

Do not copy bindings but reset receive connector network bindings to 0.0.0.0:25

### UpdateExistingConnector

Update an existing receive connector without confirmation prompt.

### ViewEntireForest

View entire Active Directory forest

## Examples

``` PowerShell
.\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName nikos-one-RC2 -TargetServer MBX2 -DomainController MYDC1.mcsmemail.de
```

Copy Exchange 2013 receive connector nikos-one-RC2 from server MBX01 to server MBX2

``` PowerShell
.\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName nikos-one-RC1 -CopyToAllOther -DomainController MYDC1.mcsmemail.de
```

Copy Exchange 2013 receive connector nikos-one-RC2 from server MBX01 to all other Exchange 2013 servers

``` PowerShell
.\Copy-ReceiveConnector.ps1 -SourceServer MBX2007 -ConnectorName "varunagroup relay" -TargetServer MBX01 -MoveToFrontend -ResetBindings -DomainController MYDC1.mcsmemail.de
```

Copy Exchange 2013 receive connector "nikos-two relay" from Exchange 2007 server MBX2007 to Exchange 2013+ server MBX01 and reset network binding

``` PowerShell
.\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName MYRECEIVECONNECTOR -CopyToAllOther -DomainController MYDC1.mcsmemail.de -UpdateExitingConnector
```

Copy Exchange 2013/2016/2019 receive connector MYRECEIVECONNECTOR from server MBX01 to all other Exchange 2013+ servers without confirmation prompt if connectors already exists

## Note

THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE
RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.

## Credits

Written by: Thomas Stensitzki

## Stay connected

- Blog: [http://blog.granikos.eu](http://blog.granikos.eu)
- Twitter: [https://twitter.com/stensitzki](https://twitter.com/stensitzki)
- LinkedIn: [http://de.linkedin.com/in/thomasstensitzki](http://de.linkedin.com/in/thomasstensitzki)
- Github: [https://github.com/Apoc70](https://github.com/Apoc70)
- MVP Blog: [https://blogs.msmvps.com/thomastechtalk/](https://blogs.msmvps.com/thomastechtalk/)
- Tech Talk YouTube Channel (DE): [http://techtalk.granikos.eu](http://techtalk.granikos.eu)
- Tech & Community Podcast (DE): [http://podcast.granikos.eu](http://podcast.granikos.eu)

For more Microsoft 365, Cloud Security, and Exchange Server stuff checkout the services provided by Granikos

- Website: [https://granikos.eu](https://granikos.eu)
- Twitter: [https://twitter.com/granikos_de](https://twitter.com/granikos_de)
