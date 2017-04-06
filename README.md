# Copy-ReceiveConnector.ps1
Copy a selected receive connector and it's configuration and permissions to other Exchange Servers

## Description
This script copies a receive connector from a source Exchange Server to a single target Exchange server or to all Exchange servers.
    
Configured permissions are copied as well, if required.

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
Change source connector transport role to FrontendTransport. This is required when you copy a receive connector from Exchange 2007 to Exchange 2013

### ResetBindings
Do not copy bindings but reset receive connector network bindings to 0.0.0.0:25

### ViewEntireForest
View entire Active Directory forest

## Examples
```
.\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName nikos-one-RC2 -TargetServer MBX2 -DomainController MYDC1.mcsmemail.de
```
Copy Exchange 2013 receive connector nikos-one-RC2 from server MBX01 to server MBX2

```
.\Copy-ReceiveConnector.ps1 -SourceServer MBX01 -ConnectorName nikos-one-RC1 -CopyToAllOther -DomainController MYDC1.mcsmemail.de
```
Copy Exchange 2013 receive connector nikos-one-RC2 from server MBX01 to all other Exchange 2013 servers 

```
.\Copy-ReceiveConnector.ps1 -SourceServer MBX2007 -ConnectorName "nikos-two relay" -TargetServer MBX01 -MoveToFrontend -ResetBindings -DomainController MYDC1.mcsmemail.de 
```
Copy Exchange 2013 receive connector "nikos-two relay" from Exchange 2007 server MBX2007 to Exchange 2013 server MBX01 and reset network bindings 
    
## TechNet Gallery
Find the script at TechNet Gallery
* https://gallery.technet.microsoft.com/Copy-a-receive-connector-b20b9bef


## Credits
Written by: Thomas Stensitzki

## Social

* My Blog: https://JustCantGetEnough.Granikos.eu
* Archived Blog: http://www.sf-tools.net/
* Twitter: https://twitter.com/apoc70
* LinkedIn: http://de.linkedin.com/in/thomasstensitzki
* Github: https://github.com/Apoc70

For more Office 365, Cloud Security and Exchange Server stuff checkout services provided by Granikos

* Blog: http://blog.granikos.eu/
* Website: https://www.granikos.eu/en/
* Twitter: https://twitter.com/granikos_de
