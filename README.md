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
    .\Copy-ReceiveConnector.ps1 -SourceServer MBX2007 -ConnectorName "nikos-two relay" -TargetServer MBX01 -MoveToF