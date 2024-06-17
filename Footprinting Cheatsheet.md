## Infrastructure-Based Enumeration - Web (Passive)

#### Sources for finding subdomains
```url
www.crt.sh
```

```url
www.censys.io
```

```url
www.virustotal.com/gui/home/url
```

#### Domain information gathering with WHOIS
```Shell
export TARGET="facebook.com" # Assign our target to an environment variable
```

```Shell
whois $TARGET
```

#### Gathering domain information using `whois.exe` from Windows Sysinternals
```cmd.exe
whois.exe facebook.com
```

#### Output certificate transparency
```Shell
curl -s https://crt.sh/\?q\=<target-domain>\&output\=json | jq .
```

#### Output certificate transparency filtered by unique subdomains
```Shell
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

#### Identifies company hosted servers directly accessible from the internet
```Shell
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```

#### Scan each IP address in a list using Shodan
```Shell
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

#### Thirdy party provider with information about client's infrastructure
```url
www.domain.glass
```

#### Thirdy party provider with information about client's infrastructure - More search filters than domain.glass
```url
www.buckets.grayhatwarfare.com
```

#### All subdomains for a given domain
```Shell
curl -s https://sonar.omnisint.io/subdomains/{domain} | jq -r '.[]' | sort -u
```

#### All TLDs found for a given domain
```Shell
curl -s https://sonar.omnisint.io/tlds/{domain} | jq -r '.[]' | sort -u
```

#### All results across all TLDs for a given domain
```Shell
curl -s https://sonar.omnisint.io/all/{domain} | jq -r '.[]' | sort -u
```

#### Reverse DNS lookup on IP address
```Shell
curl -s https://sonar.omnisint.io/reverse/{ip} | jq -r '.[]' | sort -u
```

#### Reverse DNS lookup of a CIDR range
```Shell
curl -s https://sonar.omnisint.io/reverse/{ip}/{mask} | jq -r '.[]' | sort -u
```

#### Certificate Transparency (1)
```Shell
curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u
```

#### Certificate Transparency (1)
```Shell
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
```

#### Searching for subdomains and other information on the sources provided in the source.txt list
```Shell
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}-${TARGET}";done
```

### TheHarvester

#### Using TheHarvester to collect emails, names, subdomains, IP addresses, and URLs
```Shell
cat sources.txt

baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

```Shell
export TARGET="facebook.com"
```

```Shell
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
```

#### Extract all the subdomains found and sort them 
```Shell
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```

#### Merging all the passive reconnaissance files
```Shell
cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
```

```Shell
cat facebook.com_subdomains_passive.txt | wc -l
```

### Netcraft
```
https://sitereport.netcraft.com
```

### Wayback Macine
```url
http://web.archive.org/
```

#### Installing waybackurls
```Shell
go install github.com/tomnomnom/waybackurls@latest
```

#### Using waybackurls to get a list of crawled URLs from a domain with the date it was obtained
```Shell
waybackurls -dates https://facebook.com > waybackurls.txt
```

## Infrastructure-Based Enumeration (Active)

#### Identifying the web server version based off response headers
```Shell
curl -I "http://${TARGET}"
```

#### Technology identification
```Shell
whatweb -a3 http://${TARGET} -v
```

#### Example pattern to put into .txt file for gobuster enumeration of subdomain patterns
```Shell
lert-api-shv-{GOBUSTER}-sin6
```

### WafW00f

#### Installing WafW00f
```Shell
apt install wafw00f -y
```

#### Generic Scan of WAF with WafW00f
```Shell
wafw00f -v https://www.tesla.com
```

#### vHost Fuzzing
```Shell
cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done
```

#### ZoneTransfers
```url
https://hackertarget.com/zone-transfer/
```

#### Brute forces subdomains over DNS
```Shell
export TARGET=facebook.com  
export NS=d.ns.facebook.com  
export WORDLIST=numbers.txt  
  
gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.TXT"
```

#### Discovering files and folders that cannot be spotted by browsing the website
```Shell
ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
```

#### Mutated bruteforcing against the target web server
```Shell
ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://www.target.domain/FOLDERS/WORDLISTEXTENSIONS
```

#### Extracting keywords from a website using `cewl`
```Shell
cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10
```

## Host-Based Enumeration - FTP

#### Install vsFTPd
```Shell
apt install vsftpd
```

#### vsFTPd Config File
```Shell
cat /etc/vsftpd.conf | grep -v "#"
```

#### List FTP Users
```Shell
cat /etc/ftpusers
```

#### Interact with the FTP service on the target
```Shell
ftp <FQDN/IP>
```
Anonymous login

#### Interact with the FTP service using netcat
```Shell
nc -nv <FQDN/IP> 21
```

#### Interact with the FTP service using telnet
```Shell
telnet <FQDN/IP> 21
```

#### Nmap Scan of FTP Service w/ Default Scripts
```Shell
nmap -sV -p21 -sC -A 10.129.14.136
```

#### Nmap Scan of FTP Service w/ Script Trace
```Shell
nmap -sV -p21 -sC -A 10.129.14.136 --script-trace
```

#### Interact with the FTP service on the target using an encrypted connection
```Shell
openssl s_client -connect <FQDN/IP>:21 -starttls ftp
```

#### Download all available files on the FTP server
```Shell
wget -m --no-passive ftp://anonymous:anonymous@<target>
```

#### Provide an overview of the vsFTPd server's settings
```ftp
status
```

#### vsFTPd detailed output
```ftp
debug
```

```ftp
trace
```

#### Provide a full directory listing
```ftp
ls -R
```

#### Download a selected file from the FTP server onto our local machine
```ftp
get <file name>
```

#### Uploading a selected file from our local machine to the FTP server
```ftp
put <file name>
```


## Host-Based Enumeration - SMB

#### Find OS type of SMB server
```Shell
nmap --script=smb-os-discovery -p 445 <target ip>
```

#### Enumerate shares on SMB server
```Shell
nmap --script=smb-enum-shares <target IP> -p 445
```

#### Nmap Scan with Default Scripts
```Shell
nmap 10.129.14.128 -sV -sC -p139,445
```

#### Null session authentication to SMB
```Shell
smbclient -N -L //<FQDN/IP>
```

#### Connect to a specific SMB share
```Shell
smbclient //<FQDN/IP>/<share>
```

#### Enumerate SMB Status on Linux
```Shell
smbstatus
```

#### Download a selected file from the SMB server onto our local machine
```smb
get <file name>
```

#### Putting an exclamation point in front of commands allows commands on our local system to be executed w/o losing connection
```Shell
!cd
```

#### Interaction with the target using RPC
```Shell
rpcclient -U "" <FQDN/IP>
```

#### Server information
```rpcclient
srvinfo
```

#### Enumerate all domains that are deployed in the network
```rpcclient
enumdomains
```

#### Provide domain, server, and user information of deployed domains
```rpcclient
querydominfo
```

#### Enumerate all available shares
```rpcclient
netshareenumall
```

#### Provide information about a specific share
```rpcclient
netsharegetinfo <share>
```

#### Enumerate all domain users
```rpcclient
enumdomusers
```

#### Provide information about a specific user
```rpcclient
queryuser <RID>
```

#### Brute force RIDs w/ `rpcclient`
```Shell
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

#### User enumeration using Impacket scripts
```Shell
samrdump.py <FQDN/IP>
```

#### Enumerate SMB shares
```Shell
smbmap -H <FQDN/IP>
```

#### Look in specific directory
```Shell
smbmap -H <FQDN/IP> -r <directory>
```

#### Download a specific file
```Shell
smbmap -H 10.129.14.128 --download "notes\note.txt"
```

#### Upload a specific file
```Shell
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

#### Enumerate SMB shares using null session authentication
```Shell
crackmapexec smb <FQDN/IP> --shares -u '' -p ''
```

#### SMB enumeration using `enum4linx-ng`
```Shell
enum4linux-ng.py <FQDN/IP> -A -C
```

#### Create a directory for mounting an SMB share to Linux and mounts it to Linux
```Shell
mkdir /mnt/Finance  
mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

#### Enumerate logged on users over CME
```Shell
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```


## Host-Based Enumeration - NFS

#### Retrieve a list of all currently running RPC services, their names and descriptions, the ports they use, and whether the target share is connected to the network on all required ports
```Shell
nmap 10.129.14.128 -p111,2049 -sV -sC
```

#### Run NSE's NFS scripts
```Shell
nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

#### Shows available NFS shares on the target
```Shell
nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

#### Show Available NFS Shares
```Shell
showmount -e 10.129.14.128
```

#### Make a directory on the attacker machine in preparation for the fileshare to be mounted
```Shell
mkdir target-NFS
```

#### Mount the NFS to the attacker machine
```Shell
mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
```

#### Unmount the NFS from the attacker machine
```Shell
umount ./target-NFS
```


## Host-Based Enumeration - DNS

#### Identify the `A` records for the target domain
```Shell
export TARGET="facebook.com"
```

```Shell
nslookup $TARGET
```

```Shell
dig a $TARGET @<nameserver/IP>
```

#### Query `A` records for subdomains
```Shell
nslookup -query=A $TARGET
```

```Shell
dig $TARGET @<nameserver/IP>
```

#### Query the `PTR` record for the target IP address
```Shell
nslookup -query=PTR <IP>
```

```Shell
dig -x <IP> @<nameserver/IP>
```

#### Version Query w/ `CH`
```Shell
dig CH TXT version.bind 10.129.120.85
```

#### `ANY` request to the specific nameserver
```Shell
nslookup -query=ANY $TARGET
```

```Shell
dig any $TARGET @<nameserver>
```

#### Identify the `TXT` records for the target domain
```Shell
nslookup -query=TXT $TARGET
```

```Shell
dig txt $TARGET @<nameserver/IP>
```

#### Identify the `MX` records for the target domain
```Shell
nslookup -query=MX $TARGET
```

```Shell
dig mx $TARGET @<nameserver/IP>
```

#### Identify name servers
```Shell
nslookup -type=NS <nameserver/IP>
```

#### `NS` request to the specific nameserver
```Shell
dig ns $TARGET @<nameserver/IP>
```

#### Test for `ANY` and `AXFR` zone transfer
```Shell
nslookup -type=any -query=AXFR <nameserver/IP> $TARGET
```

#### `AXFR` request to the specific nameserver
```Shell
dig axfr inlanefreight.htb @10.129.145.185
```

#### Subdomain bruteforcing w/ ffuf
```Shell
ffuf -w ./subdomains-top1million-110000.txt 0-u http://<FQDN/IP> -H "HOST: FUZZ.inlanefreight.htb" -fs 10918
```

#### Send back contents of Virtual Host
```Shell
curl -s http://10.129.57.235 -H "Host: www2.inlanefreight.htb"
```

#### Brute force subdomains over DNS
```Shell
export TARGET=facebook.com  
export NS=d.ns.facebook.com  
export WORDLIST=numbers.txt  
  
gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.TXT"
```

#### Subdomain bruteforcing
```Shell
for sub in $(cat /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

#### Subdomain bruteforcing
```Shell
dnsenum --dnsserver $IP --enum -p 0 -s 0 -o found_subdomains.txt -f /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

#### Enumerate all DNS servers of the root domain and scan for a DNS zone transfer
```Shell
fierce --domain zonetransfer.me
```

#### Enumerate subdomains
```Shell
./subfinder -d inlanefreight.com -v
```

#### Write a subdomain to enumerate to the resolvers.txt file (used IP address in example)
```Shell
echo "<FQDN/IP" > ./resolvers.txt
```

#### Subdomain enumeration (used domain name in example)
```Shell
./subbrute.py inlanefreight.htb -s ./names.txt -r ./resolvers.txt
```

#### DNS lookup for the specified subdomain
```Shell
host support.inlanefreight.com
```


## Host-Based Enumeration - SMTP

#### Logging into SMTP over Telnet
```Shell
telnet 10.129.14.128 25
```

#### SMTP Commands
| **Command** | **Description**                                                                                    |
| -------------- | ------------------------------------------------------------------------------------------------ |
| `AUTH PLAIN`   | AUTH is a service extension used to authenticate the client.                                     |
| `HELO`         | The client logs in with its computer name and thus starts the session.                           |
| `MAIL FROM`    | The client names the email sender.                                                               |
| `RCPT TO`      | The client names the email recipient.                                                            |
| `DATA`         | The client initiates the transmission of the email.                                              |
| `RSET`         | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY`         | The client checks if a mailbox is available for message transfer.                                |
| `EXPN`         | The client also checks if a mailbox is available for messaging with this command.                |
| `NOOP`         | The client requests a response from the server to prevent disconnection due to time-out.         |
| `QUIT`               |  The client terminates the session.                                                                                                |

#### Footprinting SMTP w/ Default Nmap Scripts
```Shell
nmap 10.129.14.128 -sC -sV -p25
```

#### Nmap Scan to check for Open-Relay
```Shell
nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```


## Host-Based Enumeration - IMAP

#### Footprinting IMAP/POP3 with Nmap
```Shell
nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

#### Log in to the IMAPS service using `curl`
```Shell
curl -k 'imaps://<FQDN/IP>' --user <user>:<password> -v
```

#### Connect to the IMAPS service
```Shell
openssl s_client -connect <FQDN/IP>:imaps
```

#### User login
```IMAP
1 LOGIN username password
```

#### List all directories
```IMAP
1 LIST "" *
```

#### Create a mailbox with a specified name
```IMAP
1 CREATE "INBOX"
```

#### Delete a mailbox
```IMAP
1 DELETE "INBOX"
```

#### Rename a mailbox
```IMAP
1 RENAME "ToRead" "Important"
```

#### Return a subset of names from the set of names that the User has declared as being active or subscribed
```IMAP
1 LSUB "" *
```

#### Select a mailbox so that messages in the mailbox can be accessed
```IMAP
1 SELECT INBOX
```

#### Exit the selected mailbox
```IMAP
1 UNSELECT INBOX
```

#### Retrieve data associated with a message in the mailbox
```IMAP
1 FETCH <ID> all
```

#### Retrieve data from a message in the mailbox
```IMAP
1 FETCH <ID> RFC822
```

#### Remove all messages with the Deleted flag set
```IMAP
1 CLOSE
```

#### Close the connection with the IMAP server
```IMAP
1 LOGOUT
```

#### Good resource for enumerating IMAP (helped solve lab)
```url
https://www.atmail.com/blog/imap-101-manual-imap-sessions/
```


## Host-Based Enumeration - POP3

#### Footprinting IMAP/POP3 with Nmap
```Shell
nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

#### Connect to the POP3s service
```Shell
openssl s_client -connect 10.129.14.128:pop3s
```

#### Identify the user
```pop3
USER username
```

#### Authentication of the user using its password
```pop3
PASS password
```

#### Request the number of saved emails from the server
```pop3
STAT
```

#### Request from the server the number and size of all emails
```pop3
LIST
```

#### Request the server to deliver the requested email by ID
```pop3
RETR id
```

#### Request the server to delete the requested email by ID
```pop3
DELE id
```

#### Request the server to display the server capabilities
```pop3
CAPA
```

#### Request the server to reset the transmitted information
```pop3
RSET
```

#### Close the connection with the POP3 server
```pop3
QUIT
```


## Host-Based Enumeration - SNMP

#### Querying OIDs using `snmpwalk`
```Shell
snmpwalk -v2c -c public 10.129.14.128
```

#### Bruteforcing community strings of the SNMP service
```Shell
onesixtyone -c /usr/share/SecLists/Discovery/SNMP/snmp.txt <FQDN/IP>
```
#### Installing braa
```Shell
apt install braa
```

#### Bruteforcing SNMP service OIDs with braa
```Shell
braa <community string>@<FQDN/IP>:.1.*
```
(e.g., `braa public@10.129.14.128:.1.3.6.*`)

#### Installing snmp-mib-downloader
```Shell
apt-get install snmp-mibs-downloader
```

```Shell
download-mibs
```
#### Edit the comment line saying "mibs :" in `/etc/snmp/snmp.conf`
```Shell
vim /etc/snmp/snmp.conf
```
#### Get extended objects using snmpwalk
```Shell
snmpwalk -v [VERSION_SNMP] -c [COMM_STRING] [DIR_IP] NET-SNMP-EXTEND-MIB::nsExtendObjects
```
#### Enumerate all w/ snmpwalk
```Shell
snmpwalk -v [VERSION_SNMP] -c [COMM_STRING] [DIR_IP] .1
```
#### Nmap scan of snmp, excluding snmp-brute
```Shell
nmap --script "snmp* and not snmp-brute" $ip
```
## Host-Based Enumeration - MySQL

#### nmap scan of MySQL server on port 3306
```Shell
nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```

#### Login to the MySQL server
```Shell
mysql -u <user> -p<password> -h <FQDN/IP>
```

#### Login to the MySQL server over CMD shell
```cmd.exe
mysql.exe -u username -pPassword123 -h 10.129.20.13
```

#### Open dbeaver
```Shell
dbeaver &
```

#### Show all databases
```MySQL
show databases;
```

#### Show DB version
```MySQL
select version();
```

#### Select one of the existing databases
```MySQL
use <database>;
```
Likely `sys`

#### Show all the available tables in the selected database
```MySQL
show tables;
```

#### The most important databases for the MySQL server are the system schema (`sys`) and information schema (`information_schema`)
```MySQL
use sys;
```

#### Show all columns in the selected database
```MySQL
show columns from <table>;
```

#### Show everything in the desired table
```MySQL
select * from <table>;
```

#### Search for needed string in the desired table
```MySQL
select * from <table> where <column> = <string>;
```


## Host-Based Enumeration - MSSQL

#### Nmap scan of MSSQL server
```Shell
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

#### Scan the MSSQL service with Metasploit
```Shell
use auxiliary/scanner/mssql/mssql_ping)
```

#### Remotely connect to the MSSQL server w/ authentic credentials
```Shell
mssqlclient Administrator@10.129.201.248 -windows-auth
```

#### List the databases present on the system
```MSSQL
select name from sys.databases
```

#### Interact w/ MSSQL over Linux
```Shell
sqsh -S 10.129.20.13 -U username -P Password123
```

#### Interact w/ MSSQL over CMD shell
```cmd.exe
sqlcmd -S 10.129.20.13 -U username -P Password123
```

#### Open dbeaver
```Shell
dbeaver &
```


## Host-Based Enumeration - IPMI

#### Nmap scan of IPMI subsystem
```Shell
nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

#### IPMI version detection in Metasploit
```Shell
use auxiliary/scanner/ipmi/ipmi_version
```

#### Dump IPMI hashes in Metasploit
```Shell
use auxiliary/scanner/ipmi/ipmi_dumphashes
```


## Host-Based Enumeration - Linux Remote Management - SSH

#### Remote security audit against the target SSH service
```Shell
ssh-audit.py <FQDN/IP>
```

#### Log in to the SSH server using the SSH client
```Shell
ssh <user>@<FQDN/IP>
```

#### Log in to the SSH server using private key
```Shell
ssh -i private.key <user>@<FQDN/IP>
```

#### Enforce password-based authentication
```Shell
ssh <user>@<FQDN/IP> -o PreferredAuthentications=password
```


## Host-Based Enumeration - Windows Remote Management - RDP/WinRM/WMI

#### Determine if NLA is enabled on the server or not, the product version, and the hostname
```Shell
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
```

#### RDP Security Check - Installation
```Shell
cpan
```

#### Installing rdp-sec-check
```Shell
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
```

#### Check the security settings of the RDP service
```Shell
rdp-sec-check.pl <FQDN/IP>
```

#### Log in to the RDP server from Linux
```Shell
xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>
```

#### Log in to the WinRM server
```Shell
evil-winrm -i <FQDN/IP> -u <user> -p <password>
```

#### nmap scan for WinRM
```Shell
nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```

#### Execute command using the WMI service
```Shell
wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"
```


## Host-Based Enumeration (SSH)

#### Installing SSH-Audit
```Shell
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
```

#### Enumerating SSH with SSH-Audit
```Shell
./ssh-audit.py 10.129.14.132
```

#### Change SSH Authentication Method
```Shell
ssh -v cry0l1t3@10.129.14.132
```

```Shell
ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
```


## Host-Based Enumeration (RSync)

#### Scanning for Rsync w/ Nmap
```Shell
nmap -sV -p 873 127.0.0.1
```

#### Probing for Accessible Shares
```Shell
nc -nv 127.0.0.1 873
```

#### Enumerating an Open Share
```Shell
rsync -av --list-only rsync://127.0.0.1/dev
```


## Host-Based Enumeration (R-Services)

![[Pasted image 20230302104553.png]]

#### Scanning for R-Services
```Shell
nmap -sV -p 512,513,514 10.0.17.2
```

#### Logging in Using Rlogin
```Shell
rlogin 10.0.17.2 -l htb-student
```

#### Listing Authenticated Users Using Rwho
```Shell
rwho
```

#### Listing Authenticated Users Using Rusers
```Shell
rusers -al 10.0.17.5
```
