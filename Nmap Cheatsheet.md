## Host Discovery

#### Scan Network Range
```Shell
nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

#### Scan IP List
```Shell
nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

#### Scan Multiple IPs
```Shell
nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5
```

```Shell
nmap -sn -oA tnet 10.129.2.18-20| grep for | cut -d" " -f5
```

#### Scan an IP address and store the results in multiple file formats
```Shell
nmap 10.129.2.18 -sn -oA host 
```

#### Scan an IP address with packet tracing
```Shell
nmap 10.129.2.18 -sn -oA host -PE --packet-trace 
```

#### Scan IP address and display reason for specific result
```Shell
nmap 10.129.2.18 -sn -oA host -PE --reason
```

#### Disable ARP requests and scan the target with desired ICMP echo requests
```Shell
nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping 
```

## Host and Port Scanning

### Discovering Open TCP Ports

#### Scanning Top 10 TCP Ports
```Shell
nmap 10.129.2.28 --top-ports=10
```

#### Tracing Packets
```Shell
nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```

#### Connect Scan on TCP Port 443
```Shell
nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT
```

### Discovering Open UDP Ports

#### UDP Port Scan
```Shell
nmap 10.129.2.28 -F -sU
```

#### UDP Port Scan w/ ICMP Echo requests, DNS resolution, and ARP disabled + tracing packets against a specific port and the reason for the result
```Shell
nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 100 --reason
```

#### UDP Service Scan w/ ICMP Echo requests, DNS resolution, and ARP disabled + tracing packets against a specific port and the reason for the result
```Shell
nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason -sV
```

## Saving Results

### Different Formats

#### Normal output (`-oN`) with the `.nmap` file extension
```Shell
nmap 10.129.2.28 -p- -oN target
```
Scans all ports

#### Grepable output (`-oG`) with the `.gnmap` file extension
```Shell
nmap 10.129.2.28 -p- -oG target
```

#### XML output (`-oX`) with the `.xml` file extension
```Shell
nmap 10.129.2.28 -p- -oX target
```

#### Save the results in all formats (`-oA`)
```Shell
nmap 10.129.2.28 -p- -oA target
```

#### Using `xsltproc` to convert an XML file to HTML
```Shell
xsltproc target.xml -o target.html
```

#### Open the HTML file in the browser
![[Pasted image 20230301145403.png]]

## Service Enumeration

### Service Version Detection

#### Full port scan + service detection
```Shell
nmap 10.129.2.28 -p- -sV
```

#### Full port scan + service detection w/ results displayed every 5 seconds
```Shell
nmap 10.129.2.28 -p- -sV --stats-every=5s
```

#### Full port scan + service detection + increased verbosity level
```Shell
nmap 10.129.2.28 -p- -sV -v
```
Will display the open ports directly when Nmap detects them

#### Full port scan + service detection + disable ICMP, DNS resolution, & ARP ping + trace packets
```Shell
nmap 10.129.2.28 -p- -sV -Pn -n --disable-arp-ping --packet-trace
```

#### Start tcpdump to intercept network traffic
```Shell
tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
```

#### Manually connect to an SMTP server using `nc`
```Shell
nc -nv 10.129.2.28 25
```

## Nmap Scripting Engine

| **Category** | **Description**                                                                                                                         |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `auth`       | Determination of authentication credentials.                                                                                            |
| `broadcast`  | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| `brute`        | Executes scripts that try to log in to the respective service by brute-forcing with credentials.                                        |
| `default`      | Default scripts executed by using the `-sC` option.                                                                                     |
| `discovery`    | Evaluation of accessible services                                                                                                       |
| `dos`          | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.              |
| `exploit`      | This category of scripts tries to exploit known vulnerabilities for the scanned port.                                                   |
| `external`     | Scripts that use external services for further processing.                                                                              |
| `fuzzer`       | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.     |
| `intrusive`    | Intrusive scripts that could negatively affect the target system.                                                                       |
| `malware`      | Checks if some malware infects the target system.                                                                                       |
| `safe `        | Defensive scripts that do not perform intrusive and destructive access.                                                                 |
| `version`      | Extension for service detection.                                                                                                        |
| `vuln  `       | Extension for service detection.                                                                                                        |

#### Default Scripts
```Shell
nmap <target> -sC
```

#### Specifying Scripts
```Shell
nmap 10.129.2.28 -p 25 --script banner,smtp-commands
```

#### Aggressive Scan
```Shell
nmap 10.129.2.28 -p 80 -A
```

### Vulnerability Assessment

#### Vuln Category
```Shell
nmap 10.129.2.28 -p 80 -sV --script vuln 
```

## Firewall and IDS/IPS Evasion

#### SYN-Scan
```Shell
nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping --packet-trace
```

#### ACK-Scan
```Shell
nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace
```

### Decoys

#### Scan by using decoys
```Shell
nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

#### Testing Firewall Rule
```Shell
nmap 10.129.2.28 -n -Pn -p445 -O
```
Tests for OS type w/ ICMP and DNS resolution disabled

#### Scan by Using Different Source IP
```Shell
nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```
`-S <IP addr>` is the source IP address

### DNS Proxying

#### SYN-Scan of a Filtered Port
```Shell
nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace
```

#### SYN-Scan From DNS Port
```Shell
nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```

#### Connect To The Filtered Port
```Shell
ncat -nv --source-port 53 10.129.2.28 50000
```


## Scanning Options
| **Nmap Option** | **Description** |
|---|----|
| `10.10.10.0/24` | Target network range. |
| `-sn` | Disables port scanning. |
| `-Pn` | Disables ICMP Echo Requests |
| `-n` | Disables DNS Resolution. |
| `-PE` | Performs the ping scan by using ICMP Echo Requests against the target. |
| `--packet-trace` | Shows all packets sent and received. |
| `--reason` | Displays the reason for a specific result. |
| `--disable-arp-ping` | Disables ARP Ping Requests. |
| `--top-ports=<num>` | Scans the specified top ports that have been defined as most frequent.  |
| `-p-` | Scan all ports. |
| `-p22-110` | Scan all ports between 22 and 110. |
| `-p22,25` | Scans only the specified ports 22 and 25. |
| `-F` | Scans top 100 ports. |
| `-sS` | Performs an TCP SYN-Scan. |
| `-sA` | Performs an TCP ACK-Scan. |
| `-sU` | Performs an UDP Scan. |
| `-sV` | Scans the discovered services for their versions. |
| `-sC` | Perform a Script Scan with scripts that are categorized as "default". |
| `--script <script>` | Performs a Script Scan by using the specified scripts. |
| `-O` | Performs an OS Detection Scan to determine the OS of the target. |
| `-A` | Performs OS Detection, Service Detection, and traceroute scans. |
| `-D RND:5` | Sets the number of random Decoys that will be used to scan the target. |
| `-e` | Specifies the network interface that is used for the scan. |
| `-S 10.10.10.200` | Specifies the source IP address for the scan. |
| `-g` | Specifies the source port for the scan. |
| `--dns-server <ns>` | DNS resolution is performed by using a specified name server. |

## Output Options
| **Nmap Option** | **Description** |
|---|----|
| `-oA filename` | Stores the results in all available formats starting with the name of "filename". |
| `-oN filename` | Stores the results in normal format with the name "filename". |
| `-oG filename` | Stores the results in "grepable" format with the name of "filename". |
| `-oX filename` | Stores the results in XML format with the name of "filename". |

## Performance Options
| **Nmap Option** | **Description** |
|---|----|
| `--max-retries <num>` | Sets the number of retries for scans of specific ports. |
| `--stats-every=5s` | Displays scan's status every 5 seconds. |
| `-v/-vv` | Displays verbose output during the scan. |
| `--initial-rtt-timeout 50ms` | Sets the specified time value as initial RTT timeout. |
| `--max-rtt-timeout 100ms` | Sets the specified time value as maximum RTT timeout. |
| `--min-rate 300` | Sets the number of packets that will be sent simultaneously. |
| `-T <0-5>` | Specifies the specific timing template. |