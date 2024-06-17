## Burp Shortcuts

[CTRL+I]     Send to intruder

[CTRL+SHIFT+B] 	Go to intruder

[CTRL+U] 	URL encode

[CTRL+SHIFT+U]     URL decode

[CTRL+R]     Send to Repeater

[CTRL+SHIFT+R]     Navigate to Repeater tab

## Zap Shortcuts
[CTRL+B] 	Toggle intercept on/off
[CTRL+R] 	Go to replacer
[CTRL+E] 	Go to encode/decode/hash

## Firefox Shortcuts
[CTRL+SHIFT+R] 	Force Refresh Page

## Command Injection

#### From Repeater

[CTRL+R]     Send to Repeater

[CTRL+SHIFT+R]     Navigate to Repeater tab

```Shell
ip=1;ls+-la;
```
Lists files

```Shell
ip=1;cat+flag.txt;
```
Displays file contents

## Proxying Tools

### Proxychains

To use `proxychains`, we first have to edit `/etc/proxychains.conf`, comment the final line and add the following two lines at the end of it:
```Shell
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
https 127.0.0.1 8080
```
We should also enable `Quiet Mode` to reduce noise by un-commenting `quiet_mode`

```Shell
proxychains curl http://SERVER_IP:PORT
```

### Nmap
```Shell
nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC
```

### Metasploit

#### Example w/ `robots_txt` scanner:
```Shell
use auxiliary/scanner/http/robots_txt
set PROXIES HTTP:127.0.0.1:8080
set RHOST SERVER_IP
set RPORT PORT
run
```

#### Lab Example:

Turn Burp Suite Interceptor on.

In msfconsole:
```Shell
use auxiliary/scanner/http/http_put
set PROXIES HTTP:127.0.0.1:8080
set rhost google.com
set rport 443
run
```

In Burp Suite:
![[msf as proxy.png]]

## Burp Intruder

#### Payloads
- `Sniper` Attack for only one payload position
- `Cluster Bomb` for multiple payload positions

Payload Types:
- `Simple List`: The basic and most fundamental type. We provide a wordlist, and Intruder iterates over each line in it.
- `Runtime File`: Similar to `Simple List`, but loads line-by-line as the scan runs to avoid excessive memory usage by Burp.
- `Character Substitution`: Lets us specify a list of characters and their replacements, and Burp Intruder tries all potential permutations.

*Tip: In case you wanted to use a very large wordlist, it's best to use Runtime file as the Payload Type instead of Simple List, so that Burp Intruder won't have to load the entire wordlist in advance, which may throttle memory usage.*

#### Payload Processing
- `Skip if matches regex`: allows us to provide a regex pattern for items we want to skip.
![[Pasted image 20230116132736.png]]

#### Payload Encoding
![[Pasted image 20230116132757.png]]

#### Options
- `Grep - Match`: useful options which enables us to flag specific requests depending on their responses (e.g., `200 OK`)
*Note: We may also use the `Resource Pool` tab to specify how much network resources Intruder will use*

### Installing CA Certificate

#### We can install Burp's certificate once we select Burp as our proxy in `Foxy Proxy`, by browsing to `http://burp`, and download the certificate from there by clicking on `CA Certificate`:
![[burp ca.png]]
#### Once we have our certificates, we can install them within Firefox by browsing to [about:preferences#privacy](about:preferences#privacy), scrolling to the bottom, and clicking `View Certificates`:
![[view certs.png]]
#### After that, we can select the `Authorities` tab, and then click on `import`, and select the downloaded CA certificate:
![[cert manager.png]]
#### Finally, we must select `Trust this CA to identify websites` and `Trust this CA to identify email users`, and then click OK:
![[download cert.png]]
#### Once we install the certificate and configure the Firefox proxy, all Firefox web traffic will start routing through our web proxy.