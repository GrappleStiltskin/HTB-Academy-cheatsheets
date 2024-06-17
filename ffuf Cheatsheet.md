#### Directory Fuzzing
```Shell
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -v
```

#### Directory fuzzing which shows only HTTP status codes that were successful
```Shell
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -v -mc 200
```

#### Directory fuzzing which omits unsuccessful HTTP requests
```Shell
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -v -fc 404
```

#### Extension Fuzzing
```Shell
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ
```

#### Page Fuzzing
```Shell
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```

#### Recursive Fuzzing
```Shell
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```

#### Adding `academy.htb` to the `/etc/hosts` file
```Shell
sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```
Now we can visit the website (don't forget to add the PORT in the URL)

#### Sub-domain Fuzzing
```Shell
ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/
```

#### VHost Fuzzing
```Shell
ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx
```
VHosts may or may not have public DNS records. This is where we utilize `VHosts Fuzzing` on an IP we already have. use the `-H` flag to specify a header and  the `FUZZ `keyword within it. We will always get `200 OK`. However, if the VHost does exist and we send a correct one in the header, we should get a different response size.

*Note: Don't forget to add "admin.academy.htb" to "/etc/hosts".*

#### Parameter Fuzzing - GET
```Shell
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```
`GET` requests are usually passed right after the URL, with a ? symbol, like:  `http://admin.academy.htb:PORT/admin/admin.php?param1=key`
Replace `param1` in the example above with `FUZZ` and run the scan

#### Parameter Fuzzing - POST
```Shell
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'".

#### Create a wordlist containing all numbers from 1-1000
```Shell
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```


#### Value Fuzzing
```Shell
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
Do this after the parameter fuzzing when you get a value, such as "`id`"

#### Send POST request with identified value
```Shell
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```


### Wordlists:

#### Directory, Page, Recursvie Fuzzing
`/usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt`

#### Extension Fuzzing
`/usr/share/SecLists/Discovery/Web-Content/web-extensions.txt`

#### Subdomain Fuzzing
`/usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`

#### GET Request Fuzzing
`/usr/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt`