## DTG: 2023-11-24

## Index
### ⦁	Introduction

### ⦁	Compromise Walkthrough

### ⦁	Detailed Walkthrough
### ⦁	Key Takeaways

## Introduction
A company hired your firm to test the authentication mechanism used by their latest API endpoint at asmt.htb.net. The customer is interested in a completely black box test, so they did not specify the type of authentication mechanism they are using. Furthermore, they did not specify how to interact with the API endpoint or how to use it, so you must first figure out how to interact with it before enumerating and attacking.

Identify the authentication mechanism in use, obtain admin access and submit the final flag to complete the skills assessment and module.
## Compromise Walkthrough
I was required to answer the following question:

+ Once you obtain admin access, what is the flag returned to you? Answer format: HTB{...} 

***vHosts needed for this question:***

    asmt.htb.net

I started by identifying how to interact with the API that authenticates to the web application. I discovered that it was using JWT as the authentication mechanism to access the site. After identifying how to register a user, I did a brute force attack on the secret that was being used to sign the JWT, which allowed me to change the token to one with administrative privileges so I could access the application as a privileged user.
## Detailed Walkthrough

### Detailed reproduction steps for this attack chain are as follows:
#### 1. Identified the requirements for authentication (token) and directories that are needed for creating a user and acquiring this token.

I went to the vHost endpoint provided in the assessment instructions. The page displayed instructions, stating that I needed to have a token to access this page, and that I could acquire one by either logging in, or registering a new user and then logging in. It provided the endpoints for doing both: `/login` and `/register`.
![[go here.png]]
#### 2. Identified parameters needed to register a user

I went to `http://asmt.htb.net/register` in order to try and register a new user.  I identified that GET requests weren't valid requests, and that the `Content-Type` had to be `application/json`.
![[content-type.png]]

After identifying these two things, I began entering data into the body of the message and discovered that I needed to have `first_name`, `last_name`, `email`, and `password` as the parameters to register a new user.
![[fn-ln-req 2.png]]

Once I entered this data into the POST message body, I successfully registered a new user.
![[reg.png]]
#### 3. Decoded JWT, brute forced signature secret, and obtained login token as administrator

First, I logged in as a regular user to get a login token that could be passed to the application for authentication. The initial token only provided access as a regular user though. I identified that an email and password were required on the `/login` page. So I entered the email and password I'd registered with the registration token I'd been provided. This gave me a login token.
![[un-pw.png]]
![[login 1.png]]

Unfortunately, this didn't provide access as an administrator, even when the field `isAdmin` was modified from "false" to "true." I needed to leverage this token to gain access as an administrator. First, I saved the token in a .txt file and used the `gojwtcrack` tool to brute force the secret.
```Shell
~/go/bin/gojwtcrack -t token2.txt -d /usr/share/wordlists/rockyou.txt
```
Output:
![[secret 2.png]]

The secret used to sign the JWT was "london." I went to https://jwt.io and took the login token I'd been provided previously and entered "london" as the signature, and changed the `isAdmin` parameter to "true."
![[encode secret.png]]

I copied and pasted the token into my Burp request in Repeater for the main page and sent the request. This gave me access as an administrator.
![[flag-full admin.png]]
## Key Takeaways
- Play with the `Content-Type` parameter
