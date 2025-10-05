# Expressway

<p>IP address: 10.10.11.87</p>
<p>OS: Linux</p>

## Nmap

### TCP Scan

```bash
└─$ nmap -sT -sV -sC -p- 10.10.11.87 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-03 05:20 EDT
Nmap scan report for 10.10.11.87
Host is up (0.028s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.97 seconds

```

- TCP connect() scan revealed the results above.
- No known exploits for OpenSSH 10.0p2 that would grant us entry.

### UDP scan

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sU -p 1-500 10.10.11.87
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-03 06:51 EDT
Nmap scan report for 10.10.11.87
Host is up (0.020s latency).
Not shown: 497 closed udp ports (port-unreach)
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
69/udp  open|filtered tftp
500/udp open          isakmp

Nmap done: 1 IP address (1 host up) scanned in 502.66 seconds
```

- IPSec/IKE running on port 500/udp
- Likely used for VPN negotiations
- Weak configurations (like using aggressive mode with pre-shared keys) can be brute-forced or enumerated


# FULL WRITEUP WILL BE POSTED POST-RETIREMENT OF THE MACHINE ACCORDING TO HTB GUIDELINES
