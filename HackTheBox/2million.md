# TwoMillion

# Nmap

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://2million.htb/
```

# SSH (22)

```bash
┌──(kali㉿kali)-[~]
└─$ ssh root@10.129.4.232                           
The authenticity of host '10.129.4.232 (10.129.4.232)' can't be established.
ED25519 key fingerprint is: SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:11: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.4.232' (ED25519) to the list of known hosts.
root@10.129.4.232's password: 
```

- Root login and password based authentication enabled.
- Key based authentication recommended.

# HTTP (80)

## Dirsearch

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://2million.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 4749

Output File: /home/kali/reports/http_2million.htb/__26-01-21_00-56-34.txt

Target: http://2million.htb/

[00:56:34] Starting:                                                                                                
[00:56:35] 200 -    2KB - /404                                                      
[00:56:40] 200 -    4KB - /invite                                           
[00:56:41] 200 -    4KB - /login                                            
[00:56:44] 200 -    4KB - /register                                         
```

## Vhosts

```bash
[ Nothing Interesting ]
```

## Website Features

- We need an invite code in order to create an account

<img width="1000" height="677" alt="image" src="https://github.com/user-attachments/assets/b6370328-fb0b-4023-b168-b4ee4e9d67a3" />

- Looking at the source code, we can see an interesting JavaScript file being loaded: `/js/inviteapi.min.js`

<img width="1000" height="674" alt="image 1" src="https://github.com/user-attachments/assets/bf9ee8b9-3b88-402c-82cd-71b98b20716e" />

```jsx
eval(
  (function (p, a, c, k, e, d) {
    e = function (c) {
      return c.toString(36);
    };
    if (!"".replace(/^/, String)) {
      while (c--) {
        d[c.toString(a)] = k[c] || c.toString(a);
      }
      k = [
        function (e) {
          return d[e];
        },
      ];
      e = function () {
        return "\\w+";
      };
      c = 1;
    }
    while (c--) {
      if (k[c]) {
        p = p.replace(new RegExp("\\b" + e(c) + "\\b", "g"), k[c]);
      }
    }
    return p;
  })(
    '1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',
    24,
    24,
    "response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify".split(
      "|"
    ),
    0,
    {}
  )
);

```

- Replacing `eval` with `console.log` on the browser console reveals the deobfuscated code:

```jsx
function verifyInviteCode(code) {
  var formData = {"code": code};
  $.ajax({
    type: "POST",
    dataType: "json",
    data: formData,
    url: '/api/v1/invite/verify',
    success: function(response) {
      console.log(response)
    },
    error: function(response) {
      console.log(response)
    }
  })
}

function makeInviteCode() {
  $.ajax({
    type: "POST",
    dataType: "json",
    url: '/api/v1/invite/how/to/generate',
    success: function(response) {
      console.log(response)
    },
    error: function(response) {
      console.log(response)
    }
  })
}
```

- We send a POST request to `/api/v1/invite/how/to/generate` and receive encrypted data:

```json
{
    "0": 200,
    "success": 1,
    "data": {
        "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr",
        "enctype": "ROT13"
    },
    "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
```

- Used [CyberChef](https://gchq.github.io/CyberChef/) to decrypt the data:

```json
In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate
```

- We do as instructed and voilà:

<img width="1392" height="386" alt="image 2" src="https://github.com/user-attachments/assets/7297ca40-f695-45f2-9c69-ab3f762b71fd" />

```bash
┌──(kali㉿kali)-[~]
└─$ echo "UEQ2RjAtMkMyN00tWk9KMjAtOTNBTDg=" | base64 -d            
PD6F0-2C27M-ZOJ20-93AL8  
```

- We successfully created an account on the platform:

<img width="939" height="602" alt="image 3" src="https://github.com/user-attachments/assets/188fdd88-9ef6-42e8-9cf9-886bbd4183ca" />

## API Endpoints

<img width="1379" height="701" alt="image 4" src="https://github.com/user-attachments/assets/3f281b8c-31c8-405f-9f5d-d175b18abeb1" />

```json
{
    "v1": {
        "user": {
            "GET": {
                "\/api\/v1": "Route List",
                "\/api\/v1\/invite\/how\/to\/generate": "Instructions on invite code generation",
                "\/api\/v1\/invite\/generate": "Generate invite code",
                "\/api\/v1\/invite\/verify": "Verify invite code",
                "\/api\/v1\/user\/auth": "Check if user is authenticated",
                "\/api\/v1\/user\/vpn\/generate": "Generate a new VPN configuration",
                "\/api\/v1\/user\/vpn\/regenerate": "Regenerate VPN configuration",
                "\/api\/v1\/user\/vpn\/download": "Download OVPN file"
            },
            "POST": {
                "\/api\/v1\/user\/register": "Register a new user",
                "\/api\/v1\/user\/login": "Login with existing user"
            }
        },
        "admin": {
            "GET": {
                "\/api\/v1\/admin\/auth": "Check if user is admin"
            },
            "POST": {
                "\/api\/v1\/admin\/vpn\/generate": "Generate VPN for specific user"
            },
            "PUT": {
                "\/api\/v1\/admin\/settings\/update": "Update user settings"
            }
        }
    }
}
```

### /api/v1/admin/settings/update

- `/api/v1/admin/settings/update` stood out to me

<img width="1379" height="701" alt="image 5" src="https://github.com/user-attachments/assets/0c2c89e3-8527-41a0-967c-465d9a14fe16" />

- After a bit of testing, it looks like we were able to gain admin access on the platform

<img width="1379" height="701" alt="image 6" src="https://github.com/user-attachments/assets/f46e484e-9d15-48e3-aba9-88c21fa77ae2" />

- Verified that we now have an admin account:

<img width="1379" height="701" alt="image 7" src="https://github.com/user-attachments/assets/e9072806-448d-4468-94dd-253196b699ae" />

### /api/v1/admin/vpn/generate

<img width="1379" height="701" alt="image 8" src="https://github.com/user-attachments/assets/d186389f-e11a-40db-9039-4bf1a0e3fc55" />

- We can now generate OpenVPN config files for any user

<img width="1379" height="701" alt="image 9" src="https://github.com/user-attachments/assets/be54ec1d-fd36-449d-82d0-1bf46440a4f8" />

# Initial Access

- Further testing of the username parameter revealed a RCE vulnerabilty:

<img width="1379" height="701" alt="image 10" src="https://github.com/user-attachments/assets/69b87b18-a657-4fcd-bde9-8be78afc5216" />

## Enumeration

### Users

<img width="1385" height="827" alt="image 11" src="https://github.com/user-attachments/assets/58433d6a-bb2f-4107-9029-d1e58c251b61" />

- Home directory for user `admin`:

<img width="1385" height="827" alt="image 12" src="https://github.com/user-attachments/assets/0ee7574b-fcd1-4f6b-a2ea-1aade07fbd62" />

- We don’t have permissions to do anything useful here such as retrieving the user flag or ssh keys

### Website root directory

<img width="1385" height="827" alt="image 13" src="https://github.com/user-attachments/assets/c53e9b02-c52e-4a90-81be-40f2a1d66b8f" />

- `/var/www/html/.env`  looks interesting

<img width="1385" height="827" alt="image 14" src="https://github.com/user-attachments/assets/3a2775ca-4418-4526-9692-168013dd9f96" />

# Lateral Movement

- We managed to ssh into the target using the credentials discovered previously, a case of password reuse

```bash
┌──(kali㉿kali)-[~]
└─$ ssh admin@2million.htb        
admin@2million.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.70-051570-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jan 20 10:53:10 PM UTC 2026

  System load:           0.0
  Usage of /:            73.0% of 4.82GB
  Memory usage:          8%
  Swap usage:            0%
  Processes:             217
  Users logged in:       0
  IPv4 address for eth0: 10.129.5.237
  IPv6 address for eth0: dead:beef::250:56ff:fe94:b52

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
Last login: Tue Jun  6 12:43:11 2023 from 10.10.14.6
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:~$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
```

## Enumeration as user ‘admin’

- After searching for files owned by admin (group and user), we discovered 2 interesting files: `/home/admin/user.txt`and `/var/mail/admin`

```bash
admin@2million:~$ find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o \( -user admin -o -group admin \) -type f 2>/dev/null
/run/user/1000/systemd/generator.late/app-snap\x2duserd\x2dautostart@autostart.service
/run/user/1000/systemd/inaccessible/reg
/home/admin/.gnupg/pubring.kbx
/home/admin/.gnupg/trustdb.gpg
/home/admin/.cache/motd.legal-displayed
/home/admin/snap/lxd/common/config/config.yml
/home/admin/.profile
/home/admin/user.txt
/home/admin/.bash_logout
/home/admin/.bashrc
/var/mail/admin
```

### User Flag

```bash
admin@2million:~$ cat user.txt
cb55b97bda0c5a090782b347bc269ed1
```

### /var/mail/admin

```
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

- The hints from this email suggest that the target may be vulnerable to CVE-2023-0386

# Privilege Escalation

- CVE-2023-0386 affects kernel versions from 5.11 to 6.1.8 (excluding 5.15.91)
- It allows a low-privileged local user to escalate to root privileges by exploiting a flaw in how OverlayFS handles file copies from a `nosuid` mount to another writable mount
- More on how this vulnerability works can be found [here](https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/#how-the-cve-2023-0386-vulnerability-works)

```bash
admin@2million:~$ uname -r
5.15.70-051570-generic
```

- Looks like the target is indeed vulnerable and there is a public [exploit](https://github.com/xkaneiki/CVE-2023-0386) we can use

<img width="930" height="372" alt="image 15" src="https://github.com/user-attachments/assets/2044e4a1-d386-48f4-baf6-24294780fe3d" />

## Root Flag

```bash
root@2million:/root# cat root.txt                                                                                                                                                                                                           
16637c67c75c46bac4a413decd01a2ad 
```

## thank_you.json

```bash
root@2million:/tmp/CVE-2023-0386-main# cat /root/thank_you.json 
{"encoding": "url", "data": "%7B%22encoding%22:%20%22hex%22,%20%22data%22:%20%227b22656e6372797074696f6e223a2022786f72222c2022656e6372707974696f6e5f6b6579223a20224861636b546865426f78222c2022656e636f64696e67223a2022626173653634222c202264617461223a20224441514347585167424345454c43414549515173534359744168553944776f664c5552765344676461414152446e51634454414746435145423073674230556a4152596e464130494d556745596749584a51514e487a7364466d494345535145454238374267426942685a6f4468595a6441494b4e7830574c526844487a73504144594848547050517a7739484131694268556c424130594d5567504c525a594b513848537a4d614244594744443046426b6430487742694442306b4241455a4e527741596873514c554543434477424144514b4653305046307337446b557743686b7243516f464d306858596749524a41304b424470494679634347546f4b41676b344455553348423036456b4a4c4141414d4d5538524a674952446a41424279344b574334454168393048776f334178786f44777766644141454e4170594b67514742585159436a456345536f4e426b736a41524571414130385151594b4e774246497745636141515644695952525330424857674f42557374427842735a58494f457777476442774e4a30384f4c524d61537a594e4169734246694550424564304941516842437767424345454c45674e497878594b6751474258514b45437344444767554577513653424571436c6771424138434d5135464e67635a50454549425473664353634c4879314245414d31476777734346526f416777484f416b484c52305a5041674d425868494243774c574341414451386e52516f73547830774551595a5051304c495170594b524d47537a49644379594f4653305046776f345342457454776774457841454f676b4a596734574c4545544754734f414445634553635041676430447863744741776754304d2f4f7738414e6763644f6b31444844464944534d5a48576748444267674452636e4331677044304d4f4f68344d4d4141574a51514e48335166445363644857674944515537486751324268636d515263444a6745544a7878594b5138485379634444433444433267414551353041416f734368786d5153594b4e7742464951635a4a41304742544d4e525345414654674e4268387844456c6943686b7243554d474e51734e4b7745646141494d425355644144414b48475242416755775341413043676f78515241415051514a59674d644b524d4e446a424944534d635743734f4452386d4151633347783073515263456442774e4a3038624a773050446a63634444514b57434550467734344241776c4368597242454d6650416b5259676b4e4c51305153794141444446504469454445516f36484555684142556c464130434942464c534755734a304547436a634152534d42484767454651346d45555576436855714242464c4f7735464e67636461436b434344383844536374467a424241415135425241734267777854554d6650416b4c4b5538424a785244445473615253414b4553594751777030474151774731676e42304d6650414557596759574b784d47447a304b435364504569635545515578455574694e68633945304d494f7759524d4159615052554b42446f6252536f4f4469314245414d314741416d5477776742454d644d526f6359676b5a4b684d4b4348514841324941445470424577633148414d744852566f414130506441454c4d5238524f67514853794562525459415743734f445238394268416a4178517851516f464f676354497873646141414e4433514e4579304444693150517a777853415177436c67684441344f4f6873414c685a594f424d4d486a424943695250447941414630736a4455557144673474515149494e7763494d674d524f776b47443351634369554b44434145455564304351736d547738745151594b4d7730584c685a594b513858416a634246534d62485767564377353043776f334151776b424241596441554d4c676f4c5041344e44696449484363625744774f51776737425142735a5849414242454f637874464e67425950416b47537a6f4e48545a504779414145783878476b6c694742417445775a4c497731464e5159554a45454142446f6344437761485767564445736b485259715477776742454d4a4f78304c4a67344b49515151537a734f525345574769305445413433485263724777466b51516f464a78674d4d41705950416b47537a6f4e48545a504879305042686b31484177744156676e42304d4f4941414d4951345561416b434344384e467a464457436b50423073334767416a4778316f41454d634f786f4a4a6b385049415152446e514443793059464330464241353041525a69446873724242415950516f4a4a30384d4a304543427a6847623067344554774a517738784452556e4841786f4268454b494145524e7773645a477470507a774e52516f4f47794d3143773457427831694f78307044413d3d227d%22%7D"}
```

- We can use [CyberChef](https://gchq.github.io/CyberChef/) to reveal the actual data, and it’s a thank you note from HTB team

<img width="1539" height="938" alt="image 16" src="https://github.com/user-attachments/assets/5be13be4-b05c-42dd-a0d3-39f1c9c75b3e" />
