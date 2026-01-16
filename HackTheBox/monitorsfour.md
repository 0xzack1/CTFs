# MonitorsFour

IP: 10.10.11.98

# Nmap

```bash
80/tcp   open  http    syn-ack ttl 127 nginx
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: MonitorsFour - Networking Solutions
| http-methods: 
|_  Supported Methods: GET
|_http-favicon: Unknown favicon MD5: 889DCABDC39A9126364F6A675AA4167D

5985/tcp open  http    syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
```

# HTTP (80)

## Dirsearch

```bash
┌──(kali㉿kali)-[~]
└─$ dirsearch -u [http://monitorsfour.htb](http://monitorsfour.htb)                                         

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

[13:19:53] 200 -   97B  - /.env                                            
[13:20:06] 200 -  367B  - /contact                                          
[13:20:14] 200 -   4KB  - /login                                            
[13:20:25] 301 -  162B  - /static  ->  [http://monitorsfour.htb/static/](http://monitorsfour.htb/static/)      
[13:20:28] 200 -   35B  - /user                                             
[13:20:29] 301 -  162B  - /views  ->  [http://monitorsfour.htb/views/](http://monitorsfour.htb/views/) 
```

## Website Features

### Home Page

<img width="1919" height="815" alt="image" src="https://github.com/user-attachments/assets/fd387c8d-d213-40fb-b722-ab9c3e8f4f3b" />

### Login Page

<img width="1314" height="798" alt="image 1" src="https://github.com/user-attachments/assets/f44f8480-0096-4d95-96fe-168775e65812" />

```html
<!-- Simple login form -->
<form action="/api/v1/auth" method="POST">
    <div class="panel panel-body login-form">
        <div class="text-center">
            <div>
                <img src="static/admin/assets/images/servers.png" style="width:100px;height:100px;"></img>
            </div>
            <h5 class="content-group">
                Login to your account
                <small class="display-block">Enter your credentials below</small>
            </h5>
        </div>

        <div class="form-group has-feedback has-feedback-left">
            <input name="username" id="username" type="text" class="form-control" placeholder="Username">
            <div class="form-control-feedback">
                <i class="icon-user text-muted"></i>
            </div>
        </div>

        <div class="form-group has-feedback has-feedback-left">
            <input type="password" name="password" id="password" class="form-control" placeholder="Password">
            <div class="form-control-feedback">
                <i class="icon-lock2 text-muted"></i>
            </div>
        </div>

        <div class="form-group">
            <button type="submit" class="btn btn-primary btn-block">
                Sign in
                <i class="icon-circle-right2 position-right"></i>
            </button>
        </div>

        <div class="text-center">
            <a href="/forgot-password">Forgot password?</a>
        </div>
    </div>
</form>
<!-- /simple login form -->
```

- Endpoint `/api/v1/auth` handles user authentication
- Briefly tested for SQLi but the parameters don’t seem to be injectable at first glance. Will come back to this we can’t get initial access some other way
- Also tested some common usernames/passwords with no success

### Contact Page

<img width="1332" height="171" alt="image 2" src="https://github.com/user-attachments/assets/e55e808e-98e6-43b2-8d4b-5150cd9359a3" />

# FULL WRITE-UP WILL BE AVAILABLE ONCE THE MACHINE IS NO LONGER ACTIVE
