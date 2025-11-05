# Trickster

## Challenge

I found a web app that can help process images: PNG images only! — **is that so?**

<p align="center">
<img width="528" height="138" alt="image" src="https://github.com/user-attachments/assets/689f9196-10a2-41ff-b69e-f8c6d306e170" />
</p>

## Solution

### Whatweb

```bash
┌──(kali㉿kali)-[~]
└─$ whatweb http://atlas.picoctf.net:49307/
http://atlas.picoctf.net:49307/ [200 OK] Apache[2.4.56], Country[UNITED STATES][US], HTML5, HTTPServer[Debian
Linux][Apache/2.4.56 (Debian)], IP[18.217.83.136], PHP[8.0.30], Title[File Upload Page],
X-Powered-By[PHP/8.0.30]
```

- Looks like we’re going to attempt to upload a PHP web shell

### Testing

- We want to start by using the website like a normal user would i.e. uploading a generic PNG image file

<img width="1734" height="713" alt="image" src="https://github.com/user-attachments/assets/75354551-7017-4e65-80b7-1723a00e0788" />

- File uploaded and accessible in `/uploads/image.png`

<img width="954" height="824" alt="image" src="https://github.com/user-attachments/assets/ecf344d6-8d9a-4f41-9c2a-a04451bd7f69" />

- Next we try to upload our PHP web shell without tampering with the request, and we receive the error: File name does not contain '.png’

<img width="1745" height="587" alt="image" src="https://github.com/user-attachments/assets/6a574fe8-4d8f-49e4-b8a9-1a9d07d2efe1" />

- Changing `filename="webshell.php"` to `filename="webshell.png.php"` results in a different error: The file is not a valid PNG image: 3c21444f
- We get the same error after changing `Content-Type` as well

<img width="1724" height="710" alt="image" src="https://github.com/user-attachments/assets/0f324566-d99c-411e-b808-330e99a04dcd" />

- Next step was to add PNG file signature, which resulted in a success!

<img width="1724" height="710" alt="image" src="https://github.com/user-attachments/assets/6a60031c-1c5f-4fa6-8809-c3d08a9bb36a" />

## Flag

<p align="center">
<img width="818" height="391" alt="image" src="https://github.com/user-attachments/assets/19638f7d-7282-43d9-ad4d-5403f2f51176" />
</p>
