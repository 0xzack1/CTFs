# findme

## Solution

<img width="848" height="630" alt="image" src="https://github.com/user-attachments/assets/2f1ba9f4-3b12-46da-82f7-46f4d73162b2" />

- Upon login, we are redirected to the page below:

<img width="848" height="417" alt="image 1" src="https://github.com/user-attachments/assets/46bf2af3-d063-4e0d-9f9b-5006e14656fc" />

- This page is also accessible without authentication, but we must login in order to find the flag
- Used Caido to inspect the server responses more closely, and found 2 redirects containing base64 encoded strings:

<img width="1303" height="530" alt="image 2" src="https://github.com/user-attachments/assets/dab0e421-fbe8-422c-9ab7-8b90c22431e0" />

<img width="1303" height="636" alt="image 3" src="https://github.com/user-attachments/assets/a2692bbc-b7b6-4e2d-a9aa-c265dda82295" />

### Flag

```bash
┌──(kali㉿kali)-[~]
└─$ echo "cGljb0NURntwcm94aWVzX2FsbF90aGVfd2F5XzNkOWUzNjk3fQ" | base64 -d
picoCTF{proxies_all_the_way_3d9e3697}   
```
