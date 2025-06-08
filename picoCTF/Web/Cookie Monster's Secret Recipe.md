# Analysis
We access the web application via the link provided (http://verbal-sleep.picoctf.net:64848/)

![image](https://github.com/user-attachments/assets/fec7464b-579c-4f62-96c6-7514b6032f43)

After attempting to login with random credentials (```user:password```), we receive the response below, which includes a hint to solve the challenge.

![image](https://github.com/user-attachments/assets/afa2d446-673d-4a3c-b433-391ead789a4c)

We follow the hint and open the cookies tab within the browser.

![image](https://github.com/user-attachments/assets/3f3e122a-e129-44ad-973b-ee2d5ba497b5)

We notice a cookie named secret_recipe had been generated despite the failed login attempt, and we recover the following string:
```bash
cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzXzc3MUQ1RUIwfQ==
```
The string is 64 characters long and ends with ```==```, used in Base64 encoding as padding when the original data's length is not a multiple of 3 bytes..

**Important Note:**

Base64 is a method for encoding binary data into an ASCII string format, commonly used in programming and Capture The Flag (CTF) challenges to obscure messages.
# Solution
We copy the cookie value and use Burp Decoder to obtain the flag.

![image](https://github.com/user-attachments/assets/6c9fedfa-d83e-4440-a9b1-4046ad8e006e)

We can also write a simple python script to decode the cookie value, such as:

```bash
import base64
encoded = "cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzXzc3MUQ1RUIwfQ=="
decoded = base64.b64decode(encoded).decode('utf-8')
print(decoded)
```
Output:

```picoCTF{c00k1e_m0nster_l0ves_c00kies_771D5EB0}```
