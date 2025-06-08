# Analysis
Connect to the program with netcat:
```bash
$ nc verbal-sleep.picoctf.net 51624
```
We get the following output:

![image](https://github.com/user-attachments/assets/3df1619f-8ae9-4343-9107-ee349e089862)

We know that RSA uses the following formula for decryption:
```bash
message = ciphertext^d mod N
```
We also know that:
```bash
N = p*q (p and q are prime)
phi = (p-1)(q-1) (phi is coprime with e)
d = e^(-1) mod phi 
```
We notice that the value of of N is an even number, and since N is the product of 2 prime numbers, we conclude that p or q must equal 2 (the only prime number)
```bash
p = 2
q = N//2
```
**Important Note:**

In RSA, security depends on the difficulty of factoring the modulus N, which is the product of two large, distinct prime numbers p and q. If p is chosen as 2 (the only even prime), N becomes even, making it trivial to factor by dividing by 2 to find q = N / 2. Once both primes are known, an attacker can compute the private key and decrypt any message, completely breaking the encryption. This flaw shows why RSA requires large, randomly chosen primes to ensure security, as using a small prime like 2 makes the system vulnerable.

We connect to the program a second time and we get the following output:

![image](https://github.com/user-attachments/assets/6cf5d02d-0159-4560-8d0c-f67da8795a96)

Once again, we notice that N is an even number. This suggests that the prime generation process within the encryption program might be flawed.

Taking a closer look at the program's source code, we note the use of a custom function ```getprimes()``` to generate the values of p and q. 
```python
from sys import exit
from Crypto.Util.number import bytes_to_long, inverse
from setup import get_primes

e = 65537

def gen_key(k):
    """
    Generates RSA key with k bits
    """
    p,q = get_primes(k//2)
    N = p*q
    d = inverse(e, (p-1)*(q-1))

    return ((N,e), d)

def encrypt(pubkey, m):
    N,e = pubkey
    return pow(bytes_to_long(m.encode('utf-8')), e, N)

def main(flag):
    pubkey, _privkey = gen_key(1024)
    encrypted = encrypt(pubkey, flag) 
    return (pubkey[0], encrypted)

if __name__ == "__main__":
    flag = open('flag.txt', 'r').read()
    flag = flag.strip()
    N, cypher  = main(flag)
    print("N:", N)
    print("e:", e)
    print("cyphertext:", cypher)
    exit()
```
This function, despite being tasked with generating primes of approximately k//2 = 512 bits for a 1024-bit N, occasionally (or always) returns 2 as one of the primes.
# Solution
## Method 1 (p = 2)
I wrote the following python code to decrypt the ciphertext based off the conclusion we made during the analysis that p or q must equal 2 (in this case, we suppose that p = 2).
```python
from Crypto.Util.number import long_to_bytes

N = # add value
e = 65537
c = # add value

def decrypt(n, e, p, q, c):
	phi = (p-1)*(q-1)
	d = pow(e, -1, phi)
	m = long_to_bytes(pow(c, d, n))
	return m

print(decrypt(N, e, 2, N//2, c))
```
Output:

![image](https://github.com/user-attachments/assets/87d11416-38eb-4f63-9668-73507f56f609)

To be continued...

