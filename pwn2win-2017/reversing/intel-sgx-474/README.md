[writeup by @abiondo]

**CTF:** Pwn2Win CTF 2017

**Team:** spritzers (from [SPRITZ Research Group](http://spritz.math.unipd.it/))

**Task:** reversing / Intel SGX

**Points:** 474

We were the only team to solve this challenge, so a writeup is definitely in order!

```
The Rebelious Fingers discovered a tool used by ButcherCorp for secure communication. It is possible to request the flag, but it seems to be using some sort of encryption. Can you help us?
```

We're given an [archive](./intelsgx_fd1abca8d26ddb5210e60f9f9a92de2e387733dfca220f13f1a1681b1430577e.tar.gz) with the following contents:

```
client/client: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=42d17308234552192042e76967243f77a5e3142d, not stripped
server/enclave.signed.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6027cdd5af323efe60812f7e3bfdb9f2e21da32c, not stripped
server/server: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d6624b8445b573fbc678b4c1e0f0f788ede4b2b6, not stripped
```

This challenge is centered around an [Intel SGX](https://software.intel.com/en-us/sgx) enclave. An enclave is an isolated container for code and data, often used to store secrets. Its memory can't be accessed even by the kernel, so SGX can protect against a malicious OS. An enclave runs in ring 3 (unprivileged) and can't issue syscalls: it interacts with the untrusted world via *ECALLs* and *OCALLs*. An ECALL is a call made from the outside to the enclave, while an OCALL is a call from the enclave to the outside. An important functionality of enclaves is *remote attestation*: an enclave can prove to a remote server that it is running securely and hasn't been tempered with.

I didn't have access to my SGX machine during the CTF, but in the end I was able to solve this statically, so everything worked out.

# The client

Let's start with the `client` binary. All it does is opening a socket to `enclave.butcher.team` on port 8088. Then, it prints `TODO: Finish client implementation.` and exits. Its only purpose is to give us the address of the remote server.

# The server

The `server` binary is what's running on the remote server. We have a few options:

```
$ nc enclave.butcher.team 8088
Hello there!
What would you like to do?
1: Get flag.
2: Prove I'm worthy.
3: Abort.
```

The first command creates the enclave from `enclave.signed.so`, then makes an ECALL (index 0). Let's see what we get:

```
WARNING: You haven't proved to be worthy!
Here is the IV || tag || flag encrypted with the SK key and encoded as base64:
6e1sXNqkt3L/ULDfh1W56Bphq8+S9a2DTntb9OVNfQlgYXU69sH8hhG99fBpQHFC1U0gLXnYV4uaM/EHwYxU3WAkhkKxP64EIlA=
Good luck with it!
Goodbye!
```

Mmm, ok. The SK is a key negotiated during remote attestation, so there's probably an option for that. Indeed, the second option performs a remote attestation process and, if it is successful, makes the same ECALL to get the flag. The third options exits.

At this point, we want to know more about how things work inside the enclave, especially about the flag encryption.

# The enclave

The enclave is in `enclave.signed.so`. The first thing we want to do is find the ECALL table, so that we can find the function that is called to get the flag. The table is located at `0x2f9c60`. The server was calling ECALL 0, i.e., the first one in the table. This resolves to the `sgx_get_flag` function, which in turn just calls `get_flag`. Here's the decompiled output after some renaming:

```c
void __cdecl get_flag()
{
  protected_fs_file *fd; // rax MAPDST
  char *v2; // rbx
  int v3; // edx
  unsigned int v4; // eax
  unsigned __int64 enc_flag_size; // rbx
  __int64 enc_flag; // r13
  char *v7; // rdx
  int v8; // ecx
  unsigned int v9; // eax
  char *enc_flag_b64; // r12
  char aes_key[16]; // [rsp+0h] [rbp-198h]
  char flag_path[25]; // [rsp+10h] [rbp-188h]
  __int16 v13; // [rsp+2Ch] [rbp-16Ch]
  char flag_buf[96]; // [rsp+30h] [rbp-168h]
  int v15; // [rsp+90h] [rbp-108h]
  char out_buf[200]; // [rsp+A0h] [rbp-F8h]
  unsigned __int64 v17; // [rsp+168h] [rbp-30h]

  v17 = __readfsqword(0x28u);
  v13 = 0;
  strcpy(flag_path, "/home/sgx-chall/flag.txt");
  memset(flag_buf, 0, sizeof(flag_buf));
  v15 = 0;
  memset(out_buf, 0, sizeof(out_buf));
  fd = (protected_fs_file *)sgx_fopen(flag_path, off_DB070, &flag_file_key);
  if ( fd )
  {
    sgx_fread(flag_buf, 1uLL, 46uLL, fd);
    sgx_fclose(fd, 1LL);
  }
  *(_QWORD *)aes_key = 0LL;
  *(_QWORD *)&aes_key[8] = 0LL;
  v2 = flag_buf;
  do
  {
    v3 = *(_DWORD *)v2;
    v2 += 4;
    v4 = ~v3 & (v3 - 0x1010101) & 0x80808080;
  }
  while ( !v4 );
  if ( !((unsigned __int16)~(_WORD)v3 & (unsigned __int16)(v3 - 0x101) & 0x8080) )
    v4 >>= 16;
  if ( !((unsigned __int16)~(_WORD)v3 & (unsigned __int16)(v3 - 0x101) & 0x8080) )
    v2 += 2;
  enc_flag_size = &v2[-__CFADD__((_BYTE)v4, (_BYTE)v4) - 3] - flag_buf + 28; // strlen(flag_buf) + 28
  enc_flag = calloc(enc_flag_size, 1LL);
  if ( g_p_context )
    sgx_ra_get_keys(*g_p_context, 1LL, aes_key);
  else
    sgx_read_rand(aes_key, 16LL);
  sgx_read_rand(enc_flag, 12LL);
  v7 = flag_buf;
  do
  {
    v8 = *(_DWORD *)v7;
    v7 += 4;
    v9 = ~v8 & (v8 - 16843009) & 0x80808080;
  }
  while ( !v9 );
  if ( !((unsigned __int16)~(_WORD)v8 & (unsigned __int16)(v8 - 257) & 0x8080) )
    v9 >>= 16;
  if ( !((unsigned __int16)~(_WORD)v8 & (unsigned __int16)(v8 - 257) & 0x8080) )
    v7 += 2;
  sgx_rijndael128GCM_encrypt(
    aes_key,
    flag_buf,
    &v7[-__CFADD__((_BYTE)v9, (_BYTE)v9) - 3] - flag_buf, // strlen(flag_buf)
    (char *)(enc_flag + 28),
    (const char *)enc_flag,
    12u,
    0LL,
    0,
    (void *)(enc_flag + 12));
  enc_flag_b64 = (char *)calloc(2 * enc_flag_size, 1LL);
  base64encode((const void *)enc_flag, enc_flag_size, enc_flag_b64, 2 * enc_flag_size);
  if ( g_p_context )
    strcpy(out_buf, "Well done! You have proved to be worthy!\n");
  else
    strcpy(out_buf, "WARNING: You haven't proved to be worthy!\n");
  print_ocall(out_buf, enc_flag_size);
  memset(out_buf, 0, sizeof(out_buf));
  snprintf(
    out_buf,
    200uLL,
    "Here is the IV || tag || flag encrypted with the SK key and encoded as base64:\n%s\nGood luck with it!\n",
    enc_flag_b64);
  print_ocall(out_buf, 200LL);
  free(enc_flag);
  if ( __readfsqword(0x28u) == v17 )
    free(enc_flag_b64);
}
```

It reads the flag from `/home/sgx-chall/flag.txt`, then it encrypts it using AES128-GCM, and finally ships it back to us base64-encoded. It's very important to note where the AES key comes from. If the global variable I named `g_p_context` is not null, it's obtained via `sgx_ra_get_keys`, which provides a key that was negotiated during remote attestation. More precisely, it's a key called SK (because the second parameter is 1). If that global variable is null, it uses a random key. It looks like we need to perform remote attestation, so that the flag will be encrypted by a known key instead of an unpredictable random one. This is further confirmed by the fact that xrefs to `g_p_context` show that it's set during remote attestation. Moreover, the output will call us worthy or not depending on the same variable.

# Remote attestation

SGX remote attestation is a complex process. Most importantly, it relies on various cryptographic primitives: 256-bit elliptic curve Diffie-Hellman key exchange, ECDSA-SHA256, CMAC-AES128. I'm not much of a crypto guy, so I wanted implementations that just worked and didn't get in my way. We could play with various crypto libraries and fiddle with conversions from/to the SGX serialization format, but there's a better way. Intel ships a software crypto implementation with its SGX samples, which while marked as not for production use obviously works for remote attestation. Some wonderful guy by the name of Ofir Weisse took the time to write Python bindings for that crypto code, and released it as [sgx_crypto_wrapper](https://github.com/oweisse/sgx_crypto_wrapper). Since Python is my go-to language for CTFs, this was perfect. Just copy `sgx_crypto_wrapper.py` and `crypto_wrapper.so` to your working directory and you're good to go.

Speaking of Python, let me introduce a couple helpers for the upcoming code:

```python
bytes_to_ints = lambda l : [ord(x) for x in l]
array_to_str = lambda x : str(bytearray(x))
```

The library we're using works with `ctypes`. The `bytes_to_ints` helper converts a string of bytes to an array of integers, which is what the library expects for buffers. The `array_to_str` does the opposite, and converts a `ctypes` array (which we get back from calls to the library) to a Python string. In the following code, I also assume that pwnlib has been initialized with a little-endian context, that `p` is a pwnlib tube to the challenge server and that `sgx` is an instance of `SGXCryptoWrapper` (i.e., the library).

Great, let's delve into the actual attestation process. In this process, a client (the enclave) proves it's running securely to a *service provider* (SP), which runs on a remote server. In this case, we are the SP and the challenge server is actually the client. Since in our case this client/server naming is confusing, I will refer to the challenge as the enclave and to us as the SP.

After selecting the second option, the enclave asks us for our public key (encoded with base64). This request is known as `msg0` in SGX jargon. Each party owns a 256-bit ECDH key pair to negotiate a shared secret. Public keys are 64 bytes, while the private part is 32 bytes. All we have to do is create a keypair and send the public key over:

```python
# generate SP EC256-DHKE key pair
sp_privkey, sp_pubkey = sgx.CreateECC256_keyPair()
sp_pubkey_bytes = array_to_str(sp_pubkey)
# send SP pubkey
p.recvuntil('Give me your public key encoded as base64.\n')
p.sendline(b64e(sp_pubkey_bytes))
```

After this, the enclave sends us its public key, encoded with base64. This is known as `msg1`. Simple enough:

```python
# get client's pubkey
p.recvuntil('Here goes MSG1 encoded as base64:\n')
client_pubkey_bytes = b64d(p.recvline())[:64]
```

Now that we have exchanged public keys, we have to calculate the Diffie-Hellman shared secret. The wrapper library makes this a breeze:

```python
# derive ECDH shared key
shared_key = sgx.ComputeSharedSecret(sp_privkey, bytes_to_ints(client_pubkey_bytes))
```

At this point, we have to derive various keys from the shared DH secret. Those keys will be used in future communication and, most importantly, to encrypt the flag. Key derivation (along with the ECDH calculation) happens inside the `sgx_ra_proc_msg2_trusted` function in the enclave. Its implementation is identical to the [one in the SDK](https://github.com/01org/linux-sgx/blob/master/sdk/tkey_exchange/tkey_exchange.cpp#L148). Keys are derived using the `derive_key` function, which again is identical to the [SDK implementation](https://github.com/01org/linux-sgx/blob/master/common/src/ecp.cpp#L52). Since everything's from the SDK, we can just use the nice `DeriveKey` method of the wrapper library. There are four derived keys: SMK, SK, MK and VK. We won't need all of them, but let's be generous (the wrapper expects NUL-terminated tags):

```python
# derive other shared keys
sm_key = sgx.DeriveKey(shared_key, 'SMK\x00')
s_key = sgx.DeriveKey(shared_key, 'SK\x00')
m_key = sgx.DeriveKey(shared_key, 'MK\x00')
v_key = sgx.DeriveKey(shared_key, 'VK\x00')
```

Now comes the big moment. After giving us its public key, the enclave asks us for `msg2`. Real attestation would also include `msg3` and `msg4`, but the challenge stops at this one. The format of `msg2` is available from the SDK:

```c
typedef struct _ra_msg2_t
{
    sgx_ec256_public_t       g_b;         /* the Endian-ness of Gb is Little-Endian */
    sgx_spid_t               spid;
    uint16_t                 quote_type;  /* unlinkable Quote(0) or linkable Quote(1) in little endian */
    uint16_t                 kdf_id;      /* key derivation function id in little endian. */
    sgx_ec256_signature_t    sign_gb_ga;  /* In little endian */
    sgx_mac_t                mac;         /* mac_smk(g_b||spid||quote_type||kdf_id||sign_gb_ga) */
    uint32_t                 sig_rl_size;
    uint8_t                  sig_rl[];
} sgx_ra_msg2_t;
```

Let's take this field by field:

- `g_b` is the SP's public key.
- `spid` is unused in this challenge (the enclave tells us `Tip: use any SPID; we won't be needing it anyway.`).
- We don't care about `quote_type`. I set it to 1 (linkable).
- `kdf_id` must be 1 (see `sgx_ra_proc_msg2_trusted` code).
- `sign_gb_ga` is the ECDSA-SHA256 signature of the SP's public key (`gb`) concatenated with the enclave's public key (`ga`). The signing key is the SP's key.
- `mac` is the CMAC-AES128 of the message so far. The CMAC key is the SMK.
- `sig_rl_size` is the size of the signature revocation list (`sig_rl`). I set this to zero, and didn't append a revocation list.

Okay, now we can build `msg2` and send it over:

```python
# build msg2
gb_ga = sp_pubkey_bytes + client_pubkey_bytes
msg2  = sp_pubkey_bytes # g_b
msg2 += '\x00'*16 # spid (unused)
msg2 += p16(1) # quote_type = linkable
msg2 += p16(1) # kdf_id
msg2 += array_to_str(sgx.SignECDSA(bytes_to_ints(gb_ga), sp_privkey)) # sign_gb_ga
msg2 += array_to_str(sgx.Rijndael128_CMAC(bytes_to_ints(msg2), sm_key)) # mac
msg2 += p32(0) # sig_rl_size
# send msg2
p.recvuntil('anyway.\n')
p.sendline(b64e(msg2))
```

The attestation is successful, and we get the flag encrypted with a known key:

```
Well done! You have proved to be worthy!
Here is the IV || tag || flag encrypted with the SK key and encoded as base64:
QXkHCptLRJLr7eX7fqs14LF9aSlm3XXoYA0dGYSd/GppQ64EsA6dK0Hp6lZhAkcq1m4g/0/47yKNJzhCGTGqToYZUxt9FYF3WmY=
Good luck with it!
Goodbye!
```

# Decrypting the flag

Earlier we saw that the flag was encrypted using AES128-GCM (Galois/Counter Mode) with the SK. As far as the encryption goes, it works like a normal counter mode. However, GCM also produces an authentication tag that can be used to verify the integrity of the data. From the `get_flag` function, we can see that the first 12 bytes are the counter IV, followed by 16 bytes of authentication tag, followed by the ciphertext. The SGX wrapper doesn't offer AES128-GCM, but the `cryptography` Python library does:

```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

def decrypt_flag(s_key, flag_enc):
    iv = flag_enc[:12]
    tag = flag_enc[12:28]
    cipher = flag_enc[28:]
    dec = Cipher(algorithms.AES(s_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return dec.update(cipher) + dec.finalize()
```

Which gives us the flag: `CTF-BR{SGX_aTt35T4t10N_15_v3Ry_51MpL3_1nD33d!}`.

Full script can be found [here](./solve.py).
